"""Loopback-only presentation adapter. Runs the pinned engine in bounded workers."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import time
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT.parent                    # the one engine source: the repository root (stage 1b, A01)
sys.path.insert(0, str(ENGINE))         # registers protocol_adapters and protocol_engine for an unpacked checkout
import protocol_adapters                 # noqa: E402,F401 - resolves the root adapters once; no other path hack
from jobs import AdmissionError, JobRunner  # noqa: E402
MAX_UPLOAD = 8 * 1024 * 1024
MAX_HANDLERS = 8                        # stage 6 (A08): bounded concurrent request handlers, never one thread per request
WORKER_SECONDS = 25
MAX_FRAMES = 20000
MAX_SESSIONS = 500
MAX_EVENTS = 4000


def demo_bytes():
    """Locally generated fixtures: never send a packet or collect real traffic."""
    from protocol_adapters.make_sample_pcap import frame, udp_frame
    from protocol_adapters import protocol_fixtures as f
    from protocol_adapters.proxy_demo import client_hello
    hello = client_hello()
    cases = [
        ("tcp", 443, hello, b""),
        ("tcp", 80, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", f.HTTP_RESPONSE),
        ("tcp", 443, f.SSH_MODERN_STREAM, b""),
        ("udp", 53, f.DNS, b""),
        ("tcp", 445, f.SMB2, b""),
        ("tcp", 5432, f.POSTGRESQL, b""),
        ("tcp", 8080, f.CONNECT_REQUEST + hello, f.CONNECT_RESPONSE),
        ("udp", 443, f.QUIC_INITIAL, b""),
        ("tcp", 80, f.WEBSOCKET_UPGRADE + f.WEBSOCKET_FRAME, f.WEBSOCKET_101 + f.WEBSOCKET_SERVER_FRAME),
        ("tcp", 1883, f.MQTT5, b""),
        ("tcp", 6379, b"*2\r\n$4\r\nECHO\r\n$5\r\nhello\r\n", b""),
        ("tcp", 6881, f.BITTORRENT, b""),
        ("tcp", 22, f.SSH_LEGACY_STREAM, b""),
        ("tcp", 8081, b"\xff\xff\xff\xff" * 12, b""),
        ("tcp", 25, b"220 mail.example.com ready\r\n", b""),
        ("tcp", 80, f.HTTP_BASIC_AUTH, b""),
        ("udp", 514, f.SYSLOG, b""),
        ("tcp", 443, b"\x16\x03\x01\x00\x05abcde", b""),
    ]
    frames = []
    for index, (transport, port, payload, reply) in enumerate(cases):
        client = ("192.0.2.{}".format(10 + index % 4), 52000 + index)
        server = ("198.51.100.{}".format(20 + index), port)
        if transport == "udp":
            frames.append(udp_frame(client, server, payload))
            continue
        frames.extend([frame(client, server, 999, 0, 2), frame(server, client, 8999, 1000, 18),
                       frame(client, server, 1000, 9000, 16)])
        cut = max(1, len(payload) // 2)
        # Out-of-order TCP segments exercise the actual reassembly layer.
        frames.extend([frame(client, server, 1000 + cut, 9000, 24, payload[cut:]),
                       frame(client, server, 1000, 9000, 24, payload[:cut])])
        if reply:
            frames.append(frame(server, client, 9000, 1000 + len(payload), 24, reply))
        frames.extend([frame(client, server, 1000 + len(payload), 9000 + len(reply), 17),
                       frame(server, client, 9000 + len(reply), 1001 + len(payload), 17)])
    # Deterministic burst timing, stored in the capture itself (not a decorative chart).
    data = bytearray(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    micros = 0
    for index, packet in enumerate(frames):
        micros += (15000, 25000, 18000, 260000, 30000, 12000, 600000, 20000, 140000)[index % 9]
        data.extend(struct.pack("<IIII", 1700000000 + micros // 1000000,
                                micros % 1000000, len(packet), len(packet)))
        data.extend(packet)
    return bytes(data)


def analyze_bytes(data):
    from protocol_adapters.analyze_pcap import Analyzer
    from protocol_adapters.packets import read_pcap_records, PacketError, CaptureError
    from protocol_adapters.link_packets import decode_frame
    from dataclasses import asdict
    from collections import Counter
    sessions, events, histogram = [], [], Counter()
    now, frame_count, skipped, wire_bytes = 0.0, 0, 0, 0
    started = time.perf_counter()

    def capture_event(source, destination, event):
        if len(events) >= MAX_EVENTS:
            raise ValueError("Event limit reached. Use a smaller capture (maximum 4,000 events).")
        events.append(dict(asdict(event), source=source, destination=destination, timestamp=now, frame=frame_count))

    def session(record):
        if len(sessions) >= MAX_SESSIONS:
            raise ValueError("Session limit reached. Use a capture with fewer than 500 sessions.")
        sessions.append(record)

    analyzer = Analyzer(max_connections=256, max_udp_flows=256, idle_timeout=120, compact=True,
                        on_session=session, on_retire=capture_event, fingerprints=True,
                        heuristics=True, certificates=True, include_hostnames=False)
    with tempfile.NamedTemporaryFile(suffix=".pcap") as capture:
        capture.write(data)
        capture.flush()
        for record in read_pcap_records(capture.name):
            frame_count += 1
            if frame_count > MAX_FRAMES:
                raise ValueError("Frame limit reached. Use a capture with at most 20,000 frames.")
            if record.truncated:
                raise CaptureError("Truncated capture record. No results published; use a complete capture.")
            now = record.timestamp
            wire_bytes += len(record.data)
            histogram[int(now)] += 1
            try:
                packet = decode_frame(record.data, record.linktype)
            except PacketError:
                skipped += 1
                continue
            analyzer.process(now, packet)
            for event in analyzer.last_events:
                capture_event(packet.source, packet.destination, event)
            for source, destination, event in analyzer.peer_events:
                capture_event(source, destination, event)
        analyzer.finish("Capture EOF")
    if not frame_count:
        raise ValueError("The capture contains no frames.")
    elapsed = (time.perf_counter() - started) * 1000
    for index, record in enumerate(sessions):
        record["id"] = "S-{:04d}".format(index + 1)
        endpoints = {tuple(record["client"]), tuple(record["server"])}
        record["events"] = [event for event in events
                            if {tuple(event["source"]), tuple(event["destination"])} == endpoints
                            and record["start"] <= event["timestamp"] <= record["end"]][:60]
    from protocol_engine.applications import OUTCOMES
    return {"sessions": sessions, "meta": {"frames": frame_count, "skipped": skipped,
            "wire_bytes": wire_bytes, "processing_ms": round(elapsed, 2), "events": len(events),
            "identified": sum(s["app"] not in OUTCOMES for s in sessions),
            "timeline": sorted(histogram.items()), "sha256": hashlib.sha256(data).hexdigest()}}


INSTANCE = {"id": None, "started": None}


def health_data(httpd):
    import platform
    if INSTANCE["id"] is None:
        import secrets as _secrets
        INSTANCE["id"], INSTANCE["started"] = _secrets.token_hex(8), time.time()
    source = json.loads((ROOT / "SOURCE.json").read_text())
    return {"build_digest": source.get("build_digest"), "version": source.get("version"), "commit": source.get("commit"),
            "components": source.get("components"), "python": platform.python_version(),
            "instance": INSTANCE["id"], "uptime_seconds": round(time.time() - INSTANCE["started"], 1),
            "jobs": httpd.jobs.status(), "live": httpd.live.snapshot()["state"], "handlers": MAX_HANDLERS,
            "limits": {"upload_mb": 8, "frames": MAX_FRAMES, "sessions": MAX_SESSIONS, "worker_seconds": WORKER_SECONDS}}


def catalog_data():
    from dataclasses import asdict
    from protocol_engine import supported_protocols
    from protocol_engine.applications import APPLICATIONS, OUTCOMES
    source = json.loads((ROOT / "SOURCE.json").read_text())
    protocols = [asdict(p) for p in supported_protocols()]
    return {"source": {k: source.get(k) for k in ("version", "branch", "commit", "repository", "build_digest", "components")},
            "protocols": protocols, "applications": [asdict(a) for a in APPLICATIONS.values()],
            "outcomes": OUTCOMES, "limits": {"upload_mb": 8, "frames": MAX_FRAMES,
            "sessions": MAX_SESSIONS, "worker_seconds": 25}}


def limit_worker_cpu(resource, seconds=22):
    """A CPU budget for one worker process; never raises an inherited hard limit."""
    soft, hard = resource.getrlimit(resource.RLIMIT_CPU)
    cap = (lambda value: value) if hard == resource.RLIM_INFINITY else (lambda value: min(value, hard))
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (cap(seconds), cap(seconds + 1)))
    except (ValueError, OSError):
        pass


def worker_command(kind, payload):
    """argv and stdin for one bounded worker subprocess; the only place worker kinds are defined."""
    if kind in ("analyze", "demo"):
        command = [sys.executable, "-B", str(ROOT / "server.py"), "--worker"] + (["--demo"] if kind == "demo" else [])
        return command, payload if kind == "analyze" else b""
    if kind in ("decrypt", "decrypt-demo"):
        command = [sys.executable, "-B", str(ROOT / "server.py"), "--decrypt-worker"] + (["--demo"] if kind == "decrypt-demo" else [])
        return command, payload if kind == "decrypt" else b""
    raise ValueError("unknown worker kind")


def new_runner():
    return JobRunner(worker_command, max_running=2, max_queued=4, lifetime=WORKER_SECONDS)


_DEFAULT_RUNNER = []


def default_runner():
    """The runner for direct calls outside a server (tests, scripts); a LocalServer owns its own."""
    if not _DEFAULT_RUNNER:
        _DEFAULT_RUNNER.append(new_runner())
    return _DEFAULT_RUNNER[0]


def run_job(kind, payload=b"", timeout=WORKER_SECONDS + 2, runner=None):
    """Submit through the bounded runner and wait for the outcome (the synchronous endpoints and tests)."""
    runner = runner or default_runner()
    try:
        job = runner.submit(kind, payload)
    except AdmissionError as error:
        raise BusyError(str(error)) from None
    job = runner.wait(job["id"], timeout)
    if job is None or job["state"] in ("queued", "running"):
        runner.cancel(job["id"] if job else None)
        raise ValueError("Analysis exceeded %d seconds. Use a smaller capture." % WORKER_SECONDS)
    if job["state"] != "done":
        if job["state"] == "expired":
            raise ValueError("Analysis exceeded %d seconds. Use a smaller capture." % WORKER_SECONDS)
        raise ValueError(job["reason"] if job["state"] == "failed" and job["reason"] and not job["reason"].startswith("worker")
                         else ("The analysis worker could not finish this capture." if kind in ("analyze", "demo")
                               else "Decryption worker failed; no decrypted result published."))
    return job["result"]


class BusyError(ValueError):
    pass


def run_worker(data=None, runner=None):
    return run_job("demo" if data is None else "analyze", data or b"", runner=runner)


def run_decryption_worker(data, demo=False, runner=None):
    return run_job("decrypt-demo" if demo else "decrypt", data, runner=runner)


class LocalServer(ThreadingMixIn, HTTPServer):
    """Loopback server with a bounded handler pool (stage 6, A08).

    Control requests (status, stop, heartbeat, job reads) are cheap and never wait for a worker; uploads and
    analyses go through the JobRunner's admission control. At most MAX_HANDLERS requests are served at once;
    beyond that the accept loop answers 503 immediately instead of queueing or spawning more threads.
    """
    daemon_threads = True
    block_on_close = False

    def __init__(self, *args, **kwargs):
        from live_manager import LiveManager
        self.live = LiveManager()
        self.jobs = new_runner()
        self.slots = threading.BoundedSemaphore(MAX_HANDLERS)
        self.rejected = 0
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.rejected += 1
            body = b'{"error": "Too many concurrent requests; retry shortly."}'
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: "
                                + str(len(body)).encode() + b"\r\nRetry-After: 1\r\nConnection: close\r\n\r\n" + body)
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def server_close(self):
        self.live.stop()
        self.jobs.shutdown()
        super().server_close()

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(15)
        return connection, address


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass                                  # aborted or stalled client connections end quietly

    def respond(self, code, data, kind="application/json; charset=utf-8"):
        body = json.dumps(data, allow_nan=False).encode() if kind.startswith("application/json") else data
        self.send_response(code)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        try:
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass                                  # the client went away; nothing to report to it

    def local_request(self):
        expected = "127.0.0.1:{}".format(self.server.server_port)
        # Reject cross-origin browser requests and DNS-rebinding Host values.
        if self.headers.get("Host") != expected:
            self.respond(403, {"error": "Use the local 127.0.0.1 address printed by the launcher."})
            return False
        if self.headers.get("Origin") not in (None, "http://" + expected):
            self.respond(403, {"error": "Cross-origin requests are not allowed."})
            return False
        return True

    def do_GET(self):
        if not self.local_request():
            return
        path = urlsplit(self.path).path
        if path == "/api/live/interfaces":
            return self.respond(200, self.server.live.interfaces())
        if path == "/api/live/status":
            return self.respond(200, self.server.live.snapshot())
        if path == "/api/live/events":
            # Stage 2 (A06): cursor read of the versioned event log; bounded and side-effect free.
            query = dict(part.split("=", 1) for part in urlsplit(self.path).query.split("&") if "=" in part)
            try:
                cursor, limit = int(query.get("cursor", "0")), int(query.get("limit", "500"))
                return self.respond(200, self.server.live.events_since(cursor, limit))
            except ValueError:
                return self.respond(400, {"error": "cursor and limit must be non-negative integers within bounds"})
        if path.startswith("/api/jobs/"):
            job = self.server.jobs.get(path[len("/api/jobs/"):])
            return self.respond(404, {"error": "Unknown or expired job."}) if job is None else self.respond(200, job)
        if path == "/api/health":
            # Stage 8 (A16): the complete build identity and this instance, never the token or any secret.
            return self.respond(200, health_data(self.server))
        if path == "/api/server":
            return self.respond(200, {"jobs": self.server.jobs.status(), "handlers": MAX_HANDLERS,
                                      "rejected_requests": self.server.rejected, "live": self.server.live.snapshot()["state"]})
        if path == "/api/catalog":
            return self.respond(200, catalog_data())
        if path == "/api/sample":
            return self.respond(200, demo_bytes(), "application/vnd.tcpdump.pcap")
        files = {"/": ("index.html", "text/html; charset=utf-8"),
                 "/store.js": ("store.js", "text/javascript; charset=utf-8"),
                 "/live.js": ("live.js", "text/javascript; charset=utf-8"),
                 "/decrypt.js": ("decrypt.js", "text/javascript; charset=utf-8"),
                 "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                 "/styles.css": ("styles.css", "text/css; charset=utf-8")}
        if path not in files:
            return self.respond(404, {"error": "Not found"})
        filename, kind = files[path]
        self.respond(200, (ROOT / "web" / filename).read_bytes(), kind)

    def do_POST(self):
        if not self.local_request():
            return
        path = urlsplit(self.path).path
        if path in ('/api/decrypt', '/api/decrypt/demo'):
            if self.headers.get('X-Live-Token') != self.server.live.token:
                return self.respond(403, {'error': 'Reload the dashboard before decryption.'})
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 <= length <= 12 * 1024 * 1024 or self.headers.get('Transfer-Encoding'):
                    return self.respond(413, {'error': 'Decryption upload exceeds its limit.'})
                data = self.rfile.read(length)
                if len(data) != length:
                    raise ValueError('Incomplete upload.')
                return self.respond(200, run_decryption_worker(data, path.endswith('/demo'), runner=self.server.jobs))
            except BusyError as error:
                return self.respond(429, {'error': str(error)})
            except (ValueError, OSError) as error:
                return self.respond(400, {'error': str(error)})
        if path.startswith("/api/jobs"):
            # Stage 6 (A08): asynchronous, admission-controlled jobs. POST /api/jobs {kind} with the upload as the
            # body for analyze/decrypt (decrypt bodies are the same JSON the synchronous endpoint takes);
            # POST /api/jobs/<id>/cancel is idempotent. The handler never waits for a worker.
            if self.headers.get('X-Live-Token') != self.server.live.token:
                return self.respond(403, {'error': 'Reload the dashboard before starting a job.'})
            if path.endswith("/cancel"):
                job = self.server.jobs.cancel(path[len("/api/jobs/"):-len("/cancel")])
                return self.respond(404, {"error": "Unknown or expired job."}) if job is None else self.respond(200, job)
            if path != "/api/jobs":
                return self.respond(404, {"error": "Not found"})
            kind = urlsplit(self.path).query.replace("kind=", "", 1) if urlsplit(self.path).query.startswith("kind=") else self.headers.get("X-Job-Kind", "")
            try:
                length = int(self.headers.get("Content-Length", "0"))
                limit = 12 * 1024 * 1024 if kind.startswith("decrypt") else MAX_UPLOAD
                if not 0 <= length <= limit or self.headers.get("Transfer-Encoding"):
                    return self.respond(413, {"error": "Upload exceeds its limit."})
                data = self.rfile.read(length)
                if len(data) != length:
                    raise ValueError("Incomplete upload.")
                if kind not in ("analyze", "demo", "decrypt", "decrypt-demo"):
                    raise ValueError("Unknown job kind.")
                if kind == "analyze" and not data:
                    raise ValueError("Choose a non-empty PCAP or PCAPNG file.")
                return self.respond(202, self.server.jobs.submit(kind, data))
            except AdmissionError as error:
                return self.respond(429, {"error": str(error)})
            except (ValueError, OSError) as error:
                return self.respond(400, {"error": str(error)})
        if path in ("/api/live/start", "/api/live/stop", "/api/live/heartbeat"):
            if self.headers.get('X-Live-Token') != self.server.live.token:
                return self.respond(403, {'error': 'Reload the dashboard before starting capture.'})
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 <= length <= 1024 or self.headers.get('Transfer-Encoding'):
                    raise ValueError('Invalid live control request.')
                data = self.rfile.read(length)
                options = json.loads(data) if data else {}
                if not isinstance(options, dict):
                    raise ValueError('Invalid live options.')
                if path.endswith('/start'):
                    result = self.server.live.start(options.get('interface'), options.get('duration', 120), options.get('scope', 'all'), options.get('keylog_path'))
                elif path.endswith('/heartbeat'):
                    # Stage 6 (A08): the only call that keeps a run alive, scoped to the run id it names.
                    renewed = self.server.live.heartbeat(options.get('run_id'))
                    result = dict(self.server.live.snapshot(), renewed=renewed)
                else:
                    self.server.live.stop(run_id=options.get('run_id'))      # idempotent
                    result = self.server.live.snapshot()
                return self.respond(200, result)
            except (ValueError, OSError) as error:
                return self.respond(400, {'error': str(error)})
        if path not in ("/api/demo", "/api/analyze"):
            return self.respond(404, {"error": "Not found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > MAX_UPLOAD:
                return self.respond(413, {"error": "Capture must be smaller than 8 MB."})
            if self.headers.get("Transfer-Encoding"):
                return self.respond(400, {"error": "Send a file with Content-Length."})
            self.connection.settimeout(15)
            data = self.rfile.read(length)
            if len(data) != length:
                raise ValueError("Incomplete upload.")
            if path == "/api/analyze" and not data:
                raise ValueError("Choose a non-empty PCAP or PCAPNG file.")
            result = run_worker(None if path == "/api/demo" else data, runner=self.server.jobs)
            result["meta"]["synthetic"] = path == "/api/demo"
            self.respond(200, result)
        except BusyError as error:
            self.respond(429, {"error": str(error)})
        except (ValueError, OSError, json.JSONDecodeError) as error:
            self.respond(400, {"error": str(error)})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--demo", action="store_true")
    parser.add_argument('--decrypt-worker', action='store_true')
    args = parser.parse_args()
    if args.decrypt_worker:
        import base64
        import resource
        limit_worker_cpu(resource)
        try:
            from poc_decryption.capture import analyze_capture
            if args.demo:
                from poc_decryption.demo import showcase
                payload = showcase()
            else:
                request = json.loads(sys.stdin.buffer.read(12 * 1024 * 1024 + 1))
                capture = base64.b64decode(request['capture'], validate=True)
                keylog = request['keylog']
                payload = analyze_capture(capture, keylog)
            payload['synthetic'] = args.demo
        except ImportError:
            payload = {'error': 'Decryption requires cryptography. Use the bundled launcher or install requirements-decryption.txt.'}
        except (KeyError, TypeError, json.JSONDecodeError):
            payload = {'error': 'Invalid decryption request.'}
        except Exception as error:
            payload = {'error': str(error)[:240]}
        print(json.dumps(payload, allow_nan=False))
        return
    if args.worker:
        try:
            import resource
            limit_worker_cpu(resource)
            payload = demo_bytes() if args.demo else sys.stdin.buffer.read(MAX_UPLOAD + 1)
            if len(payload) > MAX_UPLOAD:
                raise ValueError("Capture exceeds 8 MB.")
            result = analyze_bytes(payload)
        except Exception as error:
            result = {"error": "Capture could not be analyzed: " + str(error)[:240]}
        print(json.dumps(result, allow_nan=False))
        return
    server = LocalServer(("127.0.0.1", args.port), Handler)
    server.timeout = 15
    print("Protocol Observatory: http://127.0.0.1:{}".format(server.server_port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
