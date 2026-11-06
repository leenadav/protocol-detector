"""Loopback-only presentation adapter. Runs the pinned engine in bounded workers."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "engine"
sys.path.insert(0, str(ENGINE))
MAX_UPLOAD = 8 * 1024 * 1024
MAX_FRAMES = 20000
MAX_SESSIONS = 500
MAX_EVENTS = 4000


def demo_bytes():
    """Locally generated fixtures: never send a packet or collect real traffic."""
    from make_sample_pcap import frame, udp_frame
    import protocol_fixtures as f
    from proxy_demo import client_hello
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
    from analyze_pcap import Analyzer
    from packets import read_pcap_records, PacketError, CaptureError
    from link_packets import decode_frame
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


def catalog_data():
    from dataclasses import asdict
    from protocol_engine import supported_protocols
    from protocol_engine.applications import APPLICATIONS, OUTCOMES
    source = json.loads((ROOT / "SOURCE.json").read_text())
    protocols = [asdict(p) for p in supported_protocols()]
    return {"source": {k: source[k] for k in ("version", "branch", "commit", "repository")},
            "protocols": protocols, "applications": [asdict(a) for a in APPLICATIONS.values()],
            "outcomes": OUTCOMES, "limits": {"upload_mb": 8, "frames": MAX_FRAMES,
            "sessions": MAX_SESSIONS, "worker_seconds": 25}}


def run_worker(data=None):
    command = [sys.executable, "-B", str(ROOT / "server.py"), "--worker"]
    if data is None:
        command.append("--demo")
    try:
        result = subprocess.run(command, input=data or b"", capture_output=True, timeout=25, cwd=str(ROOT))
    except subprocess.TimeoutExpired:
        raise ValueError("Analysis exceeded 25 seconds. Use a smaller capture.") from None
    if result.returncode:
        raise ValueError("The analysis worker could not finish this capture.")
    payload = json.loads(result.stdout)
    if "error" in payload:
        raise ValueError(payload["error"])
    return payload


def run_decryption_worker(data, demo=False):
    command = [sys.executable, '-B', str(ROOT / 'server.py'), '--decrypt-worker']
    if demo:
        command.append('--demo')
    try:
        result = subprocess.run(command, input=data, capture_output=True, timeout=25, cwd=str(ROOT))
    except subprocess.TimeoutExpired:
        raise ValueError('Decryption exceeded the 25-second limit.') from None
    if result.returncode:
        raise ValueError('Decryption worker failed; no decrypted result published.')
    payload = json.loads(result.stdout)
    if 'error' in payload:
        raise ValueError(payload['error'])
    return payload


class LocalServer(HTTPServer):
    def __init__(self, *args, **kwargs):
        from live_manager import LiveManager
        self.live = LiveManager()
        super().__init__(*args, **kwargs)

    def server_close(self):
        self.live.stop()
        super().server_close()

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(15)
        return connection, address


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def respond(self, code, data, kind="application/json; charset=utf-8"):
        body = json.dumps(data, allow_nan=False).encode() if kind.startswith("application/json") else data
        self.send_response(code)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

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
        if path == "/api/catalog":
            return self.respond(200, catalog_data())
        if path == "/api/sample":
            return self.respond(200, demo_bytes(), "application/vnd.tcpdump.pcap")
        files = {"/": ("index.html", "text/html; charset=utf-8"),
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
                return self.respond(200, run_decryption_worker(data, path.endswith('/demo')))
            except (ValueError, OSError) as error:
                return self.respond(400, {'error': str(error)})
        if path in ("/api/live/start", "/api/live/stop"):
            if self.headers.get('X-Live-Token') != self.server.live.token:
                return self.respond(403, {'error': 'Reload the dashboard before starting capture.'})
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 <= length <= 1024 or self.headers.get('Transfer-Encoding'):
                    raise ValueError('Invalid live control request.')
                data = self.rfile.read(length)
                if path.endswith('/start'):
                    options = json.loads(data)
                    if not isinstance(options, dict):
                        raise ValueError('Invalid live options.')
                    result = self.server.live.start(options.get('interface'), options.get('duration', 120), options.get('scope', 'all'), options.get('keylog_path'))
                else:
                    self.server.live.stop()
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
            result = run_worker(None if path == "/api/demo" else data)
            result["meta"]["synthetic"] = path == "/api/demo"
            self.respond(200, result)
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
        resource.setrlimit(resource.RLIMIT_CPU, (22, 23))
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
            resource.setrlimit(resource.RLIMIT_CPU, (22, 23))
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
