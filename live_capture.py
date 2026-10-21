"""Passive, bounded live inspection. tcpdump owns capture; Python stays unprivileged.

No payloads are saved. This is an observation tool, not packet forwarding or TLS
decryption. Only initial stream scopes are classified. Use --help for examples.
"""
import argparse
import json
import math
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import weakref
from collections import Counter
from analyze_pcap import Analyzer
from capture_stream import PcapStreamDecoder
from link_packets import decode_frame
from packets import CaptureError, PacketError, UDPPacket
from protocol_engine import SignatureSet
from protocol_engine.policy import Policy
from protocol_engine.appid import classify
from protocol_engine.datagram import VALIDATORS
from protocol_engine.registry import PARSERS


def capture_command(interface, bpf, executable=None):
    if not interface or interface.startswith("-") or len(interface) > 128 or not re.fullmatch(r"[A-Za-z0-9_.:-]+", interface):
        raise ValueError("Invalid interface name")
    if not bpf or len(bpf) > 4096 or "\x00" in bpf:
        raise ValueError("Capture filter must contain 1..4096 characters")
    executable = executable or shutil.which("tcpdump")
    if not executable:
        raise CaptureError("tcpdump not found; install it or use --stdin")
    # argv only: filter and interface are never evaluated by a shell.
    return [executable, "-n", "-p", "-U", "--immediate-mode", "-s", "262144", "-i", interface, "-w", "-", "--", "ip and (" + bpf + ")"]


class CaptureMonitor:
    def __init__(self, emit, max_connections=128, byte_limit=65536, idle_timeout=60,
                 all_events=False, udp_hint=None, tcp_hint=None, crc32c_byte_limit=4096, include_hostnames=False,
                 signatures=None, fingerprints=False, heuristics=False, policy=None):
        self.emit = emit
        reference = weakref.ref(self)
        def retired(source, destination, event):
            # Analyzer must not retain its owner through a bound-method cycle.
            owner = reference()
            if owner is not None:
                owner._retired(source, destination, event)
        def session(record):
            owner = reference()
            if owner is not None:
                owner._session(record)
        self.analyzer = Analyzer(max_connections, byte_limit, idle_timeout, compact=True, udp_hint=udp_hint, tcp_hint=tcp_hint,
                                 crc32c_byte_limit=crc32c_byte_limit, on_retire=retired, on_session=session,
                                 include_hostnames=include_hostnames, signatures=signatures, fingerprints=fingerprints,
                                 heuristics=heuristics, policy=policy)
        self.tcp_hint, self.udp_hint = tcp_hint, udp_hint
        self.counts = Counter()
        self.protocols = Counter()
        self.apps = Counter()
        self.risks = Counter()
        self.policy_counts = Counter()
        self.all_events = all_events

    def _session(self, record):
        # One App-ID verdict per connection/flow; no payload-derived values.
        self.counts['sessions'] += 1
        self.apps[record['app']] += 1
        for risk in record.get('risks', ()):
            self.risks[risk] += 1
        if record.get('policy'):
            self.policy_counts[record['policy']['action']] += 1
        self.emit(record)

    def _retiring_bytes(self, source):
        state = self.analyzer.retiring
        return state['bytes'].get(source, 0) if state is not None else None

    def _retired(self, source, destination, event):
        observation = event.observation
        self.counts[observation.status] += 1
        if self.all_events:
            self.emit({'type': 'classification', 'timestamp': None,
                       'source': source, 'destination': destination, 'transport': 'tcp',
                       'status': observation.status,
                       'protocol': observation.application_protocol or observation.encryption,
                       'app': classify(observation, 'tcp', None, self._retiring_bytes(source), self.analyzer.signatures).app,
                       'scope': observation.scope, 'candidate_hint': self.tcp_hint,
                       'reason': observation.reason, 'boundary': 'observation_retired'})

    def accept(self, record, now):
        self.counts["packets"] += 1
        self.counts["captured_bytes"] += len(record.data)
        if record.truncated:
            self.counts["truncated"] += 1
            # Cannot safely associate a truncated packet with one flow: discard
            # all partial state, require new handshakes, retract prior active labels.
            self.invalidate_all("Capture truncation; active stream observations invalidated")
            return
        try:
            packet = decode_frame(record.data, record.linktype)
        except PacketError:
            self.counts["unsupported_or_malformed_packets"] += 1
            return
        transport = "udp" if isinstance(packet, UDPPacket) else "tcp"
        self.counts[transport] += 1
        message = self.analyzer.process(now, packet)
        if message.startswith("SKIP"):
            self.counts["tcp_without_start" if packet.payload else "tcp_control_without_state"] += 1
        elif message.startswith("LIMIT"):
            self.counts["connection_limit"] += 1
        elif message.startswith("INVALIDATED"):
            self.counts["stream_invalidations"] += 1
        if message.startswith("INVALIDATED") and not self.analyzer.last_events:
            self.emit({"type": "classification", "timestamp": record.timestamp,
                       "source": packet.source, "destination": packet.destination,
                       "transport": transport, "status": "invalidated", "protocol": None,
                       "scope": "initial_message", "reason": message})
        server = self.analyzer.last_server
        for event in self.analyzer.last_events:
            observation = event.observation
            self.counts[observation.status] += 1
            protocol = observation.application_protocol or observation.encryption
            if observation.status == "identified":
                self.protocols[protocol] += 1
            if self.all_events or observation.status in ("identified", "invalidated"):
                # No payload, community, credentials, HTTP path, or hostname output.
                derived = {evidence.field: evidence.value for evidence in observation.evidence if evidence.strength == "derived"}
                verdict = classify(observation, transport, server[1] if server else None, None, self.analyzer.signatures)
                self.emit({"type": "classification", "timestamp": record.timestamp,
                           "source": packet.source, "destination": packet.destination,
                           "transport": transport, "status": observation.status,
                           "protocol": protocol, "app": verdict.app, "risks": list(verdict.risks),
                           "policy": (self.analyzer.policy.evaluate(verdict, transport, server[1] if server else None).action
                                      if self.analyzer.policy is not None else None),
                           "fingerprints": derived or None, "event": event.kind,
                           "scope": observation.scope,
                           "candidate_hint": self.udp_hint if transport == 'udp' else self.tcp_hint,
                           "reason": observation.reason})

    def invalidate_all(self, reason, scope="active_connections"):
        active = len(self.analyzer.tracked)
        if active or scope == "all_observations_this_capture":
            self.emit({"type": "capture_gap", "active_connections": active, "scope": scope, "reason": reason})
        self.counts["connections_discarded_after_gap"] += active
        self.analyzer.tracked.clear()
        self.analyzer.udp_flows.clear()
        self.analyzer.quic_assembler.clear()
        self.analyzer.manager.connections.clear()

    def summary(self, elapsed, final=False, capture_stats=None):
        return {"type": "summary" if final else "progress", "elapsed_seconds": round(elapsed, 3),
                "counts": dict(self.counts), "protocols": dict(self.protocols), "apps": dict(self.apps), "risks": dict(self.risks), "policy": dict(self.policy_counts),
                "active_connections": len(self.analyzer.tracked), "active_udp_flows": len(self.analyzer.udp_flows),
                "capture_stats": capture_stats,
                "scope": "Initial messages only; capture loss may be reported at shutdown"}


class CaptureDiagnostics:
    """Bound both stderr backlog and retained diagnostic text."""
    def __init__(self):
        self.pending = bytearray()
        self.tail = bytearray()
        self.stats = {}

    def feed(self, data):
        self.tail.extend(data)
        del self.tail[:-4096]
        self.pending.extend(data)
        while b"\n" in self.pending:
            line, _, rest = self.pending.partition(b"\n")
            self.pending = bytearray(rest)
            self._line(bytes(line))
        if len(self.pending) > 8192:
            del self.pending[:-8192]

    def _line(self, line):
        match = re.fullmatch(rb"\s*(\d+) packets? (captured|received by filter|dropped by kernel|dropped by interface)\s*", line)
        if match:
            self.stats[match[2].decode().replace(" ", "_")] = int(match[1])

    def end(self):
        self._line(bytes(self.pending))


def readable(event):
    kind = event["type"]
    if kind == "classification":
        endpoint = lambda value: "{}:{}".format(*value)
        suffix = ' [candidate: {}]'.format(event['candidate_hint']) if event.get('candidate_hint') else ''
        if event['status'] == 'incomplete':
            suffix += ' | ' + event['reason']
        if event.get('fingerprints'):
            suffix += ' | ' + ' '.join('{}={}'.format(k, v) for k, v in sorted(event['fingerprints'].items()))
        if event.get('risks'):
            suffix += ' | risks=' + ','.join(event['risks'])
        if event.get('policy'):
            suffix += ' | policy=' + event['policy']
        print("{:<12} {:<13} {:<17} {} -> {}{}".format(event["status"].upper(), event["protocol"] or "unknown",
                                                   event.get("app") or "-", endpoint(event["source"]), endpoint(event["destination"]), suffix), flush=True)
    elif kind == "session":
        from analyze_pcap import readable_session
        print(readable_session(event), flush=True)
    elif kind in ("summary", "progress"):
        counts = event["counts"]
        print("{} {:.1f}s | packets={} identified={} skipped={} truncated={} limits={} invalidated={} incomplete={} | {}".format(
            kind.upper(), event["elapsed_seconds"], counts.get("packets", 0), counts.get("identified", 0),
            counts.get("unsupported_or_malformed_packets", 0) + counts.get("tcp_without_start", 0),
            counts.get("truncated", 0), counts.get("connection_limit", 0) + counts.get("budget_exhausted", 0),
            counts.get("stream_invalidations", 0), counts.get("incomplete", 0), ", ".join("{}={}".format(k, v) for k, v in event["protocols"].items()) or "no identifications"), flush=True)
        if event.get("apps"):
            print("Applications: " + ", ".join("{}={}".format(k, v) for k, v in sorted(event["apps"].items())), flush=True)
        if event.get("risks"):
            print("Flow risks: " + ", ".join("{}={}".format(k, v) for k, v in sorted(event["risks"].items())), flush=True)
        if event.get("policy"):
            print("Policy decisions: " + ", ".join("{}={}".format(k, v) for k, v in sorted(event["policy"].items())), flush=True)
        if kind == "summary":
            print("Capture statistics: " + (json.dumps(event["capture_stats"]) if event["capture_stats"] else
                  "unavailable; absence of capture loss is not established"), flush=True)
    else:
        print(kind.upper() + ": " + event.get("reason", ""), flush=True)


def run_capture(stream, emit, duration=60, max_packets=0, stats_interval=10, process=None,
                max_connections=128, byte_limit=65536, idle_timeout=60, all_events=False, udp_hint=None, tcp_hint=None,
                crc32c_byte_limit=4096, include_hostnames=False, signatures=None, fingerprints=False, heuristics=False, policy=None):
    decoder = PcapStreamDecoder()
    monitor = CaptureMonitor(emit, max_connections, byte_limit, idle_timeout, all_events, udp_hint, tcp_hint, crc32c_byte_limit,
                             include_hostnames, signatures, fingerprints, heuristics, policy)
    diagnostics = CaptureDiagnostics()
    selector = selectors.DefaultSelector()
    start = time.monotonic()
    next_stats = start + stats_interval
    stopped, natural_eof, error = False, False, None
    original_blocking = {}
    regular_key = None
    try:
        for pipe, label in ((stream, "data"), (process.stderr if process else None, "stderr")):
            if pipe is not None:
                fd = pipe.fileno()
                # epoll rejects regular files; kqueue may stop reporting them at
                # EOF. Read finite file input explicitly in bounded batches so
                # redirected --stdin reaches decoder.end() on both platforms.
                if process is None and label == 'data' and stat.S_ISREG(os.fstat(fd).st_mode):
                    regular_key = selectors.SelectorKey(fd, fd, selectors.EVENT_READ, label)
                    continue
                original_blocking[fd] = os.get_blocking(fd)
                os.set_blocking(fd, False)
                selector.register(fd, selectors.EVENT_READ, label)
        while True:
            now = time.monotonic()
            if duration and now - start >= duration:
                stopped = True
                break
            if max_packets and monitor.counts["packets"] >= max_packets:
                stopped = True
                break
            monitor.analyzer.expire(now)
            if stats_interval and now >= next_stats:
                emit(monitor.summary(now - start))
                next_stats = now + stats_interval
            timeout = min(.25, max(0, duration - (now - start))) if duration else .25
            ready = [(regular_key, selectors.EVENT_READ)] if regular_key is not None else selector.select(timeout)
            for key, _ in ready:
                try:
                    data = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not data:
                    if regular_key is None:
                        selector.unregister(key.fd)
                    if key.data == "data":
                        natural_eof = True
                    continue
                if key.data == "stderr":
                    diagnostics.feed(data)
                    continue
                for record in decoder.feed(data):
                    monitor.accept(record, time.monotonic())
                    if max_packets and monitor.counts["packets"] >= max_packets:
                        stopped = True
                        break
            if stopped or natural_eof:
                break
        if natural_eof:
            decoder.end()
    except KeyboardInterrupt:
        stopped = True
    except (CaptureError, OSError) as exc:
        error = str(exc)
    finally:
        # Terminate capture and drain both pipes together, so a full output pipe
        # cannot prevent tcpdump from exiting or printing final loss counters.
        if process is not None:
            if process.poll() is None:
                try:
                    process.send_signal(signal.SIGINT)
                except ProcessLookupError:
                    pass
            deadline = time.monotonic() + 2
            while selector.get_map() and time.monotonic() < deadline:
                for key, _ in selector.select(.05):
                    try:
                        data = os.read(key.fd, 65536)
                    except BlockingIOError:
                        continue
                    if not data:
                        selector.unregister(key.fd)
                    elif key.data == "stderr":
                        diagnostics.feed(data)
                    else:
                        monitor.counts["unprocessed_pipe_bytes_at_stop"] += len(data)
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2)
        selector.close()
        for fd, blocking in original_blocking.items():
            try:
                os.set_blocking(fd, blocking)
            except OSError:
                pass
        if process is not None:
            process.stdout.close()
            process.stderr.close()
    diagnostics.end()
    if process is not None and process.returncode not in (0, -signal.SIGINT):
        error = "tcpdump exited with status {}: {}".format(process.returncode, bytes(diagnostics.tail).decode("utf-8", "replace").strip())
    drops = diagnostics.stats.get("dropped_by_kernel", 0) + diagnostics.stats.get("dropped_by_interface", 0)
    if drops:
        monitor.invalidate_all("Capture reported packet loss; observations may be incomplete", "all_observations_this_capture")
    if error:
        monitor.invalidate_all("Capture failed; observations may be incomplete", "all_observations_this_capture")
        emit({"type": "error", "reason": error})
    monitor.analyzer.finish("Capture input EOF before initial message completed" if natural_eof else
                            "Capture stopped before initial message completed")
    summary = monitor.summary(time.monotonic() - start, True, diagnostics.stats or None)
    summary["capture_quality"] = ("failed" if error else "loss_reported" if drops else
                                  "truncated" if monitor.counts["truncated"] else
                                  "no_kernel_drops_reported" if "dropped_by_kernel" in diagnostics.stats else "unverified")
    summary["stop_reason"] = "error" if error else "limit_or_interrupt" if stopped else "eof"
    emit(summary)
    return 1 if error else 2 if drops or monitor.counts["truncated"] else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, epilog="Example: python3 live_capture.py --interface en0 --duration 60")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface", "-i", help="Capture interface (en0, lo0, eth0, ...)")
    source.add_argument("--stdin", action="store_true", help="Read a classic PCAP stream from stdin")
    source.add_argument("--interfaces", action="store_true", help="List tcpdump interfaces and exit")
    parser.add_argument("--filter", default="tcp or udp", help="BPF filter, restricted to IPv4; never a protocol identification rule")
    parser.add_argument("--duration", type=float, default=60, help="Seconds, including idle time; 0 until Ctrl-C")
    parser.add_argument("--max-packets", type=int, default=0, help="Stop after this many frames; 0 unlimited")
    parser.add_argument("--stats-interval", type=float, default=10, help="Seconds between summaries; 0 disables")
    parser.add_argument("--max-connections", type=int, default=128)
    parser.add_argument("--byte-limit", type=int, default=65536, help="Reassembly bytes per direction")
    parser.add_argument("--idle-timeout", type=float, default=60)
    parser.add_argument("--udp-hint", choices=sorted(VALIDATORS), help="Restrict UDP validation to this candidate (use a narrow filter)")
    parser.add_argument("--tcp-hint", choices=sorted(PARSERS), help="Restrict both TCP directions to this candidate (use a narrow filter)")
    parser.add_argument('--crc32c-byte-limit', type=int, default=4096, help='Maximum bytes checked by Python CRC-32C; 0 disables checksummed profiles')
    parser.add_argument("--all-events", action="store_true", help="Also show unknown/malformed/budget outcomes")
    parser.add_argument("--hostnames", action="store_true", help="Include asserted SNI/Host names in session records")
    parser.add_argument("--signatures", help="JSON file of custom application signatures (see SIGNATURES.md)")
    parser.add_argument("--fingerprints", action="store_true", help="Derive JA3/JA4/JA3S/JA4S/HASSH/HTTP2 fingerprints (FINGERPRINTS.md)")
    parser.add_argument("--heuristics", action="store_true", help="Profile unknown payload prefixes and DNS name shape; advisory evidence only (RISKS.md)")
    parser.add_argument("--policy", help="JSON policy evaluated on every session record and classification (POLICY.md)")
    parser.add_argument("--json", action="store_true", help="JSON Lines metadata; no payload output")
    args = parser.parse_args()
    if (not math.isfinite(args.duration) or args.duration < 0 or args.max_packets < 0
            or not math.isfinite(args.stats_interval) or args.stats_interval < 0
            or not math.isfinite(args.idle_timeout) or args.idle_timeout <= 0
            or not 1 <= args.max_connections <= 1024 or not 64 <= args.byte_limit <= 65536
            or not 0 <= args.crc32c_byte_limit <= 1048576):
        parser.error("Invalid limits: connections 1..1024, bytes 64..65536, CRC-32C bytes 0..1048576, finite nonnegative times, idle timeout >0")
    emit = (lambda event: print(json.dumps(event), flush=True)) if args.json else readable
    process = None
    try:
        signatures = SignatureSet.from_path(args.signatures) if args.signatures else None
        policy = Policy.from_path(args.policy) if args.policy else None
        if args.interfaces:
            executable = shutil.which("tcpdump")
            if not executable:
                raise CaptureError("tcpdump not found")
            return subprocess.run([executable, "-D"], timeout=10).returncode
        if args.stdin:
            stream = sys.stdin.buffer
        else:
            command = capture_command(args.interface, args.filter)
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            stream = process.stdout
        emit({"type": "started", "reason": "Passive initial-message inspection; no payload storage or TLS decryption",
              "interface": args.interface, "filter": command[-1] if args.interface else None,
              "tcp_hint": args.tcp_hint, "udp_hint": args.udp_hint, "signatures": len(signatures) if signatures else 0,
              "crc32c_byte_limit": args.crc32c_byte_limit,
              "max_reassembly_buffer_bytes": 4 * args.byte_limit * args.max_connections})
        return run_capture(stream, emit, args.duration, args.max_packets, args.stats_interval, process,
                           args.max_connections, args.byte_limit, args.idle_timeout, args.all_events, args.udp_hint, args.tcp_hint,
                           args.crc32c_byte_limit, args.hostnames, signatures, args.fingerprints, args.heuristics, policy)
    except BrokenPipeError:
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        emit({"type": "error", "reason": str(exc)})
        return 1
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            process.stdout.close()
            process.stderr.close()


if __name__ == "__main__":
    raise SystemExit(main())
