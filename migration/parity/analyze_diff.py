"""Migration M8: the Go `analyze` command against the Python reference on generated captures.

    python3 -B migration/parity/analyze_diff.py --binary PATH [--count 300] [--seed 1] [--keep DIR]

Captures are built from the frames of the committed session cases (migration/fixtures/cases.json): one to
five conversations per file on shifted client addresses, in classic PCAP or pcapng, with idle gaps past the
flow timeout and seeded faults (dropped, duplicated, reordered, bit-flipped and truncated records, trailing
garbage). Every third capture instead holds conversations built for bounded-prefix tracking (stress_records).
Each capture is analyzed with a seeded option set (JSON or text rows, events only, sessions,
hostnames, fingerprints, heuristics, certificates, observation modes, checksum policies, continuation, hints,
custom signatures, a policy) by the Python reference in process and by the Go binary. Standard output is
compared byte for byte in both forms (JSON rows and text), and the exit status and error text too. The reference
runs with the Go-only PRO-448 additions modelled (migration/parity/pro448.py: the flow-limit counters in the
summary and the datagram outcomes of UDP session records); nothing else about it changes. The same
capture then goes through the presentation service's analysis (presentation/server.py analyze_bytes_reference
against the Go `present` command, with seeded frame, session and event limits): results and refusals must be
equal but for the measured processing time. Synthetic bytes only.
"""
import argparse
import contextlib
import io
import json
import random
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import pro448  # noqa: E402
import sec_sess1  # noqa: E402
from protocol_adapters.packets import CaptureError  # noqa: E402
from protocol_engine import SignatureSet  # noqa: E402
from protocol_engine.policy import Policy, PolicyError  # noqa: E402

SIGNATURES = [
    {"name": "example-host", "category": "business-systems", "subcategory": "general-business", "risk": 2,
     "conditions": [{"context": "http-req-host-header", "pattern": "example"}]},
    {"name": "any-get", "conditions": {"or": [{"context": "http-req-method", "operator": "equal-to", "value": "GET"},
                                               {"context": "http2-req-method", "operator": "equal-to", "value": "GET"}]}},
    {"name": "sni-example", "parent": "ssl", "conditions": [{"context": "ssl-req-chello-sni", "pattern": "\\.example", "case_insensitive": True}]},
    {"name": "openssh", "risk": 4, "description": {"owner": "ops", "tags": ["remote-access", 1.5, None, "caf\u00e9"]},  # str() of a dict
     "conditions": [{"context": "ssh-req-banner", "pattern": "OpenSSH_[0-9]"}]},
    {"name": "dns-example", "conditions": [{"context": "dns-req-query-name", "pattern": "example"}, {"context": "dns-req-query-type", "operator": "less-than", "value": 30}]},
    {"name": "tcp-zeros", "conditions": [{"context": "unknown-req-tcp-payload", "pattern": "\\x00\\x00\\x00\\x00\\x00\\x00\\x00"}]},
    {"name": "udp-short", "conditions": [{"context": "unknown-req-udp-payload-length", "operator": "less-than", "value": 64},
                                          {"context": "unknown-req-udp-payload", "pattern": "[\\x00-\\xff]{0,8}\\x00\\x00\\x00\\x00\\x00\\x00\\x00"}]},
]
POLICY = {"version": 1, "default": "alert", "rules": [
    {"name": "web", "action": "allow", "match": {"apps": ["web-browsing", "ssl"], "server_ports": ["tcp/80", "tcp/443", "tcp/8000-8100"]}},
    {"name": "structural-only", "action": "allow", "match": {"identity_basis": ["structural"], "categories": ["networking", "business-systems"]}},
    {"name": "risky", "action": "deny", "match": {"risk_min": 4}},
    {"name": "default-ports", "action": "allow", "application_default": True, "match": {"transports": ["tcp"], "technologies": ["client-server"]}},
    {"name": "outcomes", "action": "deny", "match": {"apps": ["unknown-tcp", "unknown-udp", "incomplete"]}},
    {"name": "nonstd", "action": "alert", "match": {"port_usage": ["nonstandard"], "encryption": ["none", "tls"]}}]}


def shifted(frame, linktype, shift):
    """Move a frame to another client address so conversations share a capture without colliding."""
    if linktype != 1 or len(frame) < 34 or frame[12:14] != b"\x08\x00" or not shift:
        return frame
    data = bytearray(frame)
    for offset in (26, 30):                 # IPv4 source and destination: the last octet of 192.0.2.x only
        if data[offset:offset + 3] == b"\xc0\x00\x02":
            data[offset + 3] = (data[offset + 3] + shift) & 0xff
    return bytes(data)                      # checksums are left as they were: audit/verify then see failures


def records_for(rng, sessions):
    records, start = [], 1700000000.0
    for index in range(rng.choice([1, 1, 2, 3, 5])):
        case = rng.choice(sessions)
        shift = index * 7 if rng.random() < 0.8 else 0
        for packet in case["packets"]:
            records.append([start + packet["t"], shifted(bytes.fromhex(packet["frame"]), packet.get("linktype", 1), shift), False])
        start += rng.choice([0, 0, 0.5, 61, 200]) + 1
    if rng.random() < 0.4:
        if rng.random() < 0.2:
            rng.shuffle(records)
        else:
            records.sort(key=lambda record: record[0])
    for _ in range(rng.choice([0, 0, 0, 1, 2])):
        if not records:
            break
        index, fault = rng.randrange(len(records)), rng.random()
        if fault < 0.3:
            del records[index]
        elif fault < 0.5:
            records.insert(index, list(records[index]))
        elif fault < 0.7:
            data = bytearray(records[index][1])
            if data:
                data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
            records[index][1] = bytes(data)
        elif fault < 0.85:
            records[index][2] = True
        else:
            records[index][0] += rng.choice([-5, 100, 1e6])
    return records


def stress_records(rng):
    """Conversations built for the bounded-prefix (compact) tracking the presentation service uses: streams past
    the 64 KiB window, segments before the retained origin or half a sequence space away, overlaps, FIN at and
    beyond the window, data after FIN, resets, idle gaps around the one-second expiry interval and the timeout,
    and (rarely) more connections and flows than the tables hold."""
    from protocol_adapters.make_sample_pcap import frame, udp_frame
    from protocol_adapters.protocol_fixtures import DATAGRAM_CASES, STREAM_CASES
    records, now = [], 1700000000.0
    step = lambda: rng.choice([0, 0, 0.001, 0.4, 0.999, 1.0, 1.5, 59, 119.5, 120, 121])
    many = rng.random() < 0.04
    for index in range(rng.choice([260, 300]) if many else rng.choice([1, 1, 2, 3, 6])):
        client = ("192.0.2.{}".format(1 + index % 250), 40000 + index)
        server = ("198.51.100.{}".format(1 + index % 3), rng.choice([80, 443, 22, 1883, 5432, 8080, 9000 + index % 50]))
        if rng.random() < 0.2:
            payload = rng.choice(DATAGRAM_CASES)[0]
            for _ in range(rng.choice([1, 1, 2, 3])):
                records.append([now, udp_frame(client, server, payload), False])
                now += step()
                if rng.random() < 0.4:
                    records.append([now, udp_frame(server, client, rng.choice(DATAGRAM_CASES)[0]), False])
            continue
        isn = rng.choice([999, 0xffffffff, 0xfffffff0, 0x7fffffff, rng.randrange(1 << 32)])
        peer_isn = rng.choice([8999, 0xfffffffe, rng.randrange(1 << 32)])
        origin, peer_origin = (isn + 1) % (1 << 32), (peer_isn + 1) % (1 << 32)
        records.append([now, frame(client, server, isn, 0, 2), False])
        if rng.random() < 0.95:
            records.append([now, frame(server, client, peer_isn, origin, 18), False])
        if many:
            if rng.random() < 0.5:
                records.append([now + 0.01, frame(client, server, origin, peer_origin, 24, rng.choice(STREAM_CASES)[0]), False])
            now += rng.choice([0, 0.01, 0.5])
            continue
        records.append([now, frame(client, server, origin, peer_origin, 16), False])
        for source, destination, start, other in ((client, server, origin, peer_origin), (server, client, peer_origin, origin)):
            if source is server and rng.random() < 0.5:
                continue
            data = rng.choice(STREAM_CASES)[0]
            size = rng.choice([0, 0, 0, 200, 3000, 65536 - len(data), 65537, 70000])
            data = (data + bytes(rng.randrange(256) for _ in range(min(size, 64))) * (size // 64 + 1))[:max(len(data), size)]
            segments, offset = [], 0
            while offset < len(data):
                length = rng.choice([1, 7, 536, 1400, 1400, 1400, 9000])
                segments.append((offset, data[offset:offset + length]))
                offset += length
            fault = rng.random()
            if fault < 0.15:
                rng.shuffle(segments)
            elif fault < 0.3 and segments:
                at = rng.randrange(len(segments))
                segments.insert(at, segments[rng.randrange(len(segments))])
            elif fault < 0.4 and segments:
                at = rng.randrange(len(segments))
                changed = bytes(b ^ 1 for b in segments[at][1])
                segments.insert(rng.randrange(len(segments) + 1), (segments[at][0], changed))
            elif fault < 0.5 and len(segments) > 1:
                del segments[rng.randrange(len(segments))]
            if rng.random() < 0.3:                       # before the retained origin: wholly, or reaching into it
                back = rng.choice([1, 5, 2000, 1 << 31, (1 << 31) + 5])
                body = bytes(back if back < 4000 else 9) + data[:rng.choice([0, 3, 40])]
                segments.insert(rng.randrange(len(segments) + 1), (-back, body))
            if rng.random() < 0.1:                       # far beyond the window
                segments.insert(rng.randrange(len(segments) + 1), (rng.choice([65536, 100000, (1 << 31) - 1, 1 << 31]), b"far"))
            for offset, body in segments:
                flags = 24 if rng.random() < 0.9 else rng.choice([16, 24 | 32, 8])
                records.append([now, frame(source, destination, (start + offset) % (1 << 32), other, flags, body), False])
                now += rng.choice([0, 0, 0, 0.001, 0.4, 1.0])
            ending = rng.random()
            if ending < 0.45:
                end = len(data) + rng.choice([0, 0, 0, 1, -1, 100000])
                records.append([now, frame(source, destination, (start + end) % (1 << 32), other, 17, rng.choice([b"", b"", b"x"])), False])
                if rng.random() < 0.3:
                    records.append([now, frame(source, destination, (start + len(data) + rng.choice([0, 1, 2])) % (1 << 32), other,
                                               rng.choice([17, 24]), rng.choice([b"", b"late"])), False])
            elif ending < 0.55:
                records.append([now, frame(source, destination, (start + len(data)) % (1 << 32), other, 4), False])
            now += step()
        now += step()
    return records


def write_capture(rng, path, records):
    with open(path, "wb") as capture:
        if rng.random() < 0.4:
            def block(kind, body):
                body += bytes(-len(body) % 4)
                total = len(body) + 12
                return struct.pack("<II", kind, total) + body + struct.pack("<I", total)
            capture.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
            capture.write(block(1, struct.pack("<HHI", 1, 0, 0)))
            for timestamp, data, truncate in records:
                kept = data[:len(data) // 2] if truncate else data
                ticks = int(round(timestamp * 1000000))
                capture.write(block(6, struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xffffffff, len(kept), len(data)) + kept))
        else:
            capture.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
            for timestamp, data, truncate in records:
                kept = data[:len(data) // 2] if truncate else data
                seconds = int(timestamp)
                capture.write(struct.pack("<IIII", seconds, int(round((timestamp - seconds) * 1000000)) % 1000000, len(kept), len(data)) + kept)
        if rng.random() < 0.03:
            capture.write(b"\x00\x01\x02")


def options_for(rng, signatures_path, policy_path):
    options = []
    if rng.random() < 0.85:
        options.append("--json")
    if rng.random() < 0.3:
        options.append("--events-only")
    if rng.random() < 0.8:
        options.append("--sessions")
    for flag in ("--hostnames", "--fingerprints", "--heuristics", "--certificates"):
        if rng.random() < 0.3:
            options.append(flag)
    if rng.random() < 0.3:
        options += ["--observation", rng.choice(["handshake", "asymmetric", "midstream"])]
    if rng.random() < 0.3:
        options += ["--checksums", rng.choice(["ignore", "audit", "verify"])]
    if rng.random() < 0.2:
        options += ["--continuation", str(rng.choice([0, 512, 4096, 65536]))]
    if rng.random() < 0.1:
        options += ["--udp-hint", rng.choice(["dns", "quic", "stun", "ntp"])]
    if rng.random() < 0.1:
        options += ["--tcp-hint", rng.choice(["tls", "dns", "ldap", "kerberos", "http2"])]
    if rng.random() < 0.1:
        options += ["--crc32c-byte-limit", str(rng.choice([0, 16, 4096]))]
    if rng.random() < 0.25:
        options += ["--signatures", signatures_path]
    if rng.random() < 0.25:
        options += ["--policy", policy_path]
    if rng.random() < 0.15:
        from protocol_engine import content
        options += ["--content-version", rng.choice([item.version for item in content.releases()])]
    return options


def reference(path, options):
    """The Python analyze() in process, with the exit status and error text its command line would give."""
    def value(name, default=None):
        return options[options.index(name) + 1] if name in options else default
    arguments = dict(json_output="--json" in options, events_only="--events-only" in options,
                     sessions="--sessions" in options or "--policy" in options, include_hostnames="--hostnames" in options,
                     fingerprints="--fingerprints" in options, heuristics="--heuristics" in options, certificates="--certificates" in options,
                     observation=value("--observation", "handshake"), checksums=value("--checksums", "ignore"),
                     continuation=int(value("--continuation", 0)), udp_hint=value("--udp-hint"), tcp_hint=value("--tcp-hint"),
                     crc32c_byte_limit=int(value("--crc32c-byte-limit", 4096)))
    output, status, error = io.StringIO(), 0, ""
    from protocol_engine import content
    if "--content-version" in options:
        content.select(value("--content-version"))        # as main() does, before signatures and policy load
    try:
        if "--signatures" in options:
            arguments["signatures"] = SignatureSet.from_path(value("--signatures"))
        if "--policy" in options:
            arguments["policy"] = Policy.from_path(value("--policy"))
        with contextlib.redirect_stdout(output):
            pro448.analyze(str(path), **arguments)
    except (OSError, CaptureError, ValueError, PolicyError) as failure:
        status, error = 1, "Capture error: {}\n".format(failure)
    finally:
        content.select(content.CURRENT)                   # the selection is process-wide
    return output.getvalue(), status, error


def compare(reference_result, go_result):
    """Standard output byte for byte (the Go rows are written in the reference's JSON text form), then the exit
    status and the error text."""
    (py_out, py_status, py_error), (go_out, go_status, go_error) = reference_result, go_result
    if py_out != go_out:
        py_rows, go_rows = py_out.splitlines(), go_out.splitlines()
        index = next((i for i, (left, right) in enumerate(zip(py_rows, go_rows)) if left != right), min(len(py_rows), len(go_rows)))
        left, right = (py_rows[index:] or ["<end>"])[0], (go_rows[index:] or ["<end>"])[0]
        column = next((i for i, (a, b) in enumerate(zip(left, right)) if a != b), min(len(left), len(right)))
        return "line {} column {}: python ...{!r} go ...{!r}".format(index, column, left[max(0, column - 60):column + 60], right[max(0, column - 60):column + 60])
    if (py_status, py_error) != (go_status, go_error):
        return "exit python {} {!r:.160} go {} {!r:.160}".format(py_status, py_error, go_status, go_error)
    return None


def positive_rows(output):
    """Rows of analyze output that carry an identification: a text row naming a parser MATCH, or a JSON row whose
    classification, event or record has status `identified`."""
    return sum(1 for row in output.splitlines() if "=MATCH (" in row or '"status": "identified"' in row)


def shortfall(captures, python_positive, go_positive, completed=1):
    """Why a run without a divergence still proved nothing (Codex PRO-20): no capture was compared, neither
    backend's output carried a single identified row, or every presentation result was a refusal (`completed`
    counts the reference's completed analyses; PRO-261, from PR #99)."""
    problems = []
    if captures < 1:
        problems.append("no capture was compared (--count {})".format(captures))
    if python_positive < 1:
        problems.append("the reference output carried no identified row")
    if go_positive < 1:
        problems.append("the Go output carried no identified row")
    if captures >= 1 and completed < 1:
        problems.append("no presentation result was a completed analysis")
    return problems


def present_reference(server, data, limits):
    """presentation/server.py analyze_bytes on the reference engine: the result, or the exception class and text."""
    saved = server.MAX_FRAMES, server.MAX_SESSIONS, server.MAX_EVENTS
    server.MAX_FRAMES, server.MAX_SESSIONS, server.MAX_EVENTS = limits
    try:
        result = server.analyze_bytes_reference(data)
    except CaptureError as error:
        return {"error_type": "CaptureError", "error": str(error)}
    except ValueError as error:
        return {"error_type": "ValueError", "error": str(error)}
    finally:
        server.MAX_FRAMES, server.MAX_SESSIONS, server.MAX_EVENTS = saved
    result["meta"]["processing_ms"] = 0
    return result


def present_problem(server, binary, rng, data):
    """Compare the Go `present` command with the reference on one capture (text of the result but the timing):
    (problem or None, whether the reference completed the analysis rather than refusing it, and for a differing
    result the two sides for sec_sess1.Pins.approve, else None)."""
    limits = (20000, 500, 4000) if rng.random() < 0.7 else (rng.choice([0, 3, 20000]), rng.choice([0, 1, 2, 500]), rng.choice([0, 2, 9, 4000]))
    expected = present_reference(server, data, limits)
    done = subprocess.run([binary, "present", "--max-frames", str(limits[0]), "--max-sessions", str(limits[1]), "--max-events", str(limits[2])],  # noqa: S603
                          input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=120)
    if done.returncode != (3 if "error" in expected else 0):
        return "present exit status {} for {!r}: {}".format(done.returncode, expected.get("error"), done.stderr.decode("utf-8", "replace")[:200]), False, None
    actual = json.loads(done.stdout)
    if "meta" in actual:
        actual["meta"]["processing_ms"] = 0
    if json.dumps(actual) != json.dumps(expected):
        # The sides as indented JSON, for the SEC-SESS-1 pins: (Go, Go status, reference, reference status, limits).
        sides = (json.dumps(actual, indent=1), done.returncode, json.dumps(expected, indent=1), 3 if "error" in expected else 0,
                 "limits {}".format(list(limits)))
        return "present result differs (limits {})".format(limits), "error" not in expected, sides
    return None, "error" not in expected, None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True, help="the Go protodetect binary")
    parser.add_argument("--count", type=int, default=300)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--keep", help="write the captures here instead of a temporary directory")
    parser.add_argument("--record-sec-sess1", metavar="PATH", help="write every divergence to PATH for review; the run then fails")
    args = parser.parse_args(argv)
    pro448.self_test()
    sec_sess1.self_test()
    pins = sec_sess1.Pins("analyze", args.seed, record=args.record_sec_sess1)
    rng = random.Random(args.seed)
    sessions = [case for case in json.loads((ROOT / "migration/fixtures/cases.json").read_text(encoding="utf-8"))["cases"] if case["kind"] == "session"]
    with contextlib.ExitStack() as stack:
        folder = Path(args.keep) if args.keep else Path(stack.enter_context(tempfile.TemporaryDirectory()))
        folder.mkdir(parents=True, exist_ok=True)
        signatures_path, policy_path = str(folder / "signatures.json"), str(folder / "policy.json")
        Path(signatures_path).write_text(json.dumps(SIGNATURES), encoding="utf-8")
        Path(policy_path).write_text(json.dumps(POLICY), encoding="utf-8")
        failures, rows, presented, completed, python_positive, go_positive = [], 0, 0, 0, 0, 0
        sys.path.insert(0, str(ROOT / "presentation"))
        import server  # noqa: E402 - the presentation service's reference analysis
        for index in range(args.count):
            capture = folder / "capture-{}-{}.pcap".format(args.seed, index)
            write_capture(rng, capture, stress_records(rng) if index % 3 == 2 else records_for(rng, sessions))
            options = options_for(rng, signatures_path, policy_path)
            expected = reference(capture, options)
            done = subprocess.run([args.binary, "analyze", str(capture)] + options, stdout=subprocess.PIPE, stderr=subprocess.PIPE,  # noqa: S603
                                  check=False, timeout=120)
            rows += expected[0].count("\n")
            python_positive += positive_rows(expected[0])
            go_positive += positive_rows(done.stdout.decode("utf-8", "replace"))
            go_result = (done.stdout.decode("utf-8"), done.returncode, done.stderr.decode("utf-8"))
            problem = compare(expected, go_result)
            pins.cover(capture.name + "/analyze")
            # SEC-SESS-1 (PRO-398): a mismatch passes only when this exact case is pinned with both exact results.
            if problem and not pins.approve(capture.name + "/analyze", go_result[0], list(go_result[1:]), expected[0], list(expected[1:]),
                                            " ".join(options).replace(str(folder), "<tmp>")):
                failures.append("{} {}: {}".format(capture.name, " ".join(options), problem))
            problem, finished, sides = present_problem(server, args.binary, rng, capture.read_bytes())
            presented += 1
            completed += finished
            pins.cover(capture.name + "/present")
            if problem and not (sides and pins.approve(capture.name + "/present", *sides)):
                failures.append("{}: {}".format(capture.name, problem))
        for line in failures[:10]:
            print("analyze mismatch:", line)
        problems = shortfall(args.count, python_positive, go_positive, completed) + pins.finish()
        for line in problems:
            print("analyze parity FAILED:", line)
        print("analyze parity: {} captures, {} rows ({} identified), {} presentation results ({} completed), {} mismatched, "
              "{} approved divergences ({}) (seed {})".format(args.count, rows, python_positive, presented, completed, len(failures),
                                                             len(pins.approved), sec_sess1.LABEL, args.seed))
        return 1 if failures or problems else 0


if __name__ == "__main__":
    sys.exit(main())
