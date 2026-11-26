"""Migration M8: the Go `live` command against the Python reference on replayed capture streams.

    python3 -B migration/parity/live_diff.py --binary PATH [--count 300] [--seed 1]

Live capture depends on the clock, so both sides replay a generated capture stream with the clock taken from
the stream itself: the timestamp of the record being accepted (the Go binary's --replay-clock; the reference's
run_capture runs unchanged with its monotonic clock and its stream decoder replaced by ones that do the same).
Everything the adapter decides is then a function of the bytes: classification events, retired directions,
session records with their capture id, session id and generation, capture gaps, progress and final summaries
(counters, telemetry, input quality), the stop reason and the exit status. Captures come from
analyze_diff.py's generators (conversations of the committed session cases with faults, and bounded-prefix
stress conversations); options are seeded (events, fingerprints, heuristics, certificates, hostnames,
observation modes, checksum policies, continuation, hints, limits, custom signatures, a policy, JSON or text).
Events are compared as text, in order; the durations of work stages (wall time, stage_seconds.*) are compared
by count only. Synthetic bytes only; nothing is captured.
Since PRO-401 the gate replays a golden file instead (--golden; --record writes one): migration/parity/golden.py.
"""
import argparse
import contextlib
import io
import json
import random
import subprocess
import sys
import tempfile
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import analyze_diff  # noqa: E402
import golden  # noqa: E402 - the reference (protocol_engine, protocol_adapters, pro189) is imported only where it runs
import sec_sess1  # noqa: E402 - standard library only

CAPTURE_ID = "0123456789abcdef"


class ReplayClock:
    """time.monotonic() for the reference: the timestamp of the record being accepted."""
    now = 0.0

    def monotonic(self):
        return self.now


def options_for(rng, signatures_path, policy_path):
    options = {"duration": 0.0, "max_packets": rng.choice([0, 0, 0, 3, 40]), "stats_interval": rng.choice([0.0, 0.0, 1.0, 10.0, 0.25]),
               "max_connections": rng.choice([128, 128, 1, 2, 8]), "byte_limit": rng.choice([65536, 16384, 1000, 64]),
               "idle_timeout": rng.choice([60.0, 15.0, 0.5]), "all_events": rng.random() < 0.6, "udp_hint": None, "tcp_hint": None,
               "crc32c_byte_limit": rng.choice([4096, 4096, 0, 16]), "include_hostnames": rng.random() < 0.3, "signatures": None,
               "fingerprints": rng.random() < 0.5, "heuristics": rng.random() < 0.3, "policy": None, "certificates": rng.random() < 0.3,
               "observation": rng.choice(["handshake", "handshake", "asymmetric", "midstream"]),
               "checksums": rng.choice(["ignore", "ignore", "audit", "verify"]), "continuation": rng.choice([0, 0, 0, 64])}
    if options["continuation"] > options["byte_limit"]:
        options["continuation"] = 0
    if rng.random() < 0.08:
        options["tcp_hint"] = rng.choice(["tls", "dns", "ldap", "kerberos", "http2"])
    if rng.random() < 0.08:
        options["udp_hint"] = rng.choice(["dns", "quic", "stun", "ntp"])
    if rng.random() < 0.25:
        options["signatures"] = signatures_path
    if rng.random() < 0.25:
        options["policy"] = policy_path
    options["content_version"] = None
    if rng.random() < 0.15:
        from protocol_engine import content
        options["content_version"] = rng.choice([item.version for item in content.releases()])
    return options, rng.random() < 0.8


def arguments(options, as_json):
    out = ["--stdin", "--replay-clock", "--capture-id", CAPTURE_ID, "--duration", repr(options["duration"]),
           "--max-packets", str(options["max_packets"]), "--stats-interval", repr(options["stats_interval"]),
           "--max-connections", str(options["max_connections"]), "--byte-limit", str(options["byte_limit"]),
           "--idle-timeout", repr(options["idle_timeout"]), "--crc32c-byte-limit", str(options["crc32c_byte_limit"]),
           "--observation", options["observation"], "--checksums", options["checksums"], "--continuation", str(options["continuation"])]
    for flag, name in (("--all-events", "all_events"), ("--hostnames", "include_hostnames"), ("--fingerprints", "fingerprints"),
                       ("--heuristics", "heuristics"), ("--certificates", "certificates")):
        if options[name]:
            out.append(flag)
    for flag, name in (("--udp-hint", "udp_hint"), ("--tcp-hint", "tcp_hint"), ("--signatures", "signatures"), ("--policy", "policy"),
                       ("--content-version", "content_version")):
        if options[name]:
            out += [flag, options[name]]
    return out + (["--json"] if as_json else [])


def reference(path, options, as_json):
    """(output text, exit status) of the reference's main() for --stdin, on the replay clock."""
    from protocol_adapters import coordinator, live_capture
    from protocol_adapters.capture_stream import PcapStreamDecoder
    from protocol_engine import SignatureSet
    from protocol_engine.policy import Policy
    clock = ReplayClock()

    class Decoder(PcapStreamDecoder):
        def feed(self, data):
            for record in super().feed(data):
                clock.now = record.timestamp
                yield record

    output = io.StringIO()
    saved = live_capture.time, live_capture.PcapStreamDecoder, coordinator.secrets.token_hex
    live_capture.time, live_capture.PcapStreamDecoder = clock, Decoder
    coordinator.secrets.token_hex = lambda size: CAPTURE_ID
    from protocol_engine import content
    if options.get("content_version"):
        content.select(options["content_version"])        # as main() does, before signatures and policy load
    try:
        with contextlib.redirect_stdout(output), open(path, "rb") as stream:
            emit = (lambda event: print(json.dumps(event), flush=True)) if as_json else live_capture.readable
            signatures = SignatureSet.from_path(options["signatures"]) if options["signatures"] else None
            policy = Policy.from_path(options["policy"]) if options["policy"] else None
            from protocol_engine import content
            emit({"type": "started", "reason": "Passive initial-message inspection; no payload storage or TLS decryption",
                  "interface": None, "filter": None, "tcp_hint": options["tcp_hint"], "udp_hint": options["udp_hint"],
                  "signatures": len(signatures) if signatures else 0, "crc32c_byte_limit": options["crc32c_byte_limit"],
                  "max_reassembly_buffer_bytes": 4 * options["byte_limit"] * options["max_connections"], "content": content.pinned()})
            status = live_capture.run_capture(
                stream, emit, options["duration"], options["max_packets"], options["stats_interval"], None, options["max_connections"],
                options["byte_limit"], options["idle_timeout"], options["all_events"], options["udp_hint"], options["tcp_hint"],
                options["crc32c_byte_limit"], options["include_hostnames"], signatures, options["fingerprints"], options["heuristics"],
                policy, options["certificates"], options["observation"], options["checksums"], continuation=options["continuation"])
    finally:
        live_capture.time, live_capture.PcapStreamDecoder, coordinator.secrets.token_hex = saved
        content.select(content.CURRENT)                   # the selection is process-wide
    return output.getvalue(), status


def normalized(text, as_json):
    """Event lines with the wall-time stage histograms reduced to their counts."""
    if not as_json:
        return text
    lines = []
    for line in text.splitlines():
        event = json.loads(line, object_pairs_hook=OrderedDict)
        for name, histogram in (event.get("telemetry") or {}).get("histograms", {}).items():
            if name.startswith("stage_seconds."):
                for key in ("sum", "min", "max", "p50", "p95", "p99", "buckets"):
                    histogram[key] = None
        lines.append(json.dumps(event))
    return "\n".join(lines) + ("\n" if lines else "")


def mismatch(actual, status, expected, as_json, returncode, stderr):
    """None when Go's (exit status, events) equal the expected ones, else what differs."""
    if returncode != status:
        return "exit status {} (expected {}): {}".format(returncode, status, stderr.decode("utf-8", "replace")[:200])
    if normalized(actual, as_json) != normalized(expected, as_json):
        a, b = normalized(actual, as_json).splitlines(), normalized(expected, as_json).splitlines()
        at = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
        return "event {} differs ({} lines, expected {})".format(at, len(a), len(b))
    return None


def count_kinds(expected, as_json, kinds):
    if as_json:
        for line in expected.splitlines():
            event = json.loads(line)
            label = event["type"] + ("/" + event.get("boundary", event.get("event", "")) if event["type"] == "classification" else "")
            kinds[label] = kinds.get(label, 0) + 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True, help="the Go protodetect binary")
    parser.add_argument("--count", type=int, default=300)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--record", help="also write the inputs and the reference's answers to this golden file (migration/parity/golden.py)")
    parser.add_argument("--golden", help="compare Go with this golden file's answers; the reference is not run")
    parser.add_argument("--record-sec-sess1", metavar="PATH", help="write every divergence to PATH for review; the run then fails")
    args = parser.parse_args(argv)
    if args.golden:
        return replay_golden(args)
    import pro189
    sec_sess1.self_test()
    pins = sec_sess1.Pins("live", args.seed, record=args.record_sec_sess1)
    rng = random.Random(args.seed)
    sessions = [case for case in json.loads((ROOT / "migration/fixtures/cases.json").read_text(encoding="utf-8"))["cases"] if case["kind"] == "session"]
    pro189.self_test()
    recorder = golden.recorder(args.record, "live", {"seed": args.seed, "count": args.count, "signatures": analyze_diff.SIGNATURES,
                                                     "policy": analyze_diff.POLICY})
    failures, events, kinds, approved = [], 0, {}, 0
    with tempfile.TemporaryDirectory() as folder:
        folder = Path(folder)
        signatures_path, policy_path = str(folder / "signatures.json"), str(folder / "policy.json")
        Path(signatures_path).write_text(json.dumps(analyze_diff.SIGNATURES), encoding="utf-8")
        Path(policy_path).write_text(json.dumps(analyze_diff.POLICY), encoding="utf-8")
        for index in range(args.count):
            capture = folder / "capture-{}".format(index)
            analyze_diff.write_capture(rng, capture, analyze_diff.stress_records(rng) if index % 3 == 2 else analyze_diff.records_for(rng, sessions))
            options, as_json = options_for(rng, signatures_path, policy_path)
            expected, status = reference(capture, options, as_json)
            with open(capture, "rb") as stream:
                done = subprocess.run([args.binary, "live"] + arguments(options, as_json), stdin=stream, stdout=subprocess.PIPE,  # noqa: S603
                                      stderr=subprocess.PIPE, check=False, timeout=120)
            actual = done.stdout.decode("utf-8")
            events += expected.count("\n")
            count_kinds(expected, as_json, kinds)
            problem = mismatch(actual, status, expected, as_json, done.returncode, done.stderr)
            judged, judged_status, reason = expected, status, None
            pins.cover(capture.name)
            if problem:
                # PRO-189: accept the mismatch only when Go matches the reference with that fix modelled exactly.
                with pro189.modelled():
                    modelled, modelled_status = reference(capture, options, as_json)
                if mismatch(actual, modelled_status, modelled, as_json, done.returncode, done.stderr) is None:
                    approved += 1
                    problem, judged, judged_status, reason = None, modelled, modelled_status, pro189.LABEL
                # SEC-SESS-1 (PRO-398): or only when this exact replay is pinned with both exact results; a golden
                # file then records Go's pinned answer.
                elif pins.approve(capture.name, normalized(actual, as_json), done.returncode, normalized(expected, as_json), status,
                                  " ".join(arguments(options, as_json)[4:]).replace(str(folder), "<tmp>")):
                    problem, judged, judged_status, reason = None, actual, done.returncode, sec_sess1.LABEL
            if problem:
                failures.append("{} {}: {}".format(capture.name, " ".join(arguments(options, as_json)[4:]), problem))
            if recorder:
                recorder.add({"capture": capture.name, "data": golden.b64(capture.read_bytes()), "argv": golden.relative(arguments(options, as_json), folder),
                              "json": as_json, "expected": golden.relative(judged, folder), "status": judged_status,
                              "approved": reason == pro189.LABEL, "sec_sess1": reason == sec_sess1.LABEL})
        for line in failures[:10]:
            print("live mismatch:", line)
    problems = pins.finish()
    for line in problems:
        print("live parity FAILED:", line)
    print("live parity: {} replays, {} event lines, {} mismatched, {} approved divergences ({}), {} approved divergences ({}) (seed {}); "
          "JSON events: {}".format(args.count, events, len(failures), approved, pro189.LABEL, len(pins.approved), sec_sess1.LABEL, args.seed,
                                   ", ".join("{} {}".format(name, kinds[name]) for name in sorted(kinds))))
    if recorder:
        recorder.finish(failures or problems)
    return 1 if failures or problems else 0


def replay_golden(args):
    """The gate without the reference: the recorded captures and arguments, Go's events against the recorded ones
    (an approved PRO-189 divergence is recorded as the modelled answer Go had to give)."""
    document = golden.read(args.golden, "live")
    failures, events, kinds, approved, pinned = [], 0, {}, 0, 0
    with tempfile.TemporaryDirectory() as folder:
        folder = Path(folder)
        (folder / "signatures.json").write_text(json.dumps(document["signatures"]), encoding="utf-8")
        (folder / "policy.json").write_text(json.dumps(document["policy"]), encoding="utf-8")
        for entry in document["entries"]:
            data, argv, as_json = golden.unb64(entry["data"]), golden.absolute(entry["argv"], folder), entry["json"]
            expected = golden.absolute(entry["expected"], folder)
            capture = folder / entry["capture"]
            capture.write_bytes(data)
            with open(capture, "rb") as stream:     # a file, as in the recording run: the reads then split the same way
                done = subprocess.run([args.binary, "live"] + argv, stdin=stream, stdout=subprocess.PIPE,  # noqa: S603
                                      stderr=subprocess.PIPE, check=False, timeout=120)
            events += expected.count("\n")
            count_kinds(expected, as_json, kinds)
            approved += bool(entry.get("approved"))
            pinned += bool(entry.get("sec_sess1"))
            problem = mismatch(done.stdout.decode("utf-8"), entry["status"], expected, as_json, done.returncode, done.stderr)
            if problem:
                failures.append("{} {}: {}".format(entry["capture"], " ".join(entry["argv"][4:]), problem))
    for line in failures[:10]:
        print("live mismatch:", line)
    print("live parity (golden {}): {} replays, {} event lines, {} mismatched, {} recorded approved divergences (PRO-189), {} recorded approved divergences ({}) (recorded with seed {}); "
          "JSON events: {}".format(Path(args.golden).name, len(document["entries"]), events, len(failures), approved, pinned, sec_sess1.LABEL,
                                   document.get("seed"), ", ".join("{} {}".format(name, kinds[name]) for name in sorted(kinds))))
    return 1 if failures else 0

if __name__ == "__main__":
    sys.exit(main())
