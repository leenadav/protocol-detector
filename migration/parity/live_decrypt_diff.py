"""Migration M8: the Go live decryption worker against the Python reference, on replayed scripts.

    python3 -B migration/parity/live_decrypt_diff.py --binary PATH [--count 300] [--seed 1]

The worker (presentation/poc_decryption/live.py) depends on a capture, a clock and a key-log file that grows
while it runs. Here all three are a script: generated TLS captures (decrypt_diff.py's generator) cut into pipe
reads of seeded sizes, key-log text appended before, between or after them (late keys, missing keys, damaged
lines), periodic ticks and the end of the capture, each with its clock value. The reference's real objects
(CaptureMonitor with the retained tier, LiveDecoder, Decryptor) are driven by the script in process, with the
steps of live.py's main() around them; the Go binary reads the same script (`live-decrypt --replay`). Compared
as text, in order: every classification, session record, capture gap, progress summary, provisional and final
decryption report, the sanitized failure and the exit status; work-stage durations by count only. Nothing is
captured and no secret is written to disk or printed. Needs the `cryptography` package for the reference.
Since PRO-401 the gate replays a golden file instead (--golden; --record writes one): migration/parity/golden.py.
"""
import argparse
import json
import random
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "presentation"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

CAPTURE_ID = "0123456789abcdef"


def script_for(rng, generator):
    """[(kind, now, data)] for one generated capture and key log."""
    capture, keylog = generator.capture()
    lines = keylog.splitlines(keepends=True)
    timing = rng.random()
    early = lines if timing < 0.45 else lines[:rng.randrange(len(lines) + 1)] if timing < 0.75 else []
    late = lines[len(early):]
    if rng.random() < 0.15:
        late = []                                              # those secrets never arrive
    operations, now = [], 100.0
    if early:
        operations.append(("K", now, "".join(early).encode("ascii", "replace")))
    offset = 0
    while offset < len(capture):
        size = rng.choice([1, 7, 100, 1500, 65536, 65536, 65536])
        operations.append(("P", now, capture[offset:offset + size]))
        offset += size
        now += rng.choice([0, 0, 0.01, 0.3, 1.0, 20.0, 61.0])
        if rng.random() < 0.3:
            operations.append(("T", now, b""))
        if late and rng.random() < 0.2:
            take = rng.randrange(1, len(late) + 1)
            operations.append(("K", now, "".join(late[:take]).encode("ascii", "replace")))
            late = late[take:]
    if late and rng.random() < 0.7:
        operations.append(("K", now, "".join(late).encode("ascii", "replace")))
    if rng.random() < 0.02:
        operations.append(("P", now, bytes(2 * 1024 * 1024)))   # past the capture budget
    for _ in range(rng.choice([0, 1, 1, 3])):
        now += rng.choice([0.5, 1.0, 30.0, 61.0])
        operations.append(("T", now, b""))
    if rng.random() < 0.9:
        operations.append(("E", now, b""))
    return operations


def reference(operations):
    """(event lines, exit status) of the reference worker driven by the script."""
    from poc_decryption import MAX_STREAM, DecryptionError
    from poc_decryption import live as worker
    from protocol_adapters import coordinator
    from protocol_adapters.coordinator import RetentionBudget
    from protocol_adapters.live_capture import CaptureMonitor
    lines, emit = [], lambda event: lines.append(json.dumps(event))
    saved = coordinator.secrets.token_hex
    coordinator.secrets.token_hex = lambda size: CAPTURE_ID
    try:
        monitor = CaptureMonitor(emit, max_connections=worker.MAX_CONNECTIONS, byte_limit=16384, all_events=True,
                                 retain=RetentionBudget(per_direction=MAX_STREAM, connections=worker.MAX_CONNECTIONS))
    finally:
        coordinator.secrets.token_hex = saved
    decoder, error = worker.LiveDecoder(monitor), None
    try:
        for kind, now, data in operations:
            if kind == "K":
                decoder.advance(data.decode("ascii"))
            elif kind == "P":
                decoder.feed(data, now)
                decoder.advance()
            elif kind == "T":
                monitor.coordinator.tick(now)
                decoder.advance()
                emit(monitor.summary(now))
                emit(dict(type="decryption", report=decoder.snapshot(), provisional=True))
            else:
                decoder.advance()
                decoder.end()
                emit(dict(type="decryption", report=decoder.snapshot(), provisional=False, capture_stats={}, capture_quality="unverified"))
                emit(monitor.summary(now, final=True, capture_stats={}))
    except Exception as failure:          # noqa: BLE001 - the worker maps every failure to a sanitized code, as below
        if isinstance(failure, worker.KeyLogError):
            code = failure.code
        elif isinstance(failure, DecryptionError):
            code = "budget" if failure.code == "budget_exhausted" else "key_log"
        elif isinstance(failure, (OSError, KeyError, json.JSONDecodeError)):
            code = "key_log"
        else:
            code = "internal"
        error = worker.ERROR_CODES[code]
        monitor.invalidate_all(error, scope="all_observations_this_capture")
        emit({"type": "decryption", "report": {"connections": [], "frames": decoder.frames, "decrypted": 0}})
        emit({"type": "error", "reason": error, "code": code})
    finally:
        decoder.keys.release()
    return "".join(line + "\n" for line in lines), 1 if error else 0


def approved_model(operations, status, actual):
    """PRO-260 (Lee, 2026-11-23): Go names the post-quantum hybrid ServerHello groups the frozen reference reports
    as unknown. A run that differs from the reference is approved only when its exit status and every normalized
    event line equal the reference's under that one change (migration/parity/pro260.py)."""
    import live_diff
    import pro260
    with pro260.with_hybrid_groups():
        expected, model_status = reference(operations)
    return (expected, model_status) if model_status == status and live_diff.normalized(expected, True) == actual else None


def count_events(expected, kinds):
    for line in expected.splitlines():
        event = json.loads(line)
        label = event["type"]
        if label == "decryption":
            for row in event["report"]["connections"]:
                name = "row/" + row["status"]
                kinds[name] = kinds.get(name, 0) + 1
        elif label == "error":
            label = "error/" + event["code"]
        kinds[label] = kinds.get(label, 0) + 1


def run_go(binary, script):
    done = subprocess.run([binary, "live-decrypt", "--replay", "--capture-id", CAPTURE_ID], input=script, stdout=subprocess.PIPE,  # noqa: S603
                          stderr=subprocess.PIPE, check=False, timeout=180)
    return done.returncode, done.stdout.decode("utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True, help="the Go protodetect binary")
    parser.add_argument("--count", type=int, default=300)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--record", help="also write the scripts and the reference's answers to this golden file (migration/parity/golden.py)")
    parser.add_argument("--golden", help="compare Go with this golden file's answers; the reference is not run")
    parser.add_argument("--record-sec-sess1", metavar="PATH", help="write every divergence to PATH for review; the run then fails")
    args = parser.parse_args(argv)
    import golden
    import live_diff
    if args.golden:
        return replay_golden(args)
    import decrypt_diff
    import sec_sess1
    sec_sess1.self_test()
    pins = sec_sess1.Pins("live-decrypt", args.seed, record=args.record_sec_sess1)
    try:
        generator = decrypt_diff.Generator(args.seed)
    except ImportError:
        print("live decrypt parity FAILED: the reference needs the `cryptography` package "
              "(python3 -m pip install --require-hashes -r presentation/requirements-decryption.lock.txt)")
        return 1
    recorder = golden.recorder(args.record, "live-decrypt", {"seed": args.seed, "count": args.count})
    rng = random.Random(args.seed * 7919 + 1)
    failures, events, kinds, approved = [], 0, {}, 0
    openssl, used = generator.openssl, []
    # The scripts depend on the OpenSSL that Python links (the real exchanges' lengths drive later random draws; 3.5
    # also offers hybrid groups), so a SEC-SESS-1 pin names the OpenSSL line as part of its case id.
    environment = sec_sess1.openssl_line()

    def counted():                                  # a real OpenSSL exchange differs between runs (sec_sess1 `volatile`)
        used.append(True)
        return openssl()
    generator.openssl = counted
    for index in range(args.count):
        del used[:]
        operations = script_for(rng, generator)
        volatile = bool(used)
        expected, status = reference(operations)
        script = b"".join(kind.encode("ascii") + struct.pack(">dI", now, len(data)) + data for kind, now, data in operations)
        returncode, actual = run_go(args.binary, script)
        events += expected.count("\n")
        count_events(expected, kinds)
        a, b = live_diff.normalized(actual, True), live_diff.normalized(expected, True)
        judged, reason = (expected, status), None
        case = "{}/script-{}".format(environment, index)
        pins.cover(case)
        model = approved_model(operations, returncode, a) if (returncode != status or a != b) else None
        if model:
            approved += 1
            judged, reason = model, "PRO-260"
        elif (returncode != status or a != b) and pins.approve(case, a, returncode, b, status, volatile=volatile):
            judged, reason = (actual, returncode), sec_sess1.LABEL   # SEC-SESS-1 (PRO-398): this exact script, both results pinned
        elif returncode != status:
            failures.append("script {} (seed {}): exit status {} (expected {})".format(index, args.seed, returncode, status))
        elif a != b:
            x, y = a.splitlines(), b.splitlines()
            at = next((i for i, (p, q) in enumerate(zip(x, y)) if p != q), min(len(x), len(y)))
            failures.append("script {} (seed {}): event {} differs ({} lines, expected {})".format(index, args.seed, at, len(x), len(y)))
        if recorder:
            recorder.add({"script": golden.b64(script), "expected": judged[0], "status": judged[1], "approved": reason == "PRO-260",
                          "sec_sess1": reason == sec_sess1.LABEL})
    for line in failures[:10]:
        print("live decrypt mismatch:", line)
    problems = pins.finish()
    for line in problems:
        print("live decrypt parity FAILED:", line)
    print("live decrypt parity: {} scripts, {} event lines, {} mismatched, {} approved divergences (PRO-260), {} approved divergences ({}) "
          "(seed {}); events: {}".format(args.count, events, len(failures), approved, len(pins.approved), sec_sess1.LABEL, args.seed,
                                         ", ".join("{} {}".format(name, kinds[name]) for name in sorted(kinds))))
    if recorder:
        recorder.finish(failures or problems)
    return 1 if failures or problems else 0


def replay_golden(args):
    """The gate without the reference: the recorded scripts, Go's normalized events against the recorded ones."""
    import golden
    import live_diff
    document = golden.read(args.golden, "live-decrypt")
    failures, events, kinds, approved, pinned = [], 0, {}, 0, 0
    for index, entry in enumerate(document["entries"]):
        returncode, actual = run_go(args.binary, golden.unb64(entry["script"]))
        expected = entry["expected"]
        events += expected.count("\n")
        count_events(expected, kinds)
        approved += bool(entry.get("approved"))
        pinned += bool(entry.get("sec_sess1"))
        a, b = live_diff.normalized(actual, True), live_diff.normalized(expected, True)
        if returncode != entry["status"]:
            failures.append("script {}: exit status {} (expected {})".format(index, returncode, entry["status"]))
        elif a != b:
            x, y = a.splitlines(), b.splitlines()
            at = next((i for i, (p, q) in enumerate(zip(x, y)) if p != q), min(len(x), len(y)))
            failures.append("script {}: event {} differs ({} lines, expected {})".format(index, at, len(x), len(y)))
    for line in failures[:10]:
        print("live decrypt mismatch:", line)
    print("live decrypt parity (golden {}): {} scripts, {} event lines, {} mismatched, {} recorded approved divergences (PRO-260), "
          "{} recorded approved divergences (SEC-SESS-1) (recorded with seed {}); events: {}".format(
              Path(args.golden).name, len(document["entries"]), events, len(failures), approved, pinned, document.get("seed"),
              ", ".join("{} {}".format(name, kinds[name]) for name in sorted(kinds))))
    return 1 if failures else 0

if __name__ == "__main__":
    sys.exit(main())
