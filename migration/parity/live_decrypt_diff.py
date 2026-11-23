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


def approved_divergence(operations, status, actual):
    """PRO-260 (Lee, 2026-11-23): Go names the post-quantum hybrid ServerHello groups the frozen reference reports
    as unknown. A run that differs from the reference is approved only when its exit status and every normalized
    event line equal the reference's under that one change (migration/parity/pro260.py)."""
    import live_diff
    import pro260
    with pro260.with_hybrid_groups():
        expected, model_status = reference(operations)
    return model_status == status and live_diff.normalized(expected, True) == actual


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True, help="the Go protodetect binary")
    parser.add_argument("--count", type=int, default=300)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args(argv)
    import decrypt_diff
    import live_diff
    try:
        generator = decrypt_diff.Generator(args.seed)
    except ImportError:
        print("live decrypt parity FAILED: the reference needs the `cryptography` package "
              "(python3 -m pip install --require-hashes -r presentation/requirements-decryption.lock.txt)")
        return 1
    rng = random.Random(args.seed * 7919 + 1)
    failures, events, kinds, approved = [], 0, {}, 0
    for index in range(args.count):
        operations = script_for(rng, generator)
        expected, status = reference(operations)
        script = b"".join(kind.encode("ascii") + struct.pack(">dI", now, len(data)) + data for kind, now, data in operations)
        done = subprocess.run([args.binary, "live-decrypt", "--replay", "--capture-id", CAPTURE_ID], input=script, stdout=subprocess.PIPE,  # noqa: S603
                              stderr=subprocess.PIPE, check=False, timeout=180)
        actual = done.stdout.decode("utf-8")
        events += expected.count("\n")
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
        a, b = live_diff.normalized(actual, True), live_diff.normalized(expected, True)
        if (done.returncode != status or a != b) and approved_divergence(operations, done.returncode, a):
            approved += 1
        elif done.returncode != status:
            failures.append("script {} (seed {}): exit status {} (expected {})".format(index, args.seed, done.returncode, status))
        elif a != b:
            x, y = a.splitlines(), b.splitlines()
            at = next((i for i, (p, q) in enumerate(zip(x, y)) if p != q), min(len(x), len(y)))
            failures.append("script {} (seed {}): event {} differs ({} lines, expected {})".format(index, args.seed, at, len(x), len(y)))
    for line in failures[:10]:
        print("live decrypt mismatch:", line)
    print("live decrypt parity: {} scripts, {} event lines, {} mismatched, {} approved divergences (PRO-260) (seed {}); events: {}".format(
        args.count, events, len(failures), approved, args.seed, ", ".join("{} {}".format(name, kinds[name]) for name in sorted(kinds))))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
