#!/usr/bin/env python3
"""Migration C14: the Go live control plane's run state against the reference's LiveManager.

Worker lines come from the Go binary itself on generated inputs: `live --replay-clock --json` on the captures
of live_diff.py (whose output parity-live already proves equal to the reference's) and, when the
decryption extra is installed, `live-decrypt --replay` on the scripts of live_decrypt_diff.py. Each run's
lines are mixed with duplicates, capture gaps that name real session ids, and a few malformed lines, then
driven through both implementations with the same script of operations: fresh runs, ingests, cursor reads
(old, current, ahead, past retention, invalid), snapshots, state views and run-scoped resets naming the
current run, a stale run, none or a non-string. Every answer must be the same JSON text. JSON documents are
also echoed through both decoders and encoders. Nothing is captured; no process is started on the
reference side.

A worker run that did not complete fails the run instead of feeding both sides the same short stream
(PRO-21): neither worker may write to standard error or emit no events, and every line must be a JSON event.
`live` must exit 0, 1 (after an error event) or 2 (drops or truncation, live_capture.py) and include its
closing summary; `live-decrypt --replay`, whose script may legitimately end before any summary, must give the
exit status and events of the reference worker on the same script (live_decrypt_diff.reference).
"""
import argparse
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "presentation"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze_diff  # noqa: E402
import live_diff  # noqa: E402
from live_manager import LiveManager  # noqa: E402
from protocol_adapters import events as reference_events  # noqa: E402


def reference(script):
    """The reference's answers to a script, one JSON line per read."""
    manager, out = LiveManager(), []
    for line in script:
        op, _, arg = line.partition(" ")
        if op == "J":
            try:
                out.append(json.dumps(json.loads(bytes.fromhex(arg)), allow_nan=False))
            except ValueError as error:
                out.append(json.dumps({"error": str(error)}))
        elif op == "N":
            capture_id, phase = arg.split(" ")
            with manager.lock:            # start()'s reset of the retained state, without the worker process
                manager.events.clear()
                manager.sessions.clear()
                manager.summary, manager.decryption, manager.error = {}, None, None
                manager.sequence = manager.session_count = 0
                manager.capture_id = capture_id
                manager.log = reference_events.EventLog(capture_id)
                manager.interface = "lo"
                manager.lease = 0
                manager.state = phase
        elif op == "I":
            manager.ingest(json.loads(arg))
        elif op == "E":
            cursor, limit = (int(x) for x in arg.split(" "))
            try:
                out.append(json.dumps(manager.events_since(cursor, limit), allow_nan=False))
            except ValueError as error:
                out.append(json.dumps({"error": str(error)}))
        elif op == "S":
            out.append(json.dumps(manager.snapshot(), allow_nan=False))
        elif op == "V":
            out.append(json.dumps(manager.state_view(), allow_nan=False))
        elif op == "X":
            outcome = manager.reset(json.loads(arg))
            out.append(json.dumps(dict(manager.state_view(), **outcome), allow_nan=False))
    return out


class WorkerFailure(Exception):
    """A worker run that crashed, failed or stopped before its closing summary."""


def worker_problem(command, returncode, stdout, stderr, statuses, summary=True):
    """Why one worker run cannot serve as input, or None: its exit status, standard error and events."""
    if returncode not in statuses:
        return "{} exit status {} (expected one of {}): {}".format(command, returncode, statuses, stderr.decode("utf-8", "replace")[:200])
    if stderr:
        return "{} wrote to standard error: {}".format(command, stderr.decode("utf-8", "replace")[:200])
    lines = [line for line in stdout.decode("utf-8", "replace").splitlines() if line]
    if not lines:
        return "{} emitted no events".format(command)
    try:
        kinds = [json.loads(line).get("type") for line in lines]
    except (ValueError, AttributeError):
        return "{} emitted a line that is not a JSON event".format(command)
    if summary and "summary" not in kinds:
        return "{} emitted no summary event ({} events)".format(command, len(lines))
    return None


def checked_lines(command, done, statuses, summary=True, expected=None):
    problem = worker_problem(command, done.returncode, done.stdout, done.stderr, statuses, summary)
    if problem is None and expected is not None and live_diff.normalized(done.stdout.decode("utf-8"), True) != live_diff.normalized(expected, True):
        problem = "{} events differ from the reference worker's on the same script".format(command)
    if problem:
        raise WorkerFailure(problem)
    return [line for line in done.stdout.decode("utf-8").splitlines() if line]


def worker_lines(binary, rng, sessions, folder, index, signatures_path, policy_path):
    capture = folder / "capture-{}".format(index)
    analyze_diff.write_capture(rng, capture, analyze_diff.stress_records(rng) if index % 3 == 2 else analyze_diff.records_for(rng, sessions))
    options, _ = live_diff.options_for(rng, signatures_path, policy_path)
    options["all_events"] = rng.random() < 0.8
    with open(capture, "rb") as stream:
        done = subprocess.run([binary, "live"] + live_diff.arguments(options, True), stdin=stream, stdout=subprocess.PIPE,  # noqa: S603
                              stderr=subprocess.PIPE, check=False, timeout=120)
    return checked_lines("live", done, (0, 1, 2))


def decryption_lines(binary, rng, generator):
    import struct
    import live_decrypt_diff
    operations = live_decrypt_diff.script_for(rng, generator)
    expected, status = live_decrypt_diff.reference(operations)
    script = b"".join(kind.encode("ascii") + struct.pack(">dI", now, len(data)) + data for kind, now, data in operations)
    done = subprocess.run([binary, "live-decrypt", "--replay", "--capture-id", live_decrypt_diff.CAPTURE_ID], input=script,  # noqa: S603
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=180)
    return checked_lines("live-decrypt", done, (status,), summary=False, expected=expected)


MALFORMED = [
    {"type": "capture_gap", "reason": "Packet LOSS reported", "session_ids": ["0011223344556677"]},
    {"type": "capture_gap", "reason": None, "scope": "all_observations_this_capture"},
    {"type": "summary", "packets": 1, "ratio": 0.5, "big": 123456789012345678901234567890},
    {"type": "classification", "client": ["10.0.0.1", 5], "server": ["10.0.0.2", 6], "status": "budget_exhausted", "scope": ""},
    {"type": "error", "reason": "worker failed"},
    {"type": "error"},
    {"type": "unknown-kind"},
    {"type": 7},
    {"no_type": True},
    {"type": "decryption", "report": {"connections": [{"session_id": "aa", "generation": 2, "status": "decrypted"}, {"session_id": ""}]},
     "provisional": True, "capture_quality": "intact"},
    {"type": "decryption", "report": None, "provisional": False},
    {"type": "session", "client": ["10.0.0.9", 9], "server": ["10.0.0.1", 80], "encryption": "tls", "client_protocol": "tls", "app": "tls"},
]

def json_documents(rng, count):
    """Valid documents and byte-level mutations of them: truncations, insertions, invalid UTF-8, encoded
    surrogates and BOMs. Documents json.loads would read as UTF-16 or UTF-32 are left out (not decoded by Go)."""
    alphabet = [b"{", b"}", b"[", b"]", b",", b":", b'"', b"\\", b"u", b"d83d", b"de00", b"d800", b"0", b"-", b"e", b".", b"1",
                b" ", b"\n", b"\x01", b"\xff", b"\xc3", b"\xa9", b"\xed\xa0\x80", b"\xe2\x82", b"\xf0\x9f\x98", b"\xef\xbb\xbf",
                b"NaN", b"Infinity", b"null", b"tru", b"9" * 40]
    out = []
    for _ in range(count):
        doc = rng.choice(JSON_DOCS).encode("utf-8", "surrogatepass")
        for _ in range(rng.randint(0, 3)):
            at = rng.randint(0, len(doc))
            choice = rng.random()
            if choice < 0.4:
                doc = doc[:at] + rng.choice(alphabet) + doc[at:]
            elif choice < 0.7:
                doc = doc[:at] + doc[at + rng.randint(1, 3):]
            else:
                doc = doc[:at]
        if json.detect_encoding(doc) in ("utf-8", "utf-8-sig"):
            out.append(doc)
    return out


JSON_DOCS = ['{"a": 1, "b": [1.5, -0, 1e2, 2E-3, 1.0, 12345678901234567890123], "a": 2}', '{"s": "\\u00e9\\ud83d\\ude00\\n\\"x"}',
             '[]', '{}', '  {"x" : null , "y":true,"z":false}  ', '{"x": 1,}', '[1 2]', '"\\ud800"', '{"x": 01}', '{"x": "\x01"}', '{"a": [1, {"b": "\\ud83d\\ude00"}], "c": -1.5e-3}', '[1, 2, 3]',
             '[NaN]', '[-Infinity]', '{"k": 1e400}', '[0.1, 100000000000000000.0, 1e-7, 123.456e10]', '{"x": "\\/"}', '{"x"', '']


def script_for(rng, lines, retention_probe):
    events = [json.dumps(json.loads(line)) for line in lines]
    sids = sorted({reference_events.session_identity(e.get("transport", "tcp"), e.get("client") or e.get("source"),
                                                       e.get("server") or e.get("destination"))
                   for e in map(json.loads, events) if (e.get("client") or e.get("source")) and (e.get("server") or e.get("destination"))
                   and isinstance(e.get("client") or e.get("source"), list)})
    pool = list(events)
    for _ in range(rng.randint(0, 4)):
        pool.insert(rng.randint(0, len(pool)), json.dumps(rng.choice(MALFORMED)))
    for _ in range(rng.randint(0, 3)):
        if sids:
            gap = {"type": "capture_gap", "reason": rng.choice(["capture loss", "tcpdump dropped packets", "gap"]),
                   "session_ids": rng.sample(sids, min(len(sids), rng.randint(1, 3)))}
            pool.insert(rng.randint(0, len(pool)), json.dumps(gap))
    if pool and rng.random() < 0.5:
        pool += rng.sample(pool, min(len(pool), 5))           # duplicate deliveries of whole lines
    capture_ids = ["{:016x}".format(rng.getrandbits(64)) for _ in range(2)]
    script = ["N {} {}".format(capture_ids[0], rng.choice(["running", "stopped", "failed"]))]
    if retention_probe:                                       # past the retention of 4096: reset_required for old cursors
        filler = json.dumps({"type": "progress", "packets": 1})
        big = [json.dumps({"type": "error", "reason": "e{}".format(i)}) for i in range(4200)]
        pool = big + pool + [filler]
    for i, line in enumerate(pool):
        script.append("I " + line)
        if rng.random() < 0.08 or i == len(pool) - 1:
            script.append(rng.choice(["S", "V", "E {} {}".format(rng.randint(0, i + 2), rng.choice([1, 5, 500, 10000]))]))
    for cursor, limit in ((0, 500), (1, 1), (10 ** 6, 500), (-1, 500), (0, 0), (0, 10001), (3, 10000)):
        script.append("E {} {}".format(cursor, limit))
    if retention_probe:                                       # cursors on both sides of the oldest retained event
        edge = len(pool) - 4096
        script += ["E {} 1".format(cursor) for cursor in range(max(1, edge - 12), edge + 4)]
    script += ["S", "V"]
    script.append("X " + json.dumps(rng.choice([None, capture_ids[1], 0, 5, capture_ids[0]])))
    script += ["S", "E 0 500", "X " + json.dumps(capture_ids[0]), "V", "E 0 500"]
    script.append("N {} running".format(capture_ids[1]))
    script += ["I " + line for line in pool[:20]] + ["V", "X " + json.dumps(capture_ids[0]), "X null", "S"]
    script += ["J " + doc.hex() for doc in json_documents(rng, 40)]
    return script


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True, help="the Go protodetect binary")
    parser.add_argument("--count", type=int, default=120)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args(argv)
    rng = random.Random(args.seed)
    sessions = [case for case in json.loads((ROOT / "migration/fixtures/cases.json").read_text(encoding="utf-8"))["cases"] if case["kind"] == "session"]
    try:
        import decrypt_diff
        generator = decrypt_diff.Generator(args.seed)
    except ImportError:
        print("control parity FAILED: the decryption runs need the `cryptography` package "
              "(python3 -m pip install --require-hashes -r presentation/requirements-decryption.lock.txt)")
        return 1
    failures, reads, ingested = [], 0, 0
    with tempfile.TemporaryDirectory() as folder:
        folder = Path(folder)
        signatures_path, policy_path = str(folder / "signatures.json"), str(folder / "policy.json")
        Path(signatures_path).write_text(json.dumps(analyze_diff.SIGNATURES), encoding="utf-8")
        Path(policy_path).write_text(json.dumps(analyze_diff.POLICY), encoding="utf-8")
        for index in range(args.count):
            try:
                if generator is not None and index % 4 == 3:
                    lines = decryption_lines(args.binary, rng, generator)
                else:
                    lines = worker_lines(args.binary, rng, sessions, folder, index, signatures_path, policy_path)
            except WorkerFailure as failure:
                failures.append("run {} (seed {}): worker {}".format(index, args.seed, failure))
                continue
            script = script_for(rng, lines, index % 5 == 1)
            ingested += sum(line.startswith("I ") for line in script)
            expected = reference(script)
            done = subprocess.run([args.binary, "control-replay"], input="\n".join(script).encode("utf-8") + b"\n",  # noqa: S603
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=300)
            actual = done.stdout.decode("utf-8").splitlines()
            reads += len(expected)
            if done.returncode != 0 or actual != expected:
                at = next((i for i, (x, y) in enumerate(zip(actual, expected)) if x != y), min(len(actual), len(expected)))
                detail = "" if at >= min(len(actual), len(expected)) else " go {} | ref {}".format(actual[at][:300], expected[at][:300])
                failures.append("run {} (seed {}): read {} differs ({} reads, expected {}){}".format(index, args.seed, at, len(actual), len(expected), detail))
    for line in failures[:5]:
        print("control mismatch:", line)
    print("control parity: {} runs, {} lines ingested, {} reads, {} mismatched (seed {})".format(
        args.count, ingested, reads, len(failures), args.seed))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
