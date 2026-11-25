"""Migration C13: the Go binary's output validates against the published schemas (schemas/*.json).

    python3 -B migration/parity/schema_go.py --binary PATH [--count 200] [--seed 1]

Captures come from analyze_diff.py's generators (conversations of the committed session cases with faults,
and bounded-prefix stress conversations). Every line the Go binary writes is validated with the repository's
own validator (tools/schema_check.py), with the schema the reference's tests use for that output
(test_schema.py): `analyze --json` rows against offline-row and its session rows also against session, and
`live --json` events against live-event; session records' `engine_status` is also checked against the reference's
closed vocabulary (protocol_engine.policy.ENGINE_STATUSES), which the published schema does not enumerate. Every
invocation must also complete with its documented exit status (invocation_problem), so a crash or a timeout is a
problem rather than a shorter set of lines to validate. Options are seeded as in analyze_diff.py and live_diff.py. Nothing
is captured; nothing in the Python tree is changed or imported for behaviour, only to validate. With --golden
(migration/parity/golden.py) the inputs and the vocabulary come from the golden file and the reference is not imported.
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
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import analyze_diff  # noqa: E402
import control_diff  # noqa: E402 - the live worker's completion contract
import live_diff  # noqa: E402
import golden  # noqa: E402
import schema_check  # noqa: E402

# Values the Python reference itself emits although its list omits them (reported to Lee, not changed here):
# appid.midstream_outcome and unobserved_start_outcome return engine_status "midstream".
REFERENCE_GAPS = ("midstream",)
# protocol_adapters/live_capture.py publishes an invalidation without events in this layout; the live-event schema
# requires "app" on every classification, so the reference's own output does not validate either.
INVALIDATED_KEYS = {"type", "timestamp", "source", "destination", "transport", "status", "protocol", "scope", "reason"}


CAPTURE_ERROR = "Capture error: "        # analyze's documented refusal (exit 1), as analyze_diff.reference gives it


def invocation_problem(command, done):
    """Why a finished invocation's lines are not the whole output to validate (Codex PRO-21), or None.
    `analyze` exits 0 with nothing on stderr, or 1 with the reference's capture-error text; `live` ends with
    its summary and the exit status that summary implies (control_diff.worker_result)."""
    stderr = done.stderr.decode("utf-8", "replace")
    if command == "live":
        try:
            control_diff.worker_result("live", done)
        except control_diff.WorkerError as error:
            return str(error)
        return None
    if (done.returncode, bool(stderr)) == (0, False) or (done.returncode == 1 and stderr.startswith(CAPTURE_ERROR)):
        return None
    return "{} exited with status {}; stderr: {}".format(command, done.returncode, stderr[-400:].strip() or "<empty>")


def invoke(command, argv, timeout=120, **kwargs):
    """(completed process, None), or (None, problem) when the invocation did not complete in time."""
    try:
        return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=timeout, **kwargs), None  # noqa: S603
    except subprocess.TimeoutExpired:
        return None, "{} timed out after {} s".format(command, timeout)


def generated(args, folder, signatures, policy):
    """(capture name, bytes, analyze options, live arguments) from the seeded generators (the reference's fixtures)."""
    rng = random.Random(args.seed)
    sessions = [case for case in json.loads((ROOT / "migration/fixtures/cases.json").read_text(encoding="utf-8"))["cases"] if case["kind"] == "session"]
    for index in range(args.count):
        capture = folder / "capture-{}".format(index)
        analyze_diff.write_capture(rng, capture, analyze_diff.stress_records(rng) if index % 3 == 2 else analyze_diff.records_for(rng, sessions))
        options = [option for option in analyze_diff.options_for(rng, signatures, policy)]
        if "--json" not in options:
            options.append("--json")
        live_options, _ = live_diff.options_for(rng, signatures, policy)
        yield capture.name, capture.read_bytes(), options, live_diff.arguments(live_options, True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--record", help="also write the generated inputs (and the reference's engine-status vocabulary) to this golden file")
    parser.add_argument("--golden", help="validate Go's output on this golden file's inputs; nothing of the reference is imported")
    args = parser.parse_args(argv)
    document = golden.read(args.golden, "schema") if args.golden else None
    if document:
        statuses, signatures_doc, policy_doc = set(document["engine_statuses"]), document["signatures"], document["policy"]
    else:
        from protocol_engine.policy import ENGINE_STATUSES  # the reference's closed engine-status vocabulary
        statuses, signatures_doc, policy_doc = set(ENGINE_STATUSES), analyze_diff.SIGNATURES, analyze_diff.POLICY
    recorder = golden.recorder(args.record, "schema", {"seed": args.seed, "count": args.count, "engine_statuses": sorted(statuses),
                                                       "signatures": signatures_doc, "policy": policy_doc})
    schemas = {name: schema_check.load(name) for name in ("offline-row", "session", "live-event")}
    counts = {name: 0 for name in schemas}
    problems, gaps, captures = [], {}, 0

    def check(name, line, where):
        instance = json.loads(line)
        counts[name] += 1
        for problem in schema_check.validate(instance, schemas[name]):
            problems.append("{} [{}]: {}".format(where, name, problem))
        return instance

    with tempfile.TemporaryDirectory() as folder:
        folder = Path(folder)
        signatures, policy = str(folder / "signatures.json"), str(folder / "policy.json")
        Path(signatures).write_text(json.dumps(signatures_doc), encoding="utf-8")
        Path(policy).write_text(json.dumps(policy_doc), encoding="utf-8")
        if document:
            items = ((entry["capture"], golden.unb64(entry["data"]), golden.absolute(entry["options"], folder), golden.absolute(entry["live"], folder))
                     for entry in document["entries"])
        else:
            items = generated(args, folder, signatures, policy)
        for name, data, options, live_arguments in items:
            captures += 1
            capture = folder / name
            capture.write_bytes(data)
            if recorder:
                recorder.add({"capture": name, "data": golden.b64(data), "options": golden.relative(options, folder),
                              "live": golden.relative(live_arguments, folder)})
            done, problem = invoke("analyze", [args.binary, "analyze", str(capture)] + options)
            problem = problem or invocation_problem("analyze", done)
            if problem:
                problems.append("analyze {} {}: {}".format(capture.name, " ".join(options), problem))
            for line in (done.stdout.decode("utf-8").splitlines() if done else ()):
                row = check("offline-row", line, "analyze {} {}".format(capture.name, " ".join(options)))
                if row.get("type") == "session":
                    check("session", line, "analyze {}".format(capture.name))
                    # C13 names engine_status a closed vocabulary; schemas/session.schema.json types it only as a
                    # string, so the vocabulary is checked here against the reference's own list.
                    status = row.get("engine_status")
                    if status in REFERENCE_GAPS:
                        gaps[status] = gaps.get(status, 0) + 1
                    elif status not in statuses:
                        problems.append("analyze {}: engine_status {!r} outside the closed vocabulary".format(capture.name, status))
            with open(capture, "rb") as stream:
                done, problem = invoke("live", [args.binary, "live"] + live_arguments, stdin=stream)
            problem = problem or invocation_problem("live", done)
            if problem:
                problems.append("live {}: {}".format(capture.name, problem))
            for line in (done.stdout.decode("utf-8").splitlines() if done else ()):
                event = json.loads(line)
                if set(event) == INVALIDATED_KEYS and event.get("status") == "invalidated" and event.get("type") == "classification":
                    # live_capture.CaptureMonitor.accept emits this layout without "app", which live-event requires.
                    gaps["live invalidated without app"] = gaps.get("live invalidated without app", 0) + 1
                    counts["live-event"] += 1
                    continue
                check("live-event", line, "live {}".format(capture.name))
    for line in problems[:10]:
        print("schema problem:", line)
    print("go schema check{}: {} captures; validated {} offline rows, {} session records, {} live events; {} problems (seed {}); "
          "reference vocabulary gaps seen: {}".format(" (golden {})".format(Path(args.golden).name) if document else "", captures,
                                                      counts["offline-row"], counts["session"], counts["live-event"], len(problems),
                                                      document.get("seed") if document else args.seed,
                                                      ", ".join("{} {}".format(k, v) for k, v in sorted(gaps.items())) or "none"))
    failed = problems or not all(counts.values())
    if recorder:
        recorder.finish(failed)
    return 1 if failed else 0

if __name__ == "__main__":
    sys.exit(main())
