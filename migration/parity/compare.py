"""Migration M1: compare a backend's results against the language-neutral cases.

    python3 -B migration/parity/compare.py --cases migration/fixtures/cases.json --backend python
    python3 -B migration/parity/compare.py --cases ... --results go-results.json      (a Go run's output)
    python3 -B migration/parity/compare.py --cases ... --backend python --plant wrong-positive  (self-test)

A results file has the same shape as the cases' `expected` entries keyed by case id:
{"backend": "...", "results": {"<case id>": {...}}}. Comparison is exact on everything the plan says must not
be normalized away: statuses, protocols, applications, hostnames, reason sentences, evidence (field, value,
source, strength) in order, event kinds and ordering, revisions, metrics, session records (minus the
content digest) and per-packet messages. Approved semantic deltas (migration/parity/deltas.json) may exempt
one named path of one named case, each with a justification; nothing else is tolerated.

`--plant` mutates the backend's results in one of five ways a regression could take and must be reported:
wrong-positive (an unknown becomes identified), missing-retraction (an invalidation becomes identified),
wrong-port (a session's server port changes), dropped-event (one intermediate event disappears),
boundary-shift (bytes_inspected / a shift boundary moves).
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

PLANTS = ("wrong-positive", "missing-retraction", "wrong-port", "dropped-event", "boundary-shift")


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def diff(expected, actual, path="$", out=None, limit=200):
    """Exact structural differences as (path, expected, actual) triples, bounded."""
    out = [] if out is None else out
    if len(out) >= limit:
        return out
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key in sorted(set(expected) | set(actual)):
            if key not in expected:
                out.append((path + "." + key, "<absent>", actual[key]))
            elif key not in actual:
                out.append((path + "." + key, expected[key], "<absent>"))
            else:
                diff(expected[key], actual[key], path + "." + key, out, limit)
    elif isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            out.append((path + ".length", len(expected), len(actual)))
        for index, (e, a) in enumerate(zip(expected, actual)):
            diff(e, a, "%s[%d]" % (path, index), out, limit)
    elif expected != actual:
        out.append((path, expected, actual))
    return out


def compare(cases_doc, results_doc, deltas=None):
    deltas = deltas or {}
    report = {"compared": 0, "matched": 0, "mismatched": [], "missing": [], "extra": [], "exempted": 0}
    results = results_doc.get("results", {})
    for case in cases_doc["cases"]:
        cid = case["id"]
        if cid not in results:
            report["missing"].append(cid)
            continue
        report["compared"] += 1
        differences = diff(case["expected"], results[cid])
        allowed = {item["path"] for item in deltas.get(cid, [])}
        kept = [d for d in differences if d[0] not in allowed]
        report["exempted"] += len(differences) - len(kept)
        if kept:
            report["mismatched"].append({"id": cid, "kind": case["kind"], "label": case.get("label"),
                                         "differences": [{"path": p, "expected": e, "actual": a} for p, e, a in kept[:20]]})
        else:
            report["matched"] += 1
    report["extra"] = sorted(set(results) - {case["id"] for case in cases_doc["cases"]})
    report["ok"] = not report["mismatched"] and not report["missing"]
    return report


def plant(results, kind, cases_doc):
    """Apply one regression shape to a copy of the results; returns (mutated results, case id touched)."""
    results = json.loads(json.dumps(results))
    cases = {case["id"]: case for case in cases_doc["cases"]}

    def first(predicate):
        for cid, result in results.items():
            if predicate(cid, result):
                return cid, result
        raise ValueError("no case suits the plant " + kind)

    if kind == "wrong-positive":
        cid, result = first(lambda c, r: cases[c]["kind"] == "stream" and r["final"]["status"] == "unknown")
        result["final"]["status"] = "identified"
        result["final"]["application_protocol"] = "http/1.1"
        if result["events"]:
            result["events"][-1]["observation"] = dict(result["final"])
    elif kind == "missing-retraction":
        cid, result = first(lambda c, r: cases[c]["kind"] == "session" and any(x["engine_status"] == "invalidated" for x in r["records"]))
        for record in result["records"]:
            if record["engine_status"] == "invalidated":
                record["engine_status"], record["app"] = "identified", "quic"
    elif kind == "wrong-port":
        cid, result = first(lambda c, r: cases[c]["kind"] == "session" and r["records"])
        result["records"][0]["server"][1] += 1
    elif kind == "dropped-event":
        cid, result = first(lambda c, r: cases[c]["kind"] == "stream" and len(r["events"]) >= 2)
        del result["events"][0]
    elif kind == "boundary-shift":
        cid, result = first(lambda c, r: cases[c]["kind"] == "stream" and r["metrics"]["bytes_inspected"] > 0)
        result["metrics"]["bytes_inspected"] -= 1
    else:
        raise ValueError("unknown plant " + kind)
    return results, cid


def run_backend(backend, cases_doc):
    if backend == "python":
        from migration.parity.cases import run_case
        return {"backend": "python", "results": {case["id"]: run_case(case) for case in cases_doc["cases"]}}
    raise ValueError("unknown backend " + backend + "; pass --results for another implementation's output")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cases", default=str(ROOT / "migration/fixtures/cases.json"))
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--backend", choices=("python",), help="run this backend in process")
    source.add_argument("--results", help="a results file produced by another backend")
    parser.add_argument("--deltas", default=str(HERE / "deltas.json"))
    parser.add_argument("--plant", choices=PLANTS, help="self-test: plant one regression and expect a mismatch")
    parser.add_argument("--report", help="write the JSON report here")
    args = parser.parse_args(argv)
    cases_doc = load(args.cases)
    results_doc = run_backend(args.backend, cases_doc) if args.backend else load(args.results)
    deltas = load(args.deltas) if Path(args.deltas).exists() else {}
    if args.plant:
        results_doc["results"], touched = plant(results_doc["results"], args.plant, cases_doc)
    report = compare(cases_doc, results_doc, deltas)
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    print("parity: compared %d, matched %d, mismatched %d, missing %d, extra %d, exempted %d" % (
        report["compared"], report["matched"], len(report["mismatched"]), len(report["missing"]), len(report["extra"]), report["exempted"]))
    for item in report["mismatched"][:10]:
        print("  mismatch %s: %s" % (item["id"], "; ".join("%s expected %r got %r" % (d["path"], d["expected"], d["actual"]) for d in item["differences"][:3])))
    if args.plant:
        detected = any(item["id"] == touched for item in report["mismatched"])
        print("planted %s in %s: %s" % (args.plant, touched, "DETECTED" if detected else "NOT DETECTED"))
        return 0 if detected else 1
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
