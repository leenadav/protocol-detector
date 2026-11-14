"""Migration M1/M4: compare a backend's results against the language-neutral cases.

    python3 -B migration/parity/compare.py --cases migration/fixtures/cases.json --backend python
    python3 -B migration/parity/compare.py --cases ... --results go-results.json --families http,tls,dns \\
            --ignore '$.records'                                                  (a Go run's output)
    python3 -B migration/parity/compare.py --cases ... --backend python --plant wrong-positive  (self-test)

A results file has the same shape as the cases' `expected` entries keyed by case id:
{"backend": "...", "results": {"<case id>": {...}}}. Comparison is exact on everything the plan says must not
be normalized away: statuses, protocols, applications, hostnames, reason sentences, evidence (field, value,
source, strength) in order, event kinds and ordering, revisions, metrics, session records (minus the
content digest) and per-packet messages. Approved semantic deltas (migration/parity/deltas.json) may exempt
one named path of one named case, each with a justification; nothing else is tolerated.

A backend may answer a case with {"unsupported": "<reason>"} instead of a result. Such a case is counted
as unsupported, never as matched, and it is accepted only when migration/parity/gaps.json lists that case id
with exactly that reason (review R2, 2026-11-14: a reason that merely contained "family " or "option " used
to be exempt, so a backend that stopped answering everything still passed). The allowlist is versioned and
exact in both directions: an unsupported answer that is not listed, or listed with another reason, fails
(`unexpected_gaps`); a listed case that the backend now answers, or that no longer exists, fails too
(`stale_gaps`), so the list can only change in a reviewed diff (`--write-gaps` regenerates it from a results
file). With --families, every named family must also have at least one matched case (`claimed_without_match`).
Result ids that are not cases fail (`extra`). --ignore removes named top-level paths and is reported, so a
partial comparison is never silent.

`--plant` mutates the backend's results in one of six ways a regression could take and must be reported:
wrong-positive (an unknown becomes identified), missing-retraction (an invalidation becomes identified),
wrong-port (a session's server port changes), dropped-event (one intermediate event disappears),
boundary-shift (bytes_inspected / a shift boundary moves), supported-to-unsupported (an answered case
becomes an unsupported answer with a plausible reason).
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

PLANTS = ("wrong-positive", "missing-retraction", "wrong-port", "dropped-event", "boundary-shift", "supported-to-unsupported")
GAPS_SCHEMA = 1


def load_gaps(path):
    """The allowlist {case id: exact unsupported reason} of one backend; a missing file is an empty list."""
    path = Path(path)
    if not path.exists():
        return {}
    document = load(path)
    if document.get("schema") != GAPS_SCHEMA or not isinstance(document.get("gaps"), dict):
        raise ValueError("%s: expected {\"schema\": %d, \"gaps\": {case id: reason}}" % (path, GAPS_SCHEMA))
    return document["gaps"]


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def family_of(label):
    return (label or "").split("/", 1)[0]


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


def canonicalize_result(value):
    """Apply the expectation canonicalization (cases.py record_dict) to a backend result: content.digest is
    an implementation detail until M6 fixes its definition for both languages, so records keep content.version."""
    if isinstance(value, dict) and isinstance(value.get("records"), list):
        records = []
        for record in value["records"]:
            if isinstance(record, dict) and isinstance(record.get("content"), dict):
                record = dict(record, content={"version": record["content"].get("version")})
            records.append(record)
        value = dict(value, records=records)
    return value


def strip_ignored(value, ignored):
    """Remove ignored top-level paths ($.name) from an expectation or a result."""
    if not ignored or not isinstance(value, dict):
        return value
    names = {path[2:] for path in ignored if path.startswith("$.")}
    return {k: v for k, v in value.items() if k not in names}


def compare(cases_doc, results_doc, deltas=None, families=(), ignored=(), gaps=None):
    """Exact comparison. `gaps` is the allowlist of unsupported answers ({case id: reason}); None means none is allowed."""
    deltas = deltas or {}
    gaps = gaps or {}
    families = tuple(families)
    report = {"compared": 0, "matched": 0, "mismatched": [], "missing": [], "extra": [], "exempted": 0,
              "unsupported": 0, "unexpected_gaps": [], "stale_gaps": [], "claimed_without_match": [],
              "families": list(families), "ignored": list(ignored), "matched_by_family": {}}
    results = results_doc.get("results", {})
    matched_families = set()
    for case in cases_doc["cases"]:
        cid = case["id"]
        if cid not in results:
            report["missing"].append(cid)
            continue
        result = results[cid]
        if isinstance(result, dict) and set(result) == {"unsupported"}:
            report["unsupported"] += 1
            reason = str(result["unsupported"])
            if gaps.get(cid) != reason:
                report["unexpected_gaps"].append({"id": cid, "reason": reason, "listed": gaps.get(cid)})
            continue
        if cid in gaps:
            report["stale_gaps"].append({"id": cid, "listed": gaps[cid], "why": "the backend answers this case"})
        report["compared"] += 1
        differences = diff(strip_ignored(case["expected"], ignored), strip_ignored(canonicalize_result(result), ignored))
        allowed = {item["path"] for item in deltas.get(cid, [])}
        kept = [d for d in differences if d[0] not in allowed]
        report["exempted"] += len(differences) - len(kept)
        if kept:
            report["mismatched"].append({"id": cid, "kind": case["kind"], "label": case.get("label"),
                                         "differences": [{"path": p, "expected": e, "actual": a} for p, e, a in kept[:20]]})
        else:
            report["matched"] += 1
            matched_families.add(family_of(case.get("label")))
            key = case["kind"] + "/" + family_of(case.get("label"))
            report["matched_by_family"][key] = report["matched_by_family"].get(key, 0) + 1
    known = {case["id"] for case in cases_doc["cases"]}
    report["extra"] = sorted(set(results) - known)
    report["stale_gaps"].extend({"id": cid, "listed": gaps[cid], "why": "no such case"} for cid in sorted(set(gaps) - known))
    report["claimed_without_match"] = sorted(set(families) - matched_families)
    report["ok"] = not (report["mismatched"] or report["missing"] or report["extra"] or report["unexpected_gaps"]
                        or report["stale_gaps"] or report["claimed_without_match"])
    return report


def plant(results, kind, cases_doc):
    """Apply one regression shape to a copy of the results; returns (mutated results, case id touched)."""
    results = json.loads(json.dumps(results))
    cases = {case["id"]: case for case in cases_doc["cases"]}

    def first(predicate):
        for cid, result in results.items():
            if isinstance(result, dict) and set(result) == {"unsupported"}:
                continue
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
        cid, result = first(lambda c, r: cases[c]["kind"] == "session" and any(x["engine_status"] == "invalidated" for x in r.get("records", ())))
        for record in result["records"]:
            if record["engine_status"] == "invalidated":
                record["engine_status"], record["app"] = "identified", "quic"
    elif kind == "wrong-port":
        cid, result = first(lambda c, r: cases[c]["kind"] == "session" and r.get("records"))
        result["records"][0]["server"][1] += 1
    elif kind == "dropped-event":
        cid, result = first(lambda c, r: cases[c]["kind"] == "stream" and len(r["events"]) >= 2)
        del result["events"][0]
    elif kind == "boundary-shift":
        cid, result = first(lambda c, r: cases[c]["kind"] == "stream" and r["metrics"]["bytes_inspected"] > 0)
        result["metrics"]["bytes_inspected"] -= 1
    elif kind == "supported-to-unsupported":
        cid, result = first(lambda c, r: True)
        results[cid] = {"unsupported": "not ported in the Go backend: family " + family_of(cases[cid].get("label"))}
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
    parser.add_argument("--families", default="", help="comma-separated families the backend claims; each needs at least one matched case")
    parser.add_argument("--gaps", default=str(HERE / "gaps.json"), help="the exact allowlist of unsupported answers for --results")
    parser.add_argument("--write-gaps", action="store_true", help="rewrite --gaps from the unsupported answers of --results, then compare")
    parser.add_argument("--ignore", action="append", default=[], help="top-level path to leave out, e.g. $.records (reported)")
    parser.add_argument("--plant", choices=PLANTS, help="self-test: plant one regression and expect a mismatch")
    parser.add_argument("--report", help="write the JSON report here")
    args = parser.parse_args(argv)
    cases_doc = load(args.cases)
    results_doc = run_backend(args.backend, cases_doc) if args.backend else load(args.results)
    deltas = load(args.deltas) if Path(args.deltas).exists() else {}
    families = tuple(f for f in args.families.split(",") if f)
    if args.plant:
        results_doc["results"], touched = plant(results_doc["results"], args.plant, cases_doc)
    if args.write_gaps:
        if not args.results or args.plant:
            parser.error("--write-gaps needs --results and no --plant")
        listed = {cid: str(result["unsupported"]) for cid, result in sorted(results_doc.get("results", {}).items())
                  if isinstance(result, dict) and set(result) == {"unsupported"}}
        Path(args.gaps).write_text(json.dumps({"schema": GAPS_SCHEMA, "backend": results_doc.get("backend"), "gaps": listed},
                                              indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print("gaps written: %d -> %s" % (len(listed), args.gaps))
    gaps = load_gaps(args.gaps) if args.results else {}
    report = compare(cases_doc, results_doc, deltas, families, tuple(args.ignore), gaps)
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    print("parity: compared %d, matched %d, mismatched %d, missing %d, extra %d, exempted %d, unsupported %d%s%s" % (
        report["compared"], report["matched"], len(report["mismatched"]), len(report["missing"]), len(report["extra"]), report["exempted"],
        report["unsupported"], " (unlisted gaps: %d, stale gap entries: %d, claimed families without a match: %d)" % (
            len(report["unexpected_gaps"]), len(report["stale_gaps"]), len(report["claimed_without_match"])),
        (" ignoring " + ",".join(report["ignored"])) if report["ignored"] else ""))
    if report["matched_by_family"] and (families or args.results):
        print("  matched by kind/family: " + ", ".join("%s %d" % item for item in sorted(report["matched_by_family"].items())))
    for item in report["mismatched"][:10]:
        print("  mismatch %s: %s" % (item["id"], "; ".join("%s expected %r got %r" % (d["path"], d["expected"], d["actual"]) for d in item["differences"][:3])))
    for item in report["unexpected_gaps"][:10]:
        print("  unsupported answer not in the gap list %s: %r (listed: %r)" % (item["id"], item["reason"], item["listed"]))
    for item in report["stale_gaps"][:10]:
        print("  stale gap entry %s: %s" % (item["id"], item["why"]))
    for name in report["extra"][:10]:
        print("  result for an unknown case id: %s" % name)
    if report["claimed_without_match"]:
        print("  claimed families without a matched case: " + ", ".join(report["claimed_without_match"]))
    if args.plant:
        detected = any(item["id"] == touched for item in report["mismatched"] + report["unexpected_gaps"])
        print("planted %s in %s: %s" % (args.plant, touched, "DETECTED" if detected else "NOT DETECTED"))
        return 0 if detected else 1
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
