#!/usr/bin/env python3
"""Migration M5 acceptance: which protocol families the Go backend has proven, computed from the evidence.

A family is `parity-verified` when all of these hold, on the parity report the gate just produced
(`make parity-go`: migration/parity/go-report.json, the exact comparison of every committed case, session
records included):

  1. the report passed and claims the family, and every committed case labelled with the family matched
     exactly: as many matched cases of each kind as there are cases, and no listed gap or approved delta for
     any of them;
  2. for every transport the family serves (CAPABILITIES.json), the matched cases of that transport's kind
     (tcp: stream, udp: datagram) cover four classes: a positive message, a truncated prefix, a mutated
     message and foreign bytes;
  3. a TCP family also has at least one matched session-level case (bytes through the adapter's reassembly
     and the session record).

Otherwise it stays `experimental` (some cases match) or `pending` (none is claimed), and the shortfall is
named. The capture-level differentials (parity-analyze, parity-live, parity-decrypt, parity-live-decrypt,
schema-go) are gates of their own in `make go-check`; a family is never verified by them alone.

  --check FILE  fail when a Go status in FILE differs from the computed one (either way)
  --write FILE  set each family's Go status and evidence in FILE (other fields are kept)
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from compare import family_of  # noqa: E402

CLASSES = {
    "positive": {"whole", "whole-fin", "positive", "plain"},
    "truncated": {"half", "truncated"},
    "mutated": {"mutated", "mutated-1", "mutated-2"},
    "foreign": {"zeros", "sevens", "bytes", "text", "http-request", "tls-hello", "dns-query", "greeting", "positive-bytes"},
}
KIND_OF = {"tcp": "stream", "udp": "datagram"}


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def evidence(cases, report, gaps, deltas, capabilities):
    """{family: {"status", "cases", "classes", "shortfall"}} from the committed cases and the parity report."""
    per = defaultdict(lambda: {"cases": defaultdict(int), "classes": defaultdict(set), "touched": []})
    for case in cases["cases"]:
        family = family_of(case.get("label"))
        entry = per[family]
        entry["cases"][case["kind"]] += 1
        variant = case["id"].rsplit("/", 1)[-1]
        for name, variants in CLASSES.items():
            if variant in variants:
                entry["classes"][case["kind"]].add(name)
        if case["id"] in gaps or case["id"] in deltas:
            entry["touched"].append(case["id"])
    matched = report.get("matched_by_family", {})
    claimed = set(report.get("families", ()))
    out = {}
    for family, info in sorted(capabilities["families"].items()):
        entry = per.get(family)
        shortfall = []
        if not report.get("ok"):
            shortfall.append("the parity report did not pass")
        if family not in claimed:
            out[family] = {"status": "pending", "cases": {}, "classes": {}, "shortfall": ["not claimed by the Go backend"]}
            continue
        counts = dict(entry["cases"]) if entry else {}
        for kind, total in sorted(counts.items()):
            if matched.get(kind + "/" + family, 0) != total:
                shortfall.append("{} {} of {} cases matched".format(kind, matched.get(kind + "/" + family, 0), total))
        if entry and entry["touched"]:
            shortfall.append("{} cases carry a gap or an approved delta".format(len(entry["touched"])))
        for transport in info["transports"]:
            kind = KIND_OF[transport]
            lacking = sorted(set(CLASSES) - (entry["classes"][kind] if entry else set()))
            if lacking:
                shortfall.append("{} cases lack {}".format(kind, ", ".join(lacking)))
        if "tcp" in info["transports"] and not counts.get("session"):
            shortfall.append("no session-level case")
        out[family] = {"status": "experimental" if shortfall else "parity-verified", "cases": counts,
                       "classes": {kind: sorted(names) for kind, names in sorted((entry["classes"] if entry else {}).items())},
                       "shortfall": shortfall}
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cases", default=str(ROOT / "migration/fixtures/cases.json"))
    parser.add_argument("--report", default=str(ROOT / "migration/parity/go-report.json"))
    parser.add_argument("--gaps", default=str(ROOT / "migration/parity/gaps.json"))
    parser.add_argument("--deltas", default=str(ROOT / "migration/parity/deltas.json"))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", metavar="FILE")
    mode.add_argument("--write", metavar="FILE")
    args = parser.parse_args(argv)
    target = Path(args.check or args.write)
    capabilities = load(target)
    computed = evidence(load(args.cases), load(args.report), load(args.gaps).get("gaps", {}), load(args.deltas), capabilities)
    verified = sorted(f for f, e in computed.items() if e["status"] == "parity-verified")
    if args.write:
        for family, entry in computed.items():
            go = capabilities["families"][family].setdefault("go", {})
            go["status"] = entry["status"]
            go["evidence"] = {"cases": entry["cases"], "classes": entry["classes"], "shortfall": entry["shortfall"],
                              "rule": "migration/parity/verify_families.py over make parity-go"}
        target.write_text(json.dumps(capabilities, indent=2) + "\n", encoding="utf-8")
        print("families: {} parity-verified, {} not ({})".format(len(verified), len(computed) - len(verified),
              ", ".join(sorted(set(computed) - set(verified))) or "none"))
        return 0
    wrong = ["{}: stated {}, evidence says {}".format(f, capabilities["families"][f].get("go", {}).get("status"), e["status"])
             for f, e in computed.items() if capabilities["families"][f].get("go", {}).get("status") != e["status"]]
    for line in wrong[:20]:
        print("family status mismatch:", line)
    print("family statuses: {} parity-verified of {}, {} stated statuses differ from the evidence".format(
        len(verified), len(computed), len(wrong)))
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
