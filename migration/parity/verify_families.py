#!/usr/bin/env python3
"""Migration M5 acceptance: which protocol families the Go backend has proven, computed from the evidence.

A family is `parity-verified` when all of these hold, on the parity report the gate just produced
(`make parity-go`: migration/parity/go-report.json, the exact comparison of every committed case, session
records included):

  1. the report passed and claims the family, and every committed case labelled with the family matched
     exactly: as many matched cases of each kind as there are cases, and no listed gap or approved delta for
     any of them. A case whose deltas all pin Go's value (`go`, an approved Go-only divergence such as PRO-260)
     still had to match that value exactly; it is counted as an approved divergence, not a shortfall, but it
     earns no class or session credit below, so the family's other cases must prove every class on their own;
  2. for every transport the family serves (CAPABILITIES.json), the matched cases of that transport's kind
     (tcp: stream, udp: datagram) cover four classes: a positive message, a truncated prefix, a mutated
     message and foreign bytes. A foreign-bytes case counts only when its payload differs from every
     positive message of the family: a bytewise or 7-byte replay of the positive message ("bytes", "sevens",
     "positive-bytes") is fragmentation evidence, never foreign input (Codex PRO-20);
  3. a TCP family also has at least one matched session-level case whose reference record identifies the
     family: a TCP record the reference marked `identified`, with client bytes through the adapter's
     reassembly, whose client protocol is one the family's positive stream messages identify as (the
     application protocol, or the encryption when there is none, as for TLS). A session case is never
     credited by its kind alone (Codex PRO-20).

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
    "foreign": {"zeros", "text", "http-request", "tls-hello", "dns-query", "greeting"},
}
KIND_OF = {"tcp": "stream", "udp": "datagram"}


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def payload(case):
    """The bytes a stream or datagram case feeds (None for a session case)."""
    if case["kind"] == "stream":
        return b"".join(bytes.fromhex(chunk) for chunk in case.get("chunks") or ())
    if case["kind"] == "datagram":
        return bytes.fromhex(case.get("payload") or "")
    return None


def identity(observation):
    """What an identified observation names: its application protocol, else its encryption (TLS)."""
    if not isinstance(observation, dict) or observation.get("status") != "identified":
        return None
    return observation.get("application_protocol") or observation.get("encryption")


def identifies(session, protocols):
    """A session case whose reference record identifies one of the family's protocols from reassembled bytes."""
    records = (session.get("expected") or {}).get("records") or ()
    return any(isinstance(record, dict) and record.get("transport") == "tcp" and record.get("engine_status") == "identified"
               and (record.get("client_bytes") or 0) > 0 and record.get("client_protocol") in protocols for record in records)


def variant_of(case):
    return case["id"].rsplit("/", 1)[-1]


def evidence(cases, report, gaps, deltas, capabilities):
    """{family: {"status", "cases", "classes", "shortfall"}} from the committed cases and the parity report."""
    per = defaultdict(lambda: {"cases": defaultdict(int), "classes": defaultdict(set), "touched": [], "sessions": 0, "divergences": 0})
    positives, protocols = defaultdict(set), defaultdict(set)
    for case in cases["cases"]:
        if case["kind"] != "session" and variant_of(case) in CLASSES["positive"]:
            family = family_of(case.get("label"))
            positives[family].add(payload(case))
            expected = case.get("expected") or {}
            name = identity(expected.get("final") or expected.get("observation"))
            if name:
                protocols[family].add(name)
    pinned = {cid for cid, items in deltas.items() if items and all("go" in item for item in items)}
    for case in cases["cases"]:
        family = family_of(case.get("label"))
        entry = per[family]
        entry["cases"][case["kind"]] += 1
        if case["id"] in pinned and case["id"] not in gaps:
            entry["divergences"] += 1
            continue
        variant = variant_of(case)
        for name, variants in CLASSES.items():
            if variant in variants and not (name == "foreign" and payload(case) in positives[family]):
                entry["classes"][case["kind"]].add(name)
        if case["kind"] == "session" and identifies(case, protocols[family]):
            entry["sessions"] += 1
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
        if "tcp" in info["transports"] and not (entry and entry["sessions"]):
            shortfall.append("no session-level case identifying the family")
        out[family] = {"status": "experimental" if shortfall else "parity-verified", "cases": counts,
                       "classes": {kind: sorted(names) for kind, names in sorted((entry["classes"] if entry else {}).items())},
                       "shortfall": shortfall}
        if entry and entry["divergences"]:
            out[family]["approved_divergences"] = entry["divergences"]
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
            if entry.get("approved_divergences"):
                go["evidence"]["approved_divergences"] = entry["approved_divergences"]
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
