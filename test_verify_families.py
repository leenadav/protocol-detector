"""Migration M5 acceptance: a family's Go status is computed from the parity evidence, never stated by hand."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "migration" / "parity"))
import verify_families  # noqa: E402

CAPABILITIES = {"families": {"demo": {"transports": ["tcp"]}, "dgram": {"transports": ["udp"]}, "absent": {"transports": ["tcp"]}}}


def case(kind, family, variant):
    return {"id": "{}/0-{}/{}".format(kind, family, variant), "kind": kind, "label": family + "/x"}


def full_cases():
    cases = [case("stream", "demo", v) for v in ("whole", "half", "mutated", "zeros")] + [case("session", "demo", "plain")]
    cases += [case("datagram", "dgram", v) for v in ("positive", "truncated", "mutated-1", "text")]
    return {"cases": cases}


def report(cases, **override):
    matched = {}
    for c in cases["cases"]:
        key = c["kind"] + "/" + c["label"].split("/")[0]
        matched[key] = matched.get(key, 0) + 1
    out = {"ok": True, "families": ["demo", "dgram"], "matched_by_family": matched}
    out.update(override)
    return out


class VerifyFamiliesTests(unittest.TestCase):
    def statuses(self, cases, rep, gaps=None, deltas=None):
        computed = verify_families.evidence(cases, rep, gaps or {}, deltas or {}, CAPABILITIES)
        return {family: entry["status"] for family, entry in computed.items()}, computed

    def test_complete_evidence_verifies_and_an_unclaimed_family_is_pending(self):
        cases = full_cases()
        statuses, _ = self.statuses(cases, report(cases))
        self.assertEqual(statuses, {"demo": "parity-verified", "dgram": "parity-verified", "absent": "pending"})

    def test_each_missing_piece_of_evidence_keeps_the_family_experimental(self):
        cases = full_cases()
        rep = report(cases)
        rep["matched_by_family"]["stream/demo"] -= 1                       # one case did not match
        self.assertEqual(self.statuses(cases, rep)[0]["demo"], "experimental")
        self.assertEqual(self.statuses(cases, report(cases), gaps={cases["cases"][0]["id"]: "x"})[0]["demo"], "experimental")
        self.assertEqual(self.statuses(cases, report(cases), deltas={cases["cases"][1]["id"]: []})[0]["demo"], "experimental")
        self.assertEqual(self.statuses(cases, report(cases, ok=False))[0]["dgram"], "experimental")
        no_session = {"cases": [c for c in cases["cases"] if c["kind"] != "session"]}
        statuses, computed = self.statuses(no_session, report(no_session))
        self.assertEqual(statuses["demo"], "experimental")
        self.assertIn("no session-level case", computed["demo"]["shortfall"])
        no_mutation = {"cases": [c for c in cases["cases"] if not c["id"].endswith("/mutated-1")]}
        statuses, computed = self.statuses(no_mutation, report(no_mutation))
        self.assertEqual(statuses["dgram"], "experimental")
        self.assertIn("datagram cases lack mutated", computed["dgram"]["shortfall"])


if __name__ == "__main__":
    unittest.main()
