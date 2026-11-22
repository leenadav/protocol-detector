"""Migration M5 acceptance: a family's Go status is computed from the parity evidence, never stated by hand."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "migration" / "parity"))
import verify_families  # noqa: E402

CAPABILITIES = {"families": {"demo": {"transports": ["tcp"]}, "dgram": {"transports": ["udp"]}, "absent": {"transports": ["tcp"]}}}


POSITIVE = {"whole": b"DEMO-hello", "positive": b"DGRAM-hello", "plain": None}
BYTES = {"half": b"DEMO-", "truncated": b"DGRAM", "mutated": b"DEMO-hellp", "mutated-1": b"DGRAM-hellp", "zeros": bytes(8),
         "text": b"GET / HTTP/1.1\r\n\r\n", "bytes": b"DEMO-hello", "sevens": b"DEMO-hello"}


def observation(family, identified):
    return {"status": "identified" if identified else "unknown", "application_protocol": family + "/x" if identified else None}


def case(kind, family, variant, data=None, identified=None):
    data = POSITIVE.get(variant, BYTES.get(variant)) if data is None else data
    identified = variant in POSITIVE if identified is None else identified
    out = {"id": "{}/0-{}/{}".format(kind, family, variant), "kind": kind, "label": family + "/x"}
    if kind == "stream":
        out["chunks"] = [data[i:i + 1].hex() for i in range(len(data))] if variant == "bytes" else [data.hex()]
        out["expected"] = {"final": observation(family, identified)}
    elif kind == "datagram":
        out["payload"] = data.hex()
        out["expected"] = {"observation": observation(family, identified)}
    else:
        out["expected"] = {"packets": [{"events": [{"kind": "updated", "observation": observation(family, identified)}]}]}
    return out


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

    def test_a_replay_of_the_positive_bytes_is_not_foreign_evidence(self):
        """PRO-20: a bytewise or seven-byte re-chunking of the positive (and any case named foreign whose bytes
        equal a positive) used to count as foreign bytes."""
        for replay in ("bytes", "sevens"):
            cases = {"cases": [c for c in full_cases()["cases"] if not c["id"].endswith("/zeros")] + [case("stream", "demo", replay)]}
            statuses, computed = self.statuses(cases, report(cases))
            self.assertEqual(statuses["demo"], "experimental", replay)
            self.assertIn("stream cases lack foreign", computed["demo"]["shortfall"])
        cases = full_cases()
        cases["cases"] = [c for c in cases["cases"] if not c["id"].endswith("/text")]
        cases["cases"].append(case("datagram", "dgram", "text", data=b"DGRAM-hello"))
        statuses, computed = self.statuses(cases, report(cases))
        self.assertEqual(statuses["dgram"], "experimental")
        self.assertIn("datagram cases lack foreign", computed["dgram"]["shortfall"])
        claimed = full_cases()
        claimed["cases"] = [c for c in claimed["cases"] if not c["id"].endswith("/zeros")] + [case("stream", "demo", "zeros", identified=True)]
        self.assertEqual(self.statuses(claimed, report(claimed))[0]["demo"], "experimental")

    def test_a_positive_or_session_case_counts_only_when_it_identifies_the_family(self):
        """PRO-20: a session case was credited by its kind alone, and a positive by its variant name alone."""
        cases = full_cases()
        cases["cases"] = [c for c in cases["cases"] if c["kind"] != "session"] + [case("session", "demo", "plain", identified=False)]
        statuses, computed = self.statuses(cases, report(cases))
        self.assertEqual(statuses["demo"], "experimental")
        self.assertIn("no session-level case identifies the family", computed["demo"]["shortfall"])
        other = full_cases()
        other["cases"] = [c for c in other["cases"] if c["kind"] != "session"]
        foreign_session = case("session", "demo", "plain")
        foreign_session["expected"]["packets"][0]["events"][0]["observation"]["application_protocol"] = "other/x"
        other["cases"].append(foreign_session)
        self.assertEqual(self.statuses(other, report(other))[0]["demo"], "experimental")
        unknown = full_cases()
        unknown["cases"] = [c for c in unknown["cases"] if not c["id"].endswith("/positive")]
        unknown["cases"].append(case("datagram", "dgram", "positive", identified=False))
        statuses, computed = self.statuses(unknown, report(unknown))
        self.assertEqual(statuses["dgram"], "experimental")
        self.assertIn("datagram cases lack positive", computed["dgram"]["shortfall"])


if __name__ == "__main__":
    unittest.main()
