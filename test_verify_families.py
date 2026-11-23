"""Migration M5 acceptance: a family's Go status is computed from the parity evidence, never stated by hand."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "migration" / "parity"))
import verify_families  # noqa: E402

CAPABILITIES = {"families": {"demo": {"transports": ["tcp"]}, "dgram": {"transports": ["udp"]}, "absent": {"transports": ["tcp"]}}}
MESSAGE = {"demo": b"DEMO hello\r\n", "dgram": b"\x01\x02dgram"}
FOREIGN = b"\x00" * 64


def observation(family, identified=True):
    return {"status": "identified" if identified else "unknown", "application_protocol": family if identified else None, "encryption": None}


def payload_for(family, variant):
    message = MESSAGE[family]
    if variant in ("zeros", "text"):
        return FOREIGN
    if variant in ("half", "truncated"):
        return message[:len(message) // 2]
    if variant.startswith("mutated"):
        return message[:-1] + b"!"
    return message


def case(kind, family, variant, data=None):
    out = {"id": "{}/0-{}/{}".format(kind, family, variant), "kind": kind, "label": family + "/x"}
    data = payload_for(family, variant) if data is None else data
    positive = variant in ("whole", "positive", "bytes", "sevens")
    if kind == "stream":
        out["chunks"] = [data.hex()]
        out["expected"] = {"final": observation(family, positive)}
    elif kind == "datagram":
        out["payload"] = data.hex()
        out["expected"] = {"observation": observation(family, positive)}
    return out


def session(family, variant="plain", protocol=None, status="identified"):
    out = {"id": "session/0-{}/{}".format(family, variant), "kind": "session", "label": family + "/x"}
    out["expected"] = {"records": [{"transport": "tcp", "engine_status": status, "client_protocol": protocol or family, "client_bytes": 12}]}
    return out


def full_cases():
    cases = [case("stream", "demo", v) for v in ("whole", "half", "mutated", "zeros")] + [session("demo")]
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
        self.assertIn("no session-level case identifying the family", computed["demo"]["shortfall"])
        no_mutation = {"cases": [c for c in cases["cases"] if not c["id"].endswith("/mutated-1")]}
        statuses, computed = self.statuses(no_mutation, report(no_mutation))
        self.assertEqual(statuses["dgram"], "experimental")
        self.assertIn("datagram cases lack mutated", computed["dgram"]["shortfall"])

    def test_a_pinned_go_only_divergence_is_counted_but_earns_no_credit(self):
        """PRO-260: a case whose deltas all pin Go's value keeps the family verified when the other cases prove
        every class; the case itself proves nothing, and an unpinned delta still disqualifies."""
        cases = full_cases()
        extra = case("stream", "demo", "whole")
        extra["id"] = "stream/1-demo/whole"
        cases["cases"].append(extra)
        pinned = {extra["id"]: [{"path": "$.final", "justification": "x", "go": {}}]}
        statuses, computed = self.statuses(cases, report(cases), deltas=pinned)
        self.assertEqual(statuses["demo"], "parity-verified")
        self.assertEqual(computed["demo"]["approved_divergences"], 1)
        mixed = {extra["id"]: pinned[extra["id"]] + [{"path": "$.metrics", "justification": "x"}]}
        self.assertEqual(self.statuses(cases, report(cases), deltas=mixed)[0]["demo"], "experimental")
        # The only foreign-bytes case pinned: the class is no longer proven.
        foreign = next(c["id"] for c in cases["cases"] if c["id"].endswith("demo/zeros"))
        statuses, computed = self.statuses(cases, report(cases), deltas={foreign: pinned[extra["id"]]})
        self.assertEqual(statuses["demo"], "experimental")
        self.assertIn("stream cases lack foreign", computed["demo"]["shortfall"])

    def test_a_replay_of_the_positive_message_is_not_foreign_bytes(self):
        """Codex PRO-20 P2: a bytewise or 7-byte replay of the positive message, or a case named after foreign
        bytes whose payload is the family's own positive message, is not evidence of foreign input."""
        base = [c for c in full_cases()["cases"] if not c["id"].endswith(("/zeros", "/text"))]
        for name, extra in (("bytes", case("stream", "demo", "bytes")), ("sevens", case("stream", "demo", "sevens")),
                            ("positive-bytes", case("stream", "demo", "positive-bytes", MESSAGE["demo"])),
                            ("named foreign", case("stream", "demo", "greeting", MESSAGE["demo"])),
                            ("datagram", case("datagram", "dgram", "dns-query", MESSAGE["dgram"]))):
            cases = {"cases": base + [extra]}
            family = "dgram" if extra["kind"] == "datagram" else "demo"
            statuses, computed = self.statuses(cases, report(cases))
            self.assertEqual(statuses[family], "experimental", name)
            self.assertIn("{} cases lack foreign".format(extra["kind"]), computed[family]["shortfall"], name)
        genuine = {"cases": base + [case("stream", "demo", "greeting", b"220 mail.example ESMTP ready\r\n"),
                                    case("datagram", "dgram", "dns-query", b"\x12\x34\x01\x00")]}
        self.assertEqual(self.statuses(genuine, report(genuine))[0], {"demo": "parity-verified", "dgram": "parity-verified", "absent": "pending"})

    def test_a_session_case_counts_only_when_its_record_identifies_the_family(self):
        """Codex PRO-20 P2: a session-level case is credited by its content (a TCP record the reference
        identified as the family's protocol, with client bytes through reassembly), not by its kind alone."""
        base = [c for c in full_cases()["cases"] if c["kind"] != "session"]
        no_bytes = session("demo")
        no_bytes["expected"]["records"][0]["client_bytes"] = 0
        for name, extra in (("other protocol", session("demo", protocol="http/1.1")),
                            ("not identified", session("demo", status="invalidated", protocol="demo")),
                            ("no record", dict(session("demo"), expected={"records": []})),
                            ("no client bytes", no_bytes)):
            cases = {"cases": base + [extra]}
            statuses, computed = self.statuses(cases, report(cases))
            self.assertEqual(statuses["demo"], "experimental", name)
            self.assertIn("no session-level case identifying the family", computed["demo"]["shortfall"], name)
        tls_only = {"families": {"demo": {"transports": ["tcp"]}}}
        whole = case("stream", "demo", "whole")
        whole["expected"] = {"final": dict(observation("demo"), application_protocol=None, encryption="tls")}
        cases = {"cases": [whole] + [case("stream", "demo", v) for v in ("half", "mutated", "zeros")] + [session("demo", protocol="tls")]}
        rep = report(cases, families=["demo"])
        computed = verify_families.evidence(cases, rep, {}, {}, tls_only)
        self.assertEqual(computed["demo"]["status"], "parity-verified", computed["demo"]["shortfall"])


if __name__ == "__main__":
    unittest.main()
