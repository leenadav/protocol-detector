"""v0.60: RDP security posture from the X.224 negotiation (offered and selected security, credential modes, failures)."""
import random
import unittest

from protocol_engine import Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.remote import CREDENTIAL_MODES, FAILURES, SECURITY_PROTOCOLS, SERVER_SUPPORTS
from protocol_engine.risks import RISKS
from protocol_fixtures import RDP, RDP_CONFIRM, rdp_confirm, rdp_request

FIELDS = ("rdp_offered_security", "rdp_credential_mode", "rdp_selected_security", "rdp_server_supports", "rdp_failure")
LABELS = {"rdp_offered_security": {"standard-rdp", "tls", "credssp", "rdstls", "credssp-early-user-auth", "aad"},
          "rdp_credential_mode": {"restricted-admin", "remote-credential-guard"},
          "rdp_selected_security": {"standard-rdp", "tls", "credssp", "rdstls", "credssp-early-user-auth", "aad"},
          "rdp_server_supports": {"extended-client-data", "gfx-pipeline", "restricted-admin", "remote-credential-guard"},
          "rdp_failure": {"ssl-required", "ssl-not-allowed", "ssl-certificate-missing", "inconsistent-flags",
                          "hybrid-required", "ssl-with-user-auth-required"}}


def posture(data):
    inspector = Inspector()
    inspector.feed(data)
    found = {}
    for e in inspector.observation.evidence:
        if e.field in FIELDS:
            found.setdefault(e.field, []).append(e.value)
    return inspector.observation, found


def risks(data):
    return classify(posture(data)[0], "tcp", 3389).risks


class RdpPostureTests(unittest.TestCase):
    def test_tables_follow_ms_rdpbcgr(self):
        # MS-RDPBCGR 2.2.1.1.1, 2.2.1.2.1 and 2.2.1.2.2, written independently of the module's tables.
        self.assertEqual(dict(SECURITY_PROTOCOLS), {1: "tls", 2: "credssp", 4: "rdstls", 8: "credssp-early-user-auth", 16: "aad"})
        self.assertEqual(dict(CREDENTIAL_MODES), {1: "restricted-admin", 2: "remote-credential-guard"})
        self.assertEqual(dict(SERVER_SUPPORTS), {1: "extended-client-data", 2: "gfx-pipeline", 8: "restricted-admin", 16: "remote-credential-guard"})
        self.assertEqual(sorted(FAILURES), [1, 2, 3, 4, 5, 6])

    def test_offered_security_and_credential_modes(self):
        self.assertEqual(posture(RDP)[1], {"rdp_offered_security": ["tls", "credssp"]})
        self.assertEqual(posture(rdp_request(protocols=0))[1], {"rdp_offered_security": ["standard-rdp"]})
        self.assertEqual(posture(rdp_request(protocols=0x1f))[1]["rdp_offered_security"],
                         ["tls", "credssp", "rdstls", "credssp-early-user-auth", "aad"])
        self.assertEqual(posture(rdp_request(protocols=0x0b, flags=1))[1]["rdp_credential_mode"], ["restricted-admin"])
        self.assertEqual(posture(rdp_request(protocols=0x0b, flags=2))[1]["rdp_credential_mode"], ["remote-credential-guard"])
        both = posture(rdp_request(protocols=0x0b, flags=3, cookie=b"Cookie: mstshash=placeholder\r\n", correlation=True))
        self.assertEqual((both[0].status, both[1]["rdp_credential_mode"]), ("identified", ["restricted-admin", "remote-credential-guard"]))
        self.assertNotIn("rdp_credential_mode", posture(rdp_request(correlation=True))[1])    # the correlation flag is framing
        for data in (rdp_request(protocols=0x20), rdp_request(flags=4)):                    # unknown offers and flags stay out
            self.assertNotEqual(posture(data)[0].status, "identified", data.hex())

    def test_selected_security_and_server_flags(self):
        for bit, label in [(0, "standard-rdp")] + list(SECURITY_PROTOCOLS):
            observation, found = posture(rdp_confirm(selected=bit))
            self.assertEqual((observation.status, found), ("identified", {"rdp_selected_security": [label]}), bit)
        self.assertEqual(posture(RDP_CONFIRM)[1], {"rdp_selected_security": ["tls"]})
        found = posture(rdp_confirm(selected=2, flags=0x1f))[1]
        self.assertEqual(found["rdp_server_supports"], ["extended-client-data", "gfx-pipeline", "restricted-admin", "remote-credential-guard"])
        self.assertNotIn("rdp_server_supports", posture(rdp_confirm(selected=2, flags=0x04))[1])   # NEGRSP_FLAG_RESERVED
        for data in (rdp_confirm(selected=3), rdp_confirm(selected=32), rdp_confirm(flags=0x20)):
            self.assertNotEqual(posture(data)[0].status, "identified", data.hex())

    def test_failure_codes(self):
        for code, label in FAILURES.items():
            observation, found = posture(rdp_confirm(selected=code, kind=3))
            self.assertEqual((observation.status, found), ("identified", {"rdp_failure": [label]}), code)
        for data in (rdp_confirm(selected=0, kind=3), rdp_confirm(selected=7, kind=3), rdp_confirm(selected=1, flags=1, kind=3)):
            self.assertNotEqual(posture(data)[0].status, "identified", data.hex())

    def test_nla_risk_follows_the_server_selection(self):
        self.assertIn("rdp-nla-not-negotiated", risks(rdp_confirm(selected=1)))
        self.assertIn("rdp-nla-not-negotiated", risks(rdp_confirm(selected=0)))
        self.assertIn("obsolete-protocol", risks(rdp_confirm(selected=0)))                     # unchanged
        for selected in (2, 4, 8, 16):
            self.assertNotIn("rdp-nla-not-negotiated", risks(rdp_confirm(selected=selected)), selected)
        for data in (rdp_request(protocols=1), rdp_request(protocols=0), rdp_confirm(selected=5, kind=3)):
            self.assertNotIn("rdp-nla-not-negotiated", risks(data), data.hex())              # an offer or a failure decides nothing
        verdict = session_verdict(posture(RDP)[0], posture(RDP_CONFIRM)[0], "tcp", 3389, 100, 100)
        self.assertEqual(verdict.risks, ("desktop-or-file-sharing-session", "rdp-nla-not-negotiated"))
        verdict = session_verdict(posture(RDP)[0], posture(rdp_confirm(selected=2, flags=1))[0], "tcp", 3389, 100, 100)
        self.assertEqual(verdict.risks, ("desktop-or-file-sharing-session",))
        self.assertIn("rdp-nla-not-negotiated", RISKS)

    def test_split_points_and_mutations(self):
        for data in (rdp_request(protocols=0x0b, flags=3, cookie=b"Cookie: mstshash=placeholder\r\n", correlation=True),
                     rdp_confirm(selected=8, flags=0x19), rdp_confirm(selected=6, kind=3)):
            reference = posture(data)[1]
            for split in range(1, len(data)):
                inspector = Inspector()
                inspector.feed(data[:split])
                inspector.feed(data[split:])
                found = {}
                for e in inspector.observation.evidence:
                    if e.field in FIELDS:
                        found.setdefault(e.field, []).append(e.value)
                self.assertEqual(found, reference, split)
        generator = random.Random(60)
        for base in (rdp_request(protocols=0x1f, flags=3), rdp_confirm(selected=2, flags=0x1f), rdp_confirm(selected=2, kind=3)):
            for _ in range(300):
                data = bytearray(base)
                data[generator.randrange(len(data))] = generator.randrange(256)
                observation, found = posture(bytes(data))
                for field, values in found.items():
                    self.assertLessEqual(set(values), LABELS[field], field)
                    self.assertEqual(observation.status, "identified")


if __name__ == "__main__":
    unittest.main()
