"""v0.59: SMB2/3 security posture from the NEGOTIATE response (signing requirement, encryption, cipher, signing algorithm)."""
import struct
import unittest

from protocol_engine import Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.network import _SMB_CIPHERS, _SMB_SIGNING_ALGORITHMS
from protocol_engine.risks import RISKS
from protocol_fixtures import SMB2, SMB3_PREAUTH_RESPONSE, SMB311, SMB2_RESPONSE, SMB311_RESPONSE, smb2_response, smb3_contexts

FIELDS = ("smb_dialect", "smb_signing", "smb_encryption", "smb_encryption_cipher", "smb_signing_algorithm")


def posture(data):
    inspector = Inspector()
    inspector.feed(data)
    observation = inspector.observation
    return observation, {e.field: e.value for e in observation.evidence if e.field in FIELDS}


def response311(cipher=None, signing=None, security_mode=3, extra=()):
    items = [SMB3_PREAUTH_RESPONSE]
    if cipher is not None:
        items.append((2, struct.pack("<HH", 1, cipher)))
    if signing is not None:
        items.append((8, struct.pack("<HH", 1, signing)))
    items.extend(extra)
    return smb2_response(dialect=0x311, security_mode=security_mode, contexts=smb3_contexts(*items), context_count=len(items))


class SmbPostureTests(unittest.TestCase):
    def test_tables_follow_ms_smb2(self):
        # MS-SMB2 2.2.3.1.2 and 2.2.3.1.7, written independently of the module's tables.
        self.assertEqual(dict(_SMB_CIPHERS), {0: "none", 1: "aes-128-ccm", 2: "aes-128-gcm", 3: "aes-256-ccm", 4: "aes-256-gcm"})
        self.assertEqual(dict(_SMB_SIGNING_ALGORITHMS), {0: "hmac-sha256", 1: "aes-cmac", 2: "aes-gmac"})

    def test_encryption_by_dialect_and_capability(self):
        cases = [(smb2_response(dialect=0x202, token=b""), "2.0.2", "unavailable"), (smb2_response(dialect=0x210, token=b""), "2.1", "unavailable"),
                 (smb2_response(dialect=0x300), "3.0", "supported"), (smb2_response(dialect=0x302), "3.0.2", "supported"),
                 (smb2_response(dialect=0x300, capabilities=0x3f), "3.0", "not-supported"),
                 (smb2_response(dialect=0x302, capabilities=0x40), "3.0.2", "supported")]
        for data, dialect, encryption in cases:
            observation, found = posture(data)
            self.assertEqual((observation.status, found["smb_dialect"], found["smb_encryption"]), ("identified", dialect, encryption), dialect)
        wildcard = posture(smb2_response(dialect=0x2ff, token=b""))[1]
        self.assertNotIn("smb_encryption", wildcard)                      # a multi-protocol answer selects nothing yet
        self.assertEqual(posture(SMB2_RESPONSE)[1]["smb_encryption"], "supported")

    def test_311_cipher_and_signing_contexts(self):
        for cipher, label in _SMB_CIPHERS.items():
            found = posture(response311(cipher=cipher))[1]
            self.assertEqual((found["smb_encryption_cipher"], found["smb_encryption"]), (label, "not-supported" if cipher == 0 else "supported"))
        self.assertEqual(posture(response311(cipher=9))[1]["smb_encryption_cipher"], "other")
        for algorithm, label in _SMB_SIGNING_ALGORITHMS.items():
            self.assertEqual(posture(response311(signing=algorithm))[1]["smb_signing_algorithm"], label)
        self.assertEqual(posture(response311(signing=7))[1]["smb_signing_algorithm"], "other")
        bare = posture(response311())[1]
        self.assertEqual((bare["smb_encryption"], "smb_encryption_cipher" in bare, "smb_signing_algorithm" in bare), ("not-supported", False, False))
        self.assertEqual(posture(SMB311_RESPONSE)[1]["smb_encryption_cipher"], "aes-128-gcm")
        rejected = [response311(extra=((8, struct.pack("<HHH", 2, 0, 1)),)),                # a response selects one algorithm
                    response311(extra=((8, struct.pack("<H", 0)),)),                         # empty algorithm list
                    response311(extra=((8, struct.pack("<HHH", 1, 0, 0)),)),                 # length disagrees with the count
                    response311(signing=1, extra=((8, struct.pack("<HH", 1, 2)),)),          # duplicate signing context
                    response311(extra=((2, struct.pack("<HHH", 2, 1, 2)),))]                 # a response selects one cipher
        for data in rejected:
            self.assertNotEqual(posture(data)[0].status, "identified", data[-16:].hex())
        # Requests may offer several algorithms; the request carries no posture rows beyond its signing mode.
        observation, found = posture(SMB311)
        self.assertEqual((observation.status, set(found)), ("identified", {"smb_signing"}))

    def test_risks(self):
        def risks(data):
            return classify(posture(data)[0], "tcp", 445).risks
        self.assertIn("smb-signing-not-required", risks(SMB2_RESPONSE))                    # server enables, does not require
        self.assertNotIn("smb-signing-not-required", risks(SMB311_RESPONSE))
        self.assertNotIn("smb-signing-not-required", risks(SMB2))                          # a client's "enabled" is not the server's policy
        self.assertIn("smb-encryption-unavailable", risks(smb2_response(dialect=0x210, security_mode=3, token=b"")))
        self.assertIn("smb-encryption-unavailable", risks(smb2_response(dialect=0x302, security_mode=3, capabilities=0)))
        self.assertIn("smb-encryption-unavailable", risks(response311(cipher=0)))
        self.assertNotIn("smb-encryption-unavailable", risks(response311(cipher=4, signing=2)))
        self.assertNotIn("smb-encryption-unavailable", risks(smb2_response(dialect=0x2ff, security_mode=3, token=b"")))
        verdict = session_verdict(posture(SMB2)[0], posture(SMB2_RESPONSE)[0], "tcp", 445, 100, 100)
        self.assertEqual(verdict.risks, ("desktop-or-file-sharing-session", "smb-signing-not-required"))
        for name in ("smb-signing-not-required", "smb-encryption-unavailable"):
            self.assertIn(name, RISKS)

    def test_split_points(self):
        data = response311(cipher=4, signing=2)
        reference = posture(data)[1]
        for split in range(1, len(data), 9):
            inspector = Inspector()
            inspector.feed(data[:split])
            inspector.feed(data[split:])
            self.assertEqual({e.field: e.value for e in inspector.observation.evidence if e.field in FIELDS}, reference, split)


if __name__ == "__main__":
    unittest.main()
