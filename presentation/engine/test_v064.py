"""v0.64: RFC 9325 weak cipher-suite classes in TLS ClientHello offers, derived from the IANA registry."""
import csv
import io
import sys
import unittest
from pathlib import Path

from protocol_engine import Inspector
from protocol_engine.appid import classify
from protocol_engine.risks import RISKS
from protocol_engine.tls_ciphers import CLASS_ORDER, PROHIBITED, WEAK_SUITES, offered_weak_classes
from protocol_fixtures import SNI_PUBLIC, client_hello_with

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
from tls_cipher_classes import classes  # noqa: E402

TLS_RISKS = ("tls-prohibited-cipher-offered", "tls-64-bit-block-cipher-offered")


def offer(ciphers):
    inspector = Inspector()
    inspector.feed(client_hello_with(((0, SNI_PUBLIC), (43, b"\x02\x03\x04")), ciphers=ciphers))
    observation = inspector.observation
    return observation, [e.value for e in observation.evidence if e.field == "tls_weak_cipher_offered"]


def risks(ciphers):
    return tuple(name for name in classify(offer(ciphers)[0], "tcp", 443).risks if name in TLS_RISKS)


class WeakCipherTests(unittest.TestCase):
    def test_derivation_rules_and_embedded_table(self):
        sample = ('Value,Description,DTLS-OK,Recommended,Reference,Comment\n'
                  '"0x00,0x00",TLS_NULL_WITH_NULL_NULL,Y,N,,\n"0x00,0x03",TLS_RSA_EXPORT_WITH_RC4_40_MD5,N,D,,\n'
                  '"0x00,0x18",TLS_DH_anon_WITH_RC4_128_MD5,N,D,,\n"0x00,0x04",TLS_RSA_WITH_RC4_128_MD5,N,D,,\n'
                  '"0x00,0x09",TLS_RSA_WITH_DES_CBC_SHA,Y,D,,\n"0x00,0x0A",TLS_RSA_WITH_3DES_EDE_CBC_SHA,Y,D,,\n'
                  '"0x00,0x07",TLS_RSA_WITH_IDEA_CBC_SHA,Y,D,,\n"0xC0,0xB4",TLS_SHA256_SHA256,Y,D,,\n'
                  '"0x00,0x2F",TLS_RSA_WITH_AES_128_CBC_SHA,Y,N,,\n"0x00,0xFF",TLS_EMPTY_RENEGOTIATION_INFO_SCSV,Y,N,,\n'
                  '"0x56,0x00",TLS_FALLBACK_SCSV,Y,N,,\n"0x00,0x1C-1D",Reserved to avoid conflicts with SSLv3,,,,\n')
        derived = classes(csv.DictReader(io.StringIO(sample)))
        expected = {0x0000: "null", 0x0003: "export", 0x0018: "anon", 0x0004: "rc4", 0x0009: "des", 0x000a: "64-bit-block",
                    0x0007: "64-bit-block", 0xc0b4: "null"}
        self.assertEqual(derived, expected)              # the first matching rule wins: export before rc4, anon before rc4
        for code, label in expected.items():
            self.assertEqual(WEAK_SUITES[code], label, hex(code))
        self.assertEqual(len(WEAK_SUITES), 102)
        for code in (0x002f, 0x0035, 0xc02f, 0xc030, 0x1301, 0x1302, 0x1303, 0x00ff, 0x5600, 0x0a0a, 0xfafa):
            self.assertNotIn(code, WEAK_SUITES, hex(code))
        self.assertEqual(set(WEAK_SUITES.values()), set(CLASS_ORDER))
        self.assertEqual(PROHIBITED, set(CLASS_ORDER) - {"64-bit-block"})

    def test_offer_rows_and_risks(self):
        observation, rows = offer((0x1301, 0x1302, 0xc02f))
        self.assertEqual((observation.status, rows, risks((0x1301, 0x1302, 0xc02f))), ("identified", [], ()))
        self.assertEqual(offer((0xc02f, 0x000a))[1], ["64-bit-block"])
        self.assertEqual(risks((0xc02f, 0x000a)), ("tls-64-bit-block-cipher-offered",))
        mixed = (0x0a0a, 0xc02f, 0x0004, 0x000a, 0x0003, 0x0000, 0x0018, 0x0009, 0x0004)
        self.assertEqual(offer(mixed)[1], ["null", "export", "anon", "rc4", "des", "64-bit-block"])   # fixed order, no duplicates
        self.assertEqual(risks(mixed), tuple(sorted(TLS_RISKS)))
        self.assertEqual(risks((0x1301, 0x0018)), ("tls-prohibited-cipher-offered",))
        for name in TLS_RISKS:
            self.assertIn(name, RISKS)
        self.assertNotIn("0x0004", repr(offer(mixed)[0]))      # suite numbers are not emitted

    def test_classifier_bounds(self):
        self.assertEqual(offered_weak_classes(b"\x13\x01"), ())
        self.assertEqual(offered_weak_classes(bytes(2)), ("null",))
        many = b"".join(code.to_bytes(2, "big") for code in range(0xc000, 0xc000 + 4000))
        self.assertEqual(offered_weak_classes(many), ("null", "anon", "rc4", "64-bit-block"))

    def test_split_points(self):
        data = client_hello_with(((0, SNI_PUBLIC),), ciphers=(0xc02f, 0x0004, 0x000a))
        reference = offer((0xc02f, 0x0004, 0x000a))[1]
        for split in range(1, len(data), 5):
            inspector = Inspector()
            inspector.feed(data[:split])
            inspector.feed(data[split:])
            self.assertEqual([e.value for e in inspector.observation.evidence if e.field == "tls_weak_cipher_offered"], reference, split)


if __name__ == "__main__":
    unittest.main()
