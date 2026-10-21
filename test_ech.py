"""v0.42: encrypted_client_hello awareness in TLS and QUIC ClientHellos."""
import random
import unittest

from protocol_engine import Config, DatagramInspector, Inspector
from protocol_engine.appid import classify
from protocol_engine.parsers import ParseError, ech_type
from protocol_engine.risks import RISKS
from protocol_fixtures import SNI_PUBLIC, TLS_ECH_HELLO, client_hello_with, ech_outer
from proxy_demo import client_hello

FP = Config(fingerprints=True)


def inspect(data, config=None):
    inspector = Inspector(config)
    inspector.feed(data)
    return inspector.observation


def fields(observation, *names):
    return {e.field: e.value for e in observation.evidence if e.field in names}


class ECHTests(unittest.TestCase):
    def test_outer_ech_is_reported_and_the_public_name_kept(self):
        observation = inspect(TLS_ECH_HELLO, FP)
        self.assertEqual((observation.status, observation.encryption, observation.hostname), ("identified", "tls", "public.example.net"))
        self.assertEqual(fields(observation, "tls_ech", "tls_offered_max_version"), {"tls_ech": "outer", "tls_offered_max_version": "1.3"})
        ech = next(e for e in observation.evidence if e.field == "tls_ech")
        self.assertEqual((ech.source, ech.strength), ("wire:client_hello", "offered"))
        self.assertIn("ja4", fields(observation, "ja4"))
        self.assertEqual(classify(observation, "tcp", 443).risks, ("tls-encrypted-client-hello",))
        self.assertIn("tls-encrypted-client-hello", RISKS)
        no_sni = inspect(client_hello_with(((43, b"\x02\x03\x04"), (0xfe0d, ech_outer()))))
        self.assertEqual(classify(no_sni, "tcp", 443).risks, ("tls-encrypted-client-hello", "tls-missing-sni"))
        inner = inspect(client_hello_with(((0, SNI_PUBLIC), (43, b"\x02\x03\x04"), (0xfe0d, b"\x01"))))
        self.assertEqual((inner.status, fields(inner, "tls_ech"), classify(inner, "tcp", 443).risks), ("identified", {"tls_ech": "inner"}, ()))
        plain = inspect(client_hello(), FP)
        self.assertEqual(fields(plain, "tls_ech"), {})
        for kdf, aead in ((0x0002, 0x0002), (0x0003, 0x0003), (0x0001, 0xffff)):
            variant = inspect(client_hello_with(((0, SNI_PUBLIC), (0xfe0d, ech_outer(kdf=kdf, aead=aead, enc=b"", payload=b"\x00")))))
            self.assertEqual(fields(variant, "tls_ech"), {"tls_ech": "outer"}, (kdf, aead))
        for split in range(1, len(TLS_ECH_HELLO), 5):
            inspector = Inspector()
            inspector.feed(TLS_ECH_HELLO[:split])
            inspector.feed(TLS_ECH_HELLO[split:])
            self.assertEqual(fields(inspector.observation, "tls_ech"), {"tls_ech": "outer"}, split)

    def test_malformed_ech_makes_the_hello_malformed(self):
        malformed = [b"", b"\x02", b"\x01\x00", ech_outer()[:9], ech_outer(kdf=0x0004), ech_outer(aead=0x0004),
                     ech_outer(payload=b""), ech_outer() + b"\x00", ech_outer()[:-1],
                     b"\x00\x00\x01\x00\x01\x2a\xff\xff" + bytes(4)]
        for value in malformed:
            with self.assertRaises(ParseError, msg=value.hex()):
                ech_type(value)
            observation = inspect(client_hello_with(((0, SNI_PUBLIC), (0xfe0d, value))))
            self.assertEqual((observation.status, observation.hostname), ("malformed", None), value.hex())
        self.assertEqual(ech_type(ech_outer()), "outer")
        self.assertEqual(ech_type(b"\x01"), "inner")
        generator = random.Random(42)
        for _ in range(300):
            data = bytearray(TLS_ECH_HELLO)
            data[generator.randrange(len(data))] = generator.randrange(256)
            observation = inspect(bytes(data), FP)
            self.assertIn(observation.status, ("identified", "malformed", "detecting", "unknown", "budget_exhausted"))

    def test_quic_initial_reports_ech(self):
        from protocol_engine.quic import V1
        from test_quic import DCID, crypto_frames, protect
        datagram = protect(V1, DCID, b"", crypto_frames(TLS_ECH_HELLO[5:], [])[0])
        match = DatagramInspector(Config()).inspect(datagram)
        self.assertEqual((match.status, match.encryption, match.hostname), ("identified", "quic", "public.example.net"), match)
        ech = {e.field: (e.value, e.source) for e in match.evidence}.get("tls_ech")
        self.assertEqual(ech, ("outer", "quic_client_hello"))
        self.assertEqual(classify(match, "udp", 443).risks, ("tls-encrypted-client-hello",))
        plain = DatagramInspector(Config()).inspect(protect(V1, DCID, b"", crypto_frames(client_hello()[5:], [])[0]))
        self.assertNotIn("tls_ech", {e.field for e in plain.evidence})

if __name__ == "__main__":
    unittest.main()
