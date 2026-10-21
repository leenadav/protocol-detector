"""v0.39: leaf certificate structure after a TLS 1.2 ServerHello.

The watch adds asserted evidence about the certificate's shape (version, key,
signature family, lifetime, issuer-equals-subject) and never names, serials,
keys or signature bytes. Every failure keeps the ServerHello identification.
"""
import json
import random
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from analyze_pcap import Analyzer, readable_session
from make_sample_pcap import A, B, frame, pcap_bytes
from packets import decode_packet
from protocol_engine import Config, Inspector
from protocol_engine.appid import classify
from protocol_engine.parsers import ParseError
from protocol_engine.risks import RISKS
from protocol_engine.x509 import _CURVES, _EC, _ED25519, _ED448, _RSA, _SIGNATURES, MAX_LEAF, leaf_profile, weak_key
from protocol_fixtures import (CA_CERTIFICATE, ECDSA_SHA256, ED25519_OID, LEAF_CERTIFICATE, SHA1_RSA, SHA256_RSA, TLS_RETRY,
                               TLS_SERVER12, TLS_SERVER12_CERTIFICATE, TLS_SERVER13, _ber, certificate_message, tls_record, x509)
from proxy_demo import client_hello
from test_schema import run_json
from tools import schema_check

CERTS = Config(certificates=True)
NAMES = ("laceholder", "010203")   # issuer/subject text and the serial number must never appear


def inspect(data, config=CERTS):
    inspector = Inspector(config)
    return inspector, inspector.feed(data)


def certificate(observation):
    return {e.field[16:]: e.value for e in observation.evidence if e.field.startswith("tls_certificate_")}


def flight(*certs, coalesce=False):
    message = certificate_message(*certs)
    if coalesce:   # ServerHello and Certificate share one record, as most servers send them
        return tls_record(TLS_SERVER12[5:] + message)
    return TLS_SERVER12 + tls_record(message)


def dotted(text):
    """Encode a dotted object identifier as DER contents (independent of the engine's tables)."""
    parts = [int(part) for part in text.split(".")]
    values = [parts[0] * 40 + parts[1]] + parts[2:]
    out = bytearray()
    for value in values:
        chunk = [value & 0x7f]
        value >>= 7
        while value:
            chunk.append(0x80 | (value & 0x7f))
            value >>= 7
        out.extend(reversed(chunk))
    return bytes(out)


def risks(data):
    inspector, _ = inspect(data)
    return classify(inspector.observation, "tcp", 443).risks


class CertificateWatchTests(unittest.TestCase):
    def test_evidence_only_when_enabled_and_no_names(self):
        plain, events = inspect(TLS_SERVER12_CERTIFICATE, Config())
        self.assertEqual((plain.observation.status, plain.observation.encryption, certificate(plain.observation), plain._parser),
                         ("identified", "tls", {}, None))
        self.assertEqual(plain.metrics.bytes_inspected, len(TLS_SERVER12))
        inspector, events = inspect(TLS_SERVER12_CERTIFICATE)
        self.assertEqual([event.kind for event in events], ["updated", "refined"])
        self.assertEqual(certificate(events[0].observation), {})
        expected = {"chain": "chain", "version": "3", "self_issued": "no", "key": "rsa-2048", "signature": "sha256-rsa", "lifetime_days": "365"}
        self.assertEqual(certificate(events[1].observation), expected)
        self.assertEqual(certificate(inspector.observation), expected)
        strengths = {e.field: (e.source, e.strength) for e in inspector.observation.evidence if e.field.startswith("tls_certificate_")}
        self.assertEqual(strengths["tls_certificate_chain"], ("wire:certificate", "structural"))
        self.assertEqual({value for field, value in strengths.items() if field != "tls_certificate_chain"}, {("wire:certificate", "asserted")})
        text = repr(inspector.observation) + repr(events)
        for name in NAMES:
            self.assertNotIn(name, text)
        self.assertNotIn("4444", text)   # signature placeholder bytes
        # Only the leaf is read: the record header, the handshake header, the list lengths and the leaf itself.
        self.assertEqual(inspector.metrics.bytes_inspected, len(TLS_SERVER12) + 5 + 10 + len(LEAF_CERTIFICATE))
        self.assertIsNone(inspector._parser)
        self.assertEqual(inspector.feed(b"more"), ())
        self.assertEqual(risks(TLS_SERVER12_CERTIFICATE), ())
        single, _ = inspect(flight(LEAF_CERTIFICATE))
        self.assertEqual(certificate(single.observation)["chain"], "single")

    def test_every_split_point_and_coalesced_record(self):
        for data in (TLS_SERVER12_CERTIFICATE, flight(LEAF_CERTIFICATE, CA_CERTIFICATE, coalesce=True), flight(LEAF_CERTIFICATE)):
            whole, _ = inspect(data)
            reference = (certificate(whole.observation), whole.metrics.bytes_inspected)
            self.assertEqual(reference[0]["key"], "rsa-2048")
            for split in range(1, len(data), 7):
                inspector = Inspector(CERTS)
                kinds = [event.kind for event in inspector.feed(data[:split]) + inspector.feed(data[split:])]
                self.assertEqual(kinds, ["updated", "refined"], split)
                self.assertEqual((certificate(inspector.observation), inspector.metrics.bytes_inspected), reference, split)
            bytewise = Inspector(CERTS)
            for index in range(len(data)):
                bytewise.feed(data[index:index + 1])
            self.assertEqual((certificate(bytewise.observation), bytewise.metrics.bytes_inspected), reference)

    def test_key_signature_lifetime_and_self_issued_profiles(self):
        def profile(**kwargs):
            inspector, _ = inspect(flight(x509(**kwargs)))
            return certificate(inspector.observation), classify(inspector.observation, "tcp", 443).risks
        self.assertEqual(profile(key="rsa-1024"), ({"chain": "single", "version": "3", "self_issued": "no", "key": "rsa-1024",
                                                     "signature": "sha256-rsa", "lifetime_days": "365"}, ("tls-weak-certificate-key",)))
        self.assertEqual(profile(key="ec-256", signature=ECDSA_SHA256)[0]["key"], "ec-256")
        self.assertEqual(profile(key="ec-256", signature=ECDSA_SHA256)[1], ())
        self.assertEqual(profile(key="ec-384", signature=ECDSA_SHA256)[0]["key"], "ec-384")
        self.assertEqual(profile(key="ec-other", signature=ECDSA_SHA256), ({"chain": "single", "version": "3", "self_issued": "no", "key": "ec-other",
                                                                            "signature": "ecdsa-sha256", "lifetime_days": "365"}, ()))
        fields, found = profile(key="ed25519", signature=ED25519_OID)
        self.assertEqual((fields["key"], fields["signature"], found), ("ed25519", "ed25519", ()))
        fields, found = profile(signature=SHA1_RSA)
        self.assertEqual((fields["signature"], found), ("sha1-rsa", ("tls-weak-certificate-signature",)))
        fields, found = profile(signature=dotted("1.2.3.4"))
        self.assertEqual((fields["signature"], found), ("other", ()))
        fields, found = profile(not_after=b"20491231235959Z")
        self.assertEqual((fields["lifetime_days"], found), (str((datetime(2049, 12, 31, 23, 59, 59) - datetime(2024, 1, 1)).days),
                                                            ("tls-certificate-lifetime-excessive",)))
        self.assertEqual(profile(not_after=b"250202000000Z"), ({"chain": "single", "version": "3", "self_issued": "no", "key": "rsa-2048",
                                                                "signature": "sha256-rsa", "lifetime_days": "398"}, ()))   # 2024 is a leap year
        self.assertEqual(profile(not_after=b"250203000000Z")[1], ("tls-certificate-lifetime-excessive",))
        fields, found = profile(issuer=b"placeholder")
        self.assertEqual((fields["self_issued"], found), ("yes", ("tls-self-issued-certificate",)))
        self.assertEqual(profile(version=1, extensions=False)[0]["version"], "1")
        self.assertEqual(profile(version=2, extensions=False)[0]["version"], "2")
        self.assertEqual(profile(not_before=b"19700101000000Z", not_after=b"20380119031407Z")[0]["lifetime_days"], "24855")
        fields, found = profile(issuer=b"placeholder", key="rsa-512", signature=SHA1_RSA, not_after=b"20491231235959Z")
        self.assertEqual(found, ("tls-certificate-lifetime-excessive", "tls-self-issued-certificate",
                                 "tls-weak-certificate-key", "tls-weak-certificate-signature"))
        for name in found:
            self.assertIn(name, RISKS)
        self.assertEqual([weak_key(label) for label in ("rsa-1024", "rsa-2048", "ec-224", "ec-256", "ec-other", "other", "ed25519")],
                         [True, False, True, False, False, False, False])

    def test_rejections_keep_the_identification(self):
        inner = _ber(0x30, _ber(6, SHA256_RSA) + _ber(5, b""))
        leaf = x509()
        huge = b"\x30\x84" + (MAX_LEAF + 1 - 6).to_bytes(4, "big") + bytes(MAX_LEAF + 1 - 6)
        bad_message = certificate_message(leaf)
        broken_list = bad_message[:4] + (len(leaf) + 2).to_bytes(3, "big") + bad_message[7:]
        rejected_der = [
            leaf + b"\x00",                                                              # trailing byte inside the entry
            b"\x30\x80" + leaf[4:],                                                      # indefinite length
            x509(version=4),                                                             # version outside v1..v3
            x509(version=1, extensions=True),                                            # extensions need v3
            leaf.replace(inner, _ber(0x30, _ber(6, SHA1_RSA) + _ber(5, b"")), 1),         # inner/outer algorithms disagree
            x509(not_before=b"250101000000Z", not_after=b"240101000000Z"),               # ends before it starts
            x509(not_before=b"240230000000Z"),                                           # 30 February
            x509(not_before=b"240101000000+"),                                           # not UTC
            x509(not_before=b"2401010000Z"),                                             # no seconds
            leaf.replace(b"\x03\x41\x00\x44", b"\x03\x41\x01\x44"),                      # unused bits in the signature
            leaf.replace(b"\x00\xc5\x11", b"\x80\xc5\x11"),                              # negative RSA modulus
            x509(key="ec-256", signature=ECDSA_SHA256).replace(b"\x03\x42\x00\x04\x22", b"\x03\x42\x00\x05\x22"),  # EC point form
            leaf.replace(b"\x31\x17\x30\x15", b"\x30\x17\x30\x15", 1),                   # Name component is not a SET
            x509(serial=b"\x01" * 33),                                                   # serial beyond the profile
            b"\x30\x03\x02\x01\x01",                                                     # not a certificate at all
        ]
        for der in rejected_der:
            with self.assertRaises(ParseError, msg=der[:16].hex()):
                leaf_profile(der)
        rejected_flights = [TLS_SERVER12 + tls_record(der and certificate_message(der)) for der in rejected_der] + [
            TLS_SERVER12 + tls_record(b"\x01", kind=20),                 # ChangeCipherSpec: abbreviated handshake
            TLS_SERVER12 + tls_record(b"\x02\x28", kind=21),             # alert
            TLS_SERVER12 + tls_record(b"\x0e\x00\x00\x00"),              # ServerHelloDone first
            TLS_SERVER12 + tls_record(b"\x0b\x00\x00\x03\x00\x00\x00"),  # empty certificate list
            TLS_SERVER12 + tls_record(broken_list),                      # list length disagrees
            TLS_SERVER12 + tls_record(certificate_message(huge)),        # leaf beyond MAX_LEAF
            TLS_SERVER12 + b"\x16\x03\x03\x00\x00",                      # zero-length record
            TLS_SERVER12 + b"\x16\x04\x03\x00\x10",                      # record version outside TLS
        ]
        for data in rejected_flights:
            inspector, _ = inspect(data)
            self.assertEqual((inspector.observation.status, inspector.observation.encryption, certificate(inspector.observation), inspector._parser),
                             ("identified", "tls", {}, None), data[len(TLS_SERVER12):len(TLS_SERVER12) + 16].hex())
            self.assertLessEqual(inspector.metrics.bytes_inspected, len(data))
        whole, _ = inspect(TLS_SERVER12_CERTIFICATE)
        for limit in (64, 300, whole.metrics.bytes_inspected - 1, whole.metrics.bytes_inspected - 100):
            for split in (None, 60, 200, 400):
                budget = Inspector(Config(certificates=True, max_bytes=limit))
                if split is None:
                    budget.feed(TLS_SERVER12_CERTIFICATE)
                else:
                    budget.feed(TLS_SERVER12_CERTIFICATE[:split])
                    budget.feed(TLS_SERVER12_CERTIFICATE[split:])
                self.assertEqual((budget.observation.status, certificate(budget.observation), budget._parser), ("identified", {}, None), (limit, split))
                self.assertLessEqual(budget.metrics.bytes_inspected, limit, (limit, split))
        exact = Inspector(Config(certificates=True, max_bytes=whole.metrics.bytes_inspected))
        exact.feed(TLS_SERVER12_CERTIFICATE)
        self.assertEqual(certificate(exact.observation)["key"], "rsa-2048")
        partial, _ = inspect(TLS_SERVER12_CERTIFICATE[:len(TLS_SERVER12) + 100])
        self.assertIsNotNone(partial._parser)
        self.assertEqual((partial.end(), partial.observation.status, certificate(partial.observation), partial._parser), ((), "identified", {}, None))
        invalidated, _ = inspect(TLS_SERVER12_CERTIFICATE[:len(TLS_SERVER12) + 100])
        self.assertEqual(invalidated.invalidate("conflict")[0].observation.status, "invalidated")
        self.assertEqual(invalidated.feed(TLS_SERVER12_CERTIFICATE[len(TLS_SERVER12) + 100:]), ())
        generator = random.Random(39)
        for _ in range(400):
            data = bytearray(TLS_SERVER12_CERTIFICATE)
            index = generator.randrange(len(TLS_SERVER12), len(data))
            data[index] = generator.randrange(256)
            inspector, _ = inspect(bytes(data))
            self.assertEqual((inspector.observation.status, inspector.observation.encryption), ("identified", "tls"))
            self.assertLessEqual(inspector.metrics.bytes_inspected, len(data))
            self.assertIsNone(inspector._parser)
            text = repr(inspector.observation)
            for name in NAMES:
                self.assertNotIn(name, text)

    def test_tls13_retry_and_client_hello_never_continue(self):
        for data in (TLS_SERVER13, TLS_RETRY, client_hello()):
            inspector, events = inspect(data + tls_record(certificate_message(LEAF_CERTIFICATE)))
            self.assertEqual(([event.kind for event in events], inspector.observation.status, inspector._parser), (["updated"], "identified", None))
            self.assertEqual(certificate(inspector.observation), {})
            self.assertEqual(inspector.metrics.bytes_inspected, len(data))

    def test_oid_tables_match_their_dotted_identifiers(self):
        expected = {"1.2.840.113549.1.1.4": "md5-rsa", "1.2.840.113549.1.1.5": "sha1-rsa", "1.2.840.113549.1.1.11": "sha256-rsa",
                    "1.2.840.113549.1.1.12": "sha384-rsa", "1.2.840.113549.1.1.13": "sha512-rsa", "1.2.840.113549.1.1.10": "rsa-pss",
                    "1.2.840.10045.4.1": "ecdsa-sha1", "1.2.840.10045.4.3.2": "ecdsa-sha256", "1.2.840.10045.4.3.3": "ecdsa-sha384",
                    "1.2.840.10045.4.3.4": "ecdsa-sha512", "1.3.101.112": "ed25519", "1.3.101.113": "ed448"}
        self.assertEqual({dotted(k): v for k, v in expected.items()}, dict(_SIGNATURES))
        self.assertEqual({dotted("1.2.840.10045.3.1.7"): 256, dotted("1.3.132.0.34"): 384, dotted("1.3.132.0.35"): 521}, dict(_CURVES))
        self.assertEqual((_RSA, _EC, _ED25519, _ED448), (dotted("1.2.840.113549.1.1.1"), dotted("1.2.840.10045.2.1"), dotted("1.3.101.112"), dotted("1.3.101.113")))
        self.assertEqual(dotted("2.5.4.3"), b"\x55\x04\x03")

    def test_records_cli_and_schemas_carry_certificate_labels_only(self):
        hello = client_hello()
        cr, cs = 1000, 9000
        frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, cr, cs, 24, hello),
                  frame(B, A, cs, cr + len(hello), 24, TLS_SERVER12_CERTIFICATE)]
        for enabled in (False, True):
            records = []
            analyzer = Analyzer(on_session=records.append, certificates=enabled)
            for number, data in enumerate(frames):
                analyzer.process(number, decode_packet(data))
            analyzer.finish("done")
            record = records[0]
            self.assertEqual((record["app"], record["server_protocol"], "certificate" in record), ("ssl", "tls", enabled))
            self.assertEqual(schema_check.validate(json.loads(json.dumps(record)), schema_check.load("session")), [])
            if enabled:
                self.assertEqual(record["certificate"], {"chain": "chain", "version": "3", "self_issued": "no", "key": "rsa-2048",
                                                         "signature": "sha256-rsa", "lifetime_days": "365"})
                self.assertIn("certificate=chain=chain,key=rsa-2048", readable_session(record))
                for name in NAMES:
                    self.assertNotIn(name, json.dumps(record))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tls12.pcap"
            path.write_bytes(pcap_bytes(frames))
            code, lines = run_json("analyze_pcap.py", str(path), "--json", "--sessions", "--certificates")
            self.assertEqual(code, 0)
            session = [json.loads(line) for line in lines if '"type": "session"' in line][0]
            self.assertEqual(session["certificate"]["signature"], "sha256-rsa")
            code, lines = run_json("analyze_pcap.py", str(path), "--json", "--sessions")
            self.assertEqual(code, 0)
            self.assertNotIn("certificate", [json.loads(line) for line in lines if '"type": "session"' in line][0])
            code, lines = run_json("live_capture.py", "--stdin", "--duration", "0", "--json", "--certificates", stdin=path.read_bytes())
            self.assertEqual(code, 0)
            events = [json.loads(line) for line in lines]
            refined = [event for event in events if event.get("type") == "classification" and event.get("event") == "refined"]
            self.assertEqual(refined[0]["certificate"]["key"], "rsa-2048")
            self.assertEqual(schema_check.validate_lines(lines, "live-event")[1], [])


if __name__ == "__main__":
    unittest.main()
