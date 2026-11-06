"""v0.57: TLS posture (server key exchange and record protection, leaf basicConstraints / EKU / SAN, validity at capture time)."""
import calendar
import random
import unittest

from analyze_pcap import Analyzer
from make_sample_pcap import A, B, frame
from packets import decode_packet
from protocol_engine import Config, DatagramInspector, Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.parsers import ParseError
from protocol_engine.risks import RISKS
from protocol_engine.tls_server import _TLS12_CIPHERS
from protocol_engine.x509 import (_ANY_KEY_USAGE, _BASIC_CONSTRAINTS, _EXTENDED_KEY_USAGE, _SERVER_AUTH, _SUBJECT_ALT_NAME, MAX_EKU,
                                  MAX_GENERAL_NAMES, leaf_profile, validity)
from protocol_fixtures import (ANY_KEY_USAGE_OID, CLIENT_AUTH_OID, DTLS_SERVER_HELLO, ECDSA_SHA256, SERVER_AUTH_OID, TLS_RETRY, TLS_SERVER12, TLS_SERVER13,
                               _ber, certificate_message, dtls_record, tls_record, x509, x509_extension)
from proxy_demo import client_hello
from test_certificates import dotted

CERTS = Config(certificates=True)
SAN_OID, EKU_OID, BC_OID = b"\x55\x1d\x11", b"\x55\x1d\x25", b"\x55\x1d\x13"
NAMES = ("laceholder", "010203")
POSTURE_FIELDS = ("selected_key_exchange", "selected_cipher_mode")


def server_hello(cipher, extensions=b"", retry=False):
    hello_random = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c") if retry else bytes(range(32))
    body = b"\x03\x03" + hello_random + b"\0" + cipher.to_bytes(2, "big") + b"\0"
    if extensions:
        body += len(extensions).to_bytes(2, "big") + extensions
    return tls_record(b"\x02" + len(body).to_bytes(3, "big") + body)


def extension(kind, value):
    return kind.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


TLS13 = extension(43, b"\x03\x04")
X25519 = extension(51, b"\x00\x1d\x00\x20" + bytes(32))
FFDHE2048 = extension(51, b"\x01\x00\x01\x00" + bytes(256))
PSK = extension(41, b"\x00\x00")


def inspect(data, config=CERTS):
    inspector = Inspector(config)
    inspector.feed(data)
    return inspector.observation


def labels(observation, prefix=None, names=POSTURE_FIELDS):
    if prefix is not None:
        return {e.field[len(prefix):]: e.value for e in observation.evidence if e.field.startswith(prefix)}
    return {e.field: e.value for e in observation.evidence if e.field in names}


def risks(observation, at=None):
    return classify(observation, "tcp", 443, at=at).risks


def flight(der, cipher=None):
    hello = TLS_SERVER12 if cipher is None else server_hello(cipher)
    return hello + tls_record(certificate_message(der))


def posix(text):
    return calendar.timegm((int(text[:4]), int(text[5:7]), int(text[8:10]), int(text[11:13] or 0), int(text[14:16] or 0), 0, 0, 0, 0))


class ServerSelectionTests(unittest.TestCase):
    def test_tls12_suites_by_key_exchange_and_record_protection(self):
        # Written from the RFC 5246 / 5289 suite names, independent of the engine's tables.
        suites = {0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
                  0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0xc024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
                  0xc025: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", 0xc026: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
                  0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                  0xc029: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", 0xc02a: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
                  0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                  0xc02d: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", 0xc02e: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
                  0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                  0xc031: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", 0xc032: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"}
        self.assertEqual(set(suites), set(_TLS12_CIPHERS))
        for cipher, name in suites.items():
            exchange = "ecdhe" if "_ECDHE_" in name else "static-ecdh" if "_ECDH_" in name else "static-rsa"
            mode = "aead" if "_GCM_" in name else "cbc"
            observation = inspect(server_hello(cipher), Config())
            self.assertEqual((observation.status, labels(observation)), ("identified", {"selected_key_exchange": exchange, "selected_cipher_mode": mode}), name)
            self.assertEqual(risks(observation), () if exchange == "ecdhe" else ("tls-no-forward-secrecy",), name)
        self.assertEqual(labels(inspect(TLS_SERVER12, Config())), {"selected_key_exchange": "ecdhe", "selected_cipher_mode": "aead"})

    def test_tls13_key_share_psk_and_retry(self):
        cases = [(TLS13 + X25519, "ecdhe", ()), (TLS13 + FFDHE2048, "dhe", ()), (TLS13 + PSK + X25519, "ecdhe", ()),
                 (TLS13 + PSK, "psk", ("tls-no-forward-secrecy",))]
        for extensions, exchange, expected in cases:
            for cipher in range(0x1301, 0x1306):
                observation = inspect(server_hello(cipher, extensions), Config())
                self.assertEqual((observation.status, labels(observation)), ("identified", {"selected_key_exchange": exchange, "selected_cipher_mode": "aead"}))
                self.assertEqual(risks(observation), expected)
        self.assertEqual(labels(inspect(TLS_SERVER13, Config())), {"selected_key_exchange": "ecdhe", "selected_cipher_mode": "aead"})
        retry = inspect(TLS_RETRY, Config())
        self.assertEqual((retry.status, labels(retry)), ("identified", {}))      # a retry selects nothing yet
        self.assertEqual(labels(inspect(client_hello(), Config())), {})
        self.assertEqual(risks(inspect(server_hello(0x002f) + tls_record(certificate_message(x509())))), ("tls-no-forward-secrecy",))

    def test_dtls12_server_hello_carries_the_same_labels(self):
        observation = DatagramInspector().inspect(DTLS_SERVER_HELLO)
        self.assertEqual((observation.status, labels(observation)), ("identified", {"selected_key_exchange": "ecdhe", "selected_cipher_mode": "aead"}))
        self.assertEqual(classify(observation, "udp", 443).risks, ())
        static = DatagramInspector().inspect(dtls_record(2, b"\xfe\xfd" + bytes(range(32)) + b"\x00\x00\x2f\x00"))
        self.assertEqual((static.status, labels(static)), ("identified", {"selected_key_exchange": "static-rsa", "selected_cipher_mode": "cbc"}))
        self.assertEqual(classify(static, "udp", 443).risks, ("tls-no-forward-secrecy",))


class LeafPostureTests(unittest.TestCase):
    def profile(self, **kwargs):
        observation = inspect(flight(x509(**kwargs)))
        return labels(observation, "tls_certificate_"), risks(observation)

    def test_basic_constraints_eku_and_san_labels(self):
        fields, found = self.profile()
        self.assertEqual({k: fields[k] for k in ("ca", "eku", "san", "not_before", "not_after")},
                         {"ca": "no", "eku": "server-auth", "san": "present", "not_before": "2024-01-01", "not_after": "2024-12-31"})
        self.assertEqual(found, ())
        self.assertEqual(self.profile(ca=True), (dict(fields, ca="yes"), ("tls-ca-certificate-as-leaf",)))
        self.assertEqual(self.profile(ca=True, path_len=b"\x00")[0]["ca"], "yes")
        self.assertEqual(self.profile(ca=True, path_len=b"\x00\x80")[0]["ca"], "yes")
        self.assertEqual(self.profile(eku=(CLIENT_AUTH_OID,)), (dict(fields, eku="other"), ("tls-certificate-not-for-server-auth",)))
        self.assertEqual(self.profile(eku=(ANY_KEY_USAGE_OID,)), (dict(fields, eku="any"), ()))
        self.assertEqual(self.profile(eku=(CLIENT_AUTH_OID, SERVER_AUTH_OID)), (fields, ()))
        self.assertEqual(self.profile(eku=(CLIENT_AUTH_OID, ANY_KEY_USAGE_OID))[0]["eku"], "any")
        self.assertEqual(self.profile(eku=(SERVER_AUTH_OID,) * MAX_EKU)[0]["eku"], "server-auth")
        self.assertEqual(self.profile(eku=None), (dict(fields, eku="absent"), ()))
        self.assertEqual(self.profile(san=None), (dict(fields, san="absent"), ("tls-certificate-without-san",)))
        many = tuple(b"h%03d.placeholder.example" % index for index in range(MAX_GENERAL_NAMES))
        self.assertEqual(self.profile(san=many), (fields, ()))                      # exactly at the entry budget
        unknown = x509_extension(bytes.fromhex("2b0601040182370a0302"), _ber(0x30, b""))       # framing only, never interpreted
        self.assertEqual(self.profile(extra=(unknown,)), (fields, ()))
        self.assertEqual(self.profile(extensions=False), (dict(fields, eku="absent", san="absent"), ("tls-certificate-without-san",)))
        for version in (1, 2):
            fields_v, found_v = self.profile(version=version, extensions=False)
            self.assertEqual(({"ca", "eku", "san"} & set(fields_v), found_v), (set(), ()))
            self.assertEqual(fields_v["not_after"], "2024-12-31")
        all_four = self.profile(ca=True, eku=(CLIENT_AUTH_OID,), san=None, issuer=b"placeholder")[1]
        self.assertEqual(all_four, ("tls-ca-certificate-as-leaf", "tls-certificate-not-for-server-auth",
                                    "tls-certificate-without-san", "tls-self-issued-certificate"))
        for name in all_four + ("tls-no-forward-secrecy", "tls-certificate-outside-validity"):
            self.assertIn(name, RISKS)
        # The interpreted OIDs, encoded independently from their dotted form.
        self.assertEqual((_BASIC_CONSTRAINTS, _SUBJECT_ALT_NAME, _EXTENDED_KEY_USAGE, _SERVER_AUTH, _ANY_KEY_USAGE),
                         (dotted("2.5.29.19"), dotted("2.5.29.17"), dotted("2.5.29.37"), dotted("1.3.6.1.5.5.7.3.1"), dotted("2.5.29.37.0")))
        self.assertEqual((SERVER_AUTH_OID, CLIENT_AUTH_OID, ANY_KEY_USAGE_OID),
                         (dotted("1.3.6.1.5.5.7.3.1"), dotted("1.3.6.1.5.5.7.3.2"), dotted("2.5.29.37.0")))

    def test_extension_rules_reject_without_losing_the_identification(self):
        def raw(oid, value, **kwargs):
            return x509(extra=(x509_extension(oid, value),), **kwargs)
        rejected = {
            "duplicate subjectAltName": raw(SAN_OID, _ber(0x30, _ber(0x82, b"placeholder.example"))),
            "duplicate basicConstraints": raw(BC_OID, _ber(0x30, b""), eku=None),
            "cA FALSE encoded": x509(constraints=_ber(1, b"\x00")),                         # DER omits the default
            "cA not a DER boolean": x509(constraints=_ber(1, b"\x01")),
            "pathLen without cA": x509(path_len=b"\x01"),
            "negative pathLen": x509(ca=True, path_len=b"\x80"),
            "non-minimal pathLen": x509(ca=True, path_len=b"\x00\x01"),
            "oversized pathLen": x509(ca=True, path_len=b"\x01\x02\x03\x04\x05"),
            "empty pathLen": x509(ca=True, path_len=b""),
            "empty EKU": x509(eku=()),
            "EKU beyond the purpose budget": x509(eku=(SERVER_AUTH_OID,) * (MAX_EKU + 1)),
            "EKU entry not an OID": x509(eku=None, extra=(x509_extension(EKU_OID, _ber(0x30, _ber(0x0c, b"serverAuth"))),)),
            "EKU trailing bytes": x509(eku=None, extra=(x509_extension(EKU_OID, _ber(0x30, _ber(6, SERVER_AUTH_OID)) + b"\x00"),)),
            "empty SAN": x509(san=()),
            "SAN entry with a universal tag": x509(san=None, extra=(x509_extension(SAN_OID, _ber(0x30, _ber(0x0c, b"placeholder"))),)),
            "SAN choice beyond registeredID": x509(san=None, extra=(x509_extension(SAN_OID, _ber(0x30, _ber(0x89, b"\x01"))),)),
            "SAN entry overruns": x509(san=None, extra=(x509_extension(SAN_OID, b"\x30\x04\x82\x05ab"),)),
            "basicConstraints not a sequence": x509(eku=None, san=None).replace(b"\x04\x02\x30\x00", b"\x04\x02\x31\x00"),
            "basicConstraints unexpected field": x509(constraints=_ber(5, b"")),
            "basicConstraints field after pathLen": x509(constraints=_ber(1, b"\xff") + _ber(2, b"\x01") + _ber(5, b"")),
            "basicConstraints trailing bytes": x509(eku=None, san=None).replace(      # same length, non-critical
                b"\x30\x0c\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x02\x30\x00", b"\x30\x0c\x06\x03\x55\x1d\x13\x04\x05\x30\x00\x00\x00\x00"),
        }
        for name, der in rejected.items():
            with self.assertRaises(ParseError, msg=name):
                leaf_profile(der)
            observation = inspect(flight(der))
            self.assertEqual((observation.status, observation.encryption, labels(observation, "tls_certificate_")), ("identified", "tls", {}), name)
            self.assertEqual(labels(observation)["selected_key_exchange"], "ecdhe", name)
        # The basicConstraints encoding the same-length replacements rely on.
        self.assertIn(b"\x30\x0c\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x02\x30\x00", x509(eku=None, san=None))
        accepted = x509(eku=None, san=None).replace(b"\x30\x0c\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x02\x30\x00",
                                                    b"\x30\x0c\x06\x03\x55\x1d\x13\x04\x05\x30\x03\x01\x01\xff")   # non-critical cA TRUE
        self.assertEqual(dict(leaf_profile(accepted))["tls_certificate_ca"], "yes")

    def test_no_names_and_mutations_keep_the_identification(self):
        der = x509(ca=True, path_len=b"\x02", eku=(CLIENT_AUTH_OID, SERVER_AUTH_OID), san=(b"placeholder.example", b"www.placeholder.example"))
        data = flight(der)
        whole = inspect(data)
        reference = labels(whole, "tls_certificate_")
        self.assertEqual((reference["ca"], reference["eku"], reference["san"]), ("yes", "server-auth", "present"))
        text = repr(whole)
        for name in NAMES:
            self.assertNotIn(name, text)
        for split in range(1, len(data), 11):
            inspector = Inspector(CERTS)
            inspector.feed(data[:split])
            inspector.feed(data[split:])
            self.assertEqual(labels(inspector.observation, "tls_certificate_"), reference, split)
        generator = random.Random(57)
        start = len(TLS_SERVER12)
        for _ in range(500):
            mutated = bytearray(data)
            mutated[generator.randrange(start, len(mutated))] = generator.randrange(256)
            inspector = Inspector(CERTS)
            inspector.feed(bytes(mutated))
            observation = inspector.observation
            self.assertEqual((observation.status, observation.encryption, inspector._parser), ("identified", "tls", None))
            self.assertLessEqual(inspector.metrics.bytes_inspected, len(mutated))
            found = labels(observation, "tls_certificate_")
            self.assertLessEqual(set(found.get(k) for k in ("ca",) if k in found), {"yes", "no"})
            self.assertIn(found.get("eku", "absent"), ("server-auth", "any", "other", "absent"))
            for name in NAMES:
                self.assertNotIn(name, repr(observation))


class ValidityTests(unittest.TestCase):
    def test_day_granular_window_and_unset_clocks(self):
        cases = [("2023-12-31T23:59", "not-yet-valid"), ("2024-01-01T00:00", "current"), ("2024-06-15T12:00", "current"),
                 ("2024-12-31T23:59", "current"), ("2025-01-01T00:00", "expired")]
        for moment, expected in cases:
            self.assertEqual(validity("2024-01-01", "2024-12-31", posix(moment)), expected, moment)
            self.assertEqual(validity("2024-01-01", "2024-12-31", posix(moment) + 0.5), expected, moment)
        for at in (None, 0, 3, 946684799, float("nan"), float("inf"), float("-inf"), 253402300800, 1e300, -5):
            self.assertIsNone(validity("2024-01-01", "2024-12-31", at), at)
        self.assertEqual(validity("2024-01-01", "2024-12-31", 946684800), "not-yet-valid")
        self.assertEqual(validity("0005-01-01", "9999-12-31", 253402300799), "current")
        self.assertIsNone(validity(None, "2024-12-31", posix("2024-06-01T00:00")))
        self.assertIsNone(validity("2024-01-01", "", posix("2024-06-01T00:00")))
        old = dict(leaf_profile(x509(not_before=b"00050101000000Z", not_after=b"00060101000000Z")))
        self.assertEqual((old["tls_certificate_not_before"], old["tls_certificate_not_after"]), ("0005-01-01", "0006-01-01"))

    def test_risk_needs_a_capture_clock(self):
        observation = inspect(flight(x509()))
        self.assertEqual(risks(observation), ())
        self.assertEqual(risks(observation, posix("2024-07-01T00:00")), ())
        for moment in ("2023-06-01T00:00", "2026-10-22T00:00"):
            self.assertEqual(risks(observation, posix(moment)), ("tls-certificate-outside-validity",), moment)
        self.assertEqual(risks(observation, 5), ())
        hello = inspect(client_hello(), Config())
        verdict = session_verdict(hello, observation, "tcp", 443, 100, 100, at=posix("2025-03-01T00:00"))
        self.assertEqual((verdict.app, verdict.risks), ("ssl", ("tls-certificate-outside-validity",)))
        self.assertEqual(session_verdict(hello, observation, "tcp", 443, 100, 100).risks, ())

    def test_records_judge_validity_at_the_session_start(self):
        hello = client_hello()
        cr, cs = 1000, 9000
        frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, cr, cs, 24, hello),
                  frame(B, A, cs, cr + len(hello), 24, TLS_SERVER12 + tls_record(certificate_message(x509())))]

        def record(start, step):
            records = []
            analyzer = Analyzer(on_session=records.append, certificates=True)
            for number, data in enumerate(frames):
                analyzer.process(start + number * step, decode_packet(data))
            analyzer.finish("done")
            return records[0]
        # Starts on the last valid day and ends after midnight: judged at the start, so current
        # (day-granular and start-anchored errs towards not flagging; RISKS.md documents it).
        late = record(posix("2024-12-31T23:59") + 58, 1)
        self.assertGreaterEqual(late["end"], posix("2025-01-01T00:00"))
        self.assertEqual(late["certificate"]["validity"], "current")
        self.assertNotIn("tls-certificate-outside-validity", late["risks"])
        expired = record(posix("2025-01-01T00:00"), 1)
        self.assertEqual(expired["certificate"]["validity"], "expired")
        self.assertIn("tls-certificate-outside-validity", expired["risks"])
        early = record(posix("2023-12-31T12:00"), 1)
        self.assertEqual((early["certificate"]["validity"], "tls-certificate-outside-validity" in early["risks"]), ("not-yet-valid", True))
        unset = record(0, 1)
        self.assertNotIn("validity", unset["certificate"])
        self.assertNotIn("tls-certificate-outside-validity", unset["risks"])


class ReviewRound1Tests(unittest.TestCase):
    """Repairs for the v0.57 round-1 findings: SAN entry budget and GeneralName forms, DER critical flag."""

    def assert_rejected(self, der, name):
        with self.assertRaises(ParseError, msg=name):
            leaf_profile(der)
        observation = inspect(flight(der))
        self.assertEqual((observation.status, observation.encryption, labels(observation, "tls_certificate_")), ("identified", "tls", {}), name)

    def test_general_name_budget_and_forms(self):
        def san(*entries):
            return x509(san=None, extra=(x509_extension(SAN_OID, _ber(0x30, b"".join(entries))),))
        name = _ber(0x30, _ber(0x31, _ber(0x30, _ber(6, b"\x55\x04\x03") + _ber(0x0c, b"placeholder"))))
        valid = {"rfc822Name": _ber(0x81, b"a@placeholder.example"), "dNSName": _ber(0x82, b"placeholder.example"),
                 "x400Address": _ber(0xa3, _ber(0x30, b"")), "directoryName": _ber(0xa4, name), "ediPartyName": _ber(0xa5, _ber(0xa1, _ber(0x0c, b"p"))),
                 "URI": _ber(0x86, b"https://placeholder.example/"), "iPAddress v4": _ber(0x87, bytes(4)), "iPAddress v6": _ber(0x87, bytes(16)),
                 "registeredID": _ber(0x88, b"\x2b\x06\x01"), "otherName": _ber(0xa0, _ber(6, b"\x2b\x06\x01\x04\x01\x82\x37\x14\x02\x03") + _ber(0xa0, _ber(0x0c, b"p")))}
        for label, entry in valid.items():
            self.assertEqual(dict(leaf_profile(san(entry)))["tls_certificate_san"], "present", label)
        self.assertEqual(dict(leaf_profile(san(*valid.values())))["tls_certificate_san"], "present")
        rejected = {
            "primitive [0] otherName": san(b"\x80\x00"), "constructed [1] rfc822Name": san(_ber(0xa1, _ber(0x16, b"a"))),
            "constructed [2] dNSName": san(b"\xa2\x00"), "primitive [3] x400Address": san(b"\x83\x01\x00"),
            "primitive [4] directoryName": san(b"\x84\x01\x00"), "primitive [5] ediPartyName": san(b"\x85\x01\x00"),
            "constructed [6] URI": san(b"\xa6\x00"), "constructed [7] iPAddress": san(_ber(0xa7, bytes(4))),
            "constructed [8] registeredID": san(_ber(0xa8, b"\x2b")), "choice [9]": san(b"\x89\x01\x00"),
            "universal tag": san(_ber(0x16, b"a")), "empty dNSName": san(b"\x82\x00"), "empty rfc822Name": san(b"\x81\x00"),
            "empty URI": san(b"\x86\x00"), "empty x400Address": san(b"\xa3\x00"), "iPAddress of 5 octets": san(_ber(0x87, bytes(5))),
            "iPAddress of 8 octets": san(_ber(0x87, bytes(8))), "registeredID cut mid-arc": san(_ber(0x88, b"\x2b\x86")),
            "otherName without OID": san(_ber(0xa0, _ber(0xa0, _ber(0x0c, b"p")))),
            "otherName without value": san(_ber(0xa0, _ber(6, b"\x2b\x06\x01"))),
            "otherName with trailing bytes": san(_ber(0xa0, _ber(6, b"\x2b\x06\x01") + _ber(0xa0, _ber(0x0c, b"p")) + b"\x05\x00")),
            "directoryName not a Name": san(_ber(0xa4, _ber(0x31, b""))),
            "directoryName with trailing bytes": san(_ber(0xa4, name + b"\x05\x00")),
            "one entry over the budget": x509(san=tuple(b"h%03d.placeholder.example" % index for index in range(MAX_GENERAL_NAMES + 1))),
        }
        for label, der in rejected.items():
            self.assert_rejected(der, label)
        for name_text in NAMES + ("placeholder.example",):
            self.assertNotIn(name_text, repr(leaf_profile(san(*valid.values()))))

    def test_explicit_critical_false_is_not_der(self):
        def flagged(oid, value, flag):
            return _ber(0x30, _ber(6, oid) + (_ber(1, flag) if flag is not None else b"") + _ber(4, value))
        unknown = bytes.fromhex("2b0601040182370a0302")
        cases = {"subjectAltName": (SAN_OID, _ber(0x30, _ber(0x82, b"placeholder.example")), {"san": None}),
                 "extendedKeyUsage": (EKU_OID, _ber(0x30, _ber(6, SERVER_AUTH_OID)), {"eku": None}),
                 "uninterpreted extension": (unknown, _ber(0x30, b""), {})}
        for label, (oid, value, omit) in cases.items():
            for flag in (None, b"\xff"):
                self.assertIn("tls_certificate_san", dict(leaf_profile(x509(extra=(flagged(oid, value, flag),), **omit))), label)
            for flag in (b"\x00", b"\x01", b"\x7f", b"\xff\xff"):
                self.assert_rejected(x509(extra=(flagged(oid, value, flag),), **omit), label + " critical " + flag.hex())
        base = x509(eku=None, san=None)
        self.assertIn(b"\x55\x1d\x13\x01\x01\xff", base)
        self.assert_rejected(base.replace(b"\x55\x1d\x13\x01\x01\xff", b"\x55\x1d\x13\x01\x01\x00"), "basicConstraints critical FALSE")


class ReviewRound2Tests(unittest.TestCase):
    """Repairs for the v0.57 round-2 finding: GeneralName inner values, DER object identifiers everywhere."""

    def test_general_name_inner_values(self):
        def san(*entries):
            return x509(san=None, extra=(x509_extension(SAN_OID, _ber(0x30, b"".join(entries))),))
        other_oid = _ber(6, b"\x2b\x06\x01")
        valid = {"IA5 text with every seven-bit value": _ber(0x82, bytes(range(1, 128))),
                 "registeredID with a multi-octet arc": _ber(0x88, b"\x2b\x81\x00"),
                 "otherName": _ber(0xa0, other_oid + _ber(0xa0, _ber(0x0c, b"p"))),
                 "x400Address of two elements": _ber(0xa3, _ber(0x30, b"") + _ber(0x61, _ber(0x13, b"x"))),
                 "ediPartyName with nameAssigner": _ber(0xa5, _ber(0xa0, _ber(0x0c, b"a")) + _ber(0xa1, _ber(0x0c, b"p")))}
        for label, entry in valid.items():
            self.assertEqual(dict(leaf_profile(san(entry)))["tls_certificate_san"], "present", label)
        rejected = {
            "rfc822Name octet 0xff": san(b"\x81\x01\xff"), "dNSName octet 0x80": san(b"\x82\x01\x80"),
            "URI with a high octet": san(b"\x86\x02\x61\xff"),
            "registeredID non-minimal first arc": san(b"\x88\x02\x80\x00"), "registeredID empty": san(b"\x88\x00"),
            "registeredID non-minimal later arc": san(b"\x88\x03\x2b\x80\x01"),
            "otherName empty [0]": san(_ber(0xa0, other_oid + b"\xa0\x00")),
            "otherName two values": san(_ber(0xa0, other_oid + _ber(0xa0, _ber(0x0c, b"p") + _ber(0x0c, b"q")))),
            "otherName truncated value": san(_ber(0xa0, other_oid + b"\xa0\x03\x0c\x05\x61")),
            "otherName wrong value tag": san(_ber(0xa0, other_oid + _ber(0xa1, _ber(0x0c, b"p")))),
            "otherName non-minimal type-id": san(_ber(0xa0, _ber(6, b"\x2b\x80\x06") + _ber(0xa0, _ber(0x0c, b"p")))),
            "x400Address one stray byte": san(b"\xa3\x01\xff"),
            "x400Address beyond 32 elements": san(_ber(0xa3, _ber(0x05, b"") * 33)),
            "ediPartyName one stray byte": san(b"\xa5\x01\xff"),
            "ediPartyName without partyName": san(_ber(0xa5, _ber(0xa0, _ber(0x0c, b"a")))),
            "ediPartyName empty partyName": san(_ber(0xa5, b"\xa1\x00")),
            "ediPartyName partyName of two values": san(_ber(0xa5, _ber(0xa1, _ber(0x0c, b"p") + _ber(0x0c, b"q")))),
            "ediPartyName trailing element": san(_ber(0xa5, _ber(0xa1, _ber(0x0c, b"p")) + _ber(0xa2, _ber(0x0c, b"x")))),
            "ediPartyName empty nameAssigner": san(_ber(0xa5, b"\xa0\x00" + _ber(0xa1, _ber(0x0c, b"p")))),
            "extension OID non-minimal": x509(extra=(x509_extension(b"\x2b\x80\x06\x01", _ber(0x30, b"")),)),
            "key purpose OID non-minimal": x509(eku=(b"\x2b\x06\x01\x05\x05\x07\x03\x80\x01",)),
        }
        for label, der in rejected.items():
            with self.assertRaises(ParseError, msg=label):
                leaf_profile(der)
            observation = inspect(flight(der))
            self.assertEqual((observation.status, observation.encryption, labels(observation, "tls_certificate_")), ("identified", "tls", {}), label)


class ReviewRound3Tests(unittest.TestCase):
    """v0.57 round-3 finding (carried into the v0.58 request): the EC named-curve OID is DER-checked like every other OID."""

    def test_ec_named_curve_oid_is_der(self):
        def leaf_with_curve(parameters):
            spki = _ber(0x30, _ber(0x30, _ber(6, bytes.fromhex("2a8648ce3d0201")) + parameters) + _ber(3, b"\x00\x04" + b"\x22" * 64))
            return x509(signature=ECDSA_SHA256, spki=spki)
        accepted = {"P-256": (_ber(6, bytes.fromhex("2a8648ce3d030107")), "ec-256"),
                    "unknown named curve (secp256k1)": (_ber(6, bytes.fromhex("2b8104000a")), "ec-other"),
                    "multi-octet arc in an unknown curve": (_ber(6, b"\x2b\x81\x00\x01"), "ec-other"),
                    "implicit parameters (NULL)": (_ber(5, b""), "ec-other")}
        for label, (parameters, expected) in accepted.items():
            self.assertEqual(dict(leaf_profile(leaf_with_curve(parameters)))["tls_certificate_key"], expected, label)
        rejected = {"empty OID": b"\x06\x00", "leading 80 00": b"\x06\x02\x80\x00",
                    "non-minimal later arc": b"\x06\x03\x2b\x80\x01", "incomplete final arc": b"\x06\x02\x2b\x86",
                    "OID with a trailing element": _ber(6, bytes.fromhex("2a8648ce3d030107")) + b"\x05\x00"}
        for label, parameters in rejected.items():
            der = leaf_with_curve(parameters)
            with self.assertRaises(ParseError, msg=label):
                leaf_profile(der)
            observation = inspect(flight(der))
            self.assertEqual((observation.status, observation.encryption, labels(observation, "tls_certificate_")), ("identified", "tls", {}), label)


if __name__ == "__main__":
    unittest.main()
