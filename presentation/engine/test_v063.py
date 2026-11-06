"""v0.63: Kerberos encryption types (offered in KDC requests, selected in KDC replies) with the weak-etype risks."""
import random
import unittest

from protocol_engine import DatagramInspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.risks import RISKS
from protocol_engine.windows import ETYPE_CLASSES, WEAK_ETYPE_CLASSES
from protocol_fixtures import KERBEROS, KERBEROS_AS_REP, KERBEROS_TGS_REP, _ber, _krb_principal

FIELDS = ("kerberos_etype_preferred", "kerberos_etype_offered", "kerberos_reply_etype", "kerberos_ticket_etype")
KRB_RISKS = ("kerberos-weak-etype-offered", "kerberos-weak-etype-selected")


def integer(value):
    # Minimal two's-complement length: -128 is one octet (0x80), 128 is two (0x00 0x80).
    return _ber(2, value.to_bytes(((value if value >= 0 else ~value).bit_length() + 8) // 8, "big", signed=True))


def request(etypes=(18, 17), tag=0x6a, body=None):
    if body is None:
        body = (_ber(0xa0, _ber(0x03, b"\x00\x40\x81\x00\x10")) + _ber(0xa2, _ber(0x1b, b"EXAMPLE.ORG"))
                + _ber(0xa5, _ber(0x18, b"20371231235959Z")) + _ber(0xa7, _ber(2, b"\x12\x34\x56\x78"))
                + _ber(0xa8, _ber(0x30, b"".join(integer(e) for e in etypes))))
    msg_type = {0x6a: b"\x0a", 0x6c: b"\x0c"}[tag]
    return _ber(tag, _ber(0x30, _ber(0xa1, _ber(2, b"\x05")) + _ber(0xa2, _ber(2, msg_type)) + _ber(0xa4, _ber(0x30, body))))


def encrypted(etype, cipher=bytes(24)):
    return _ber(0x30, _ber(0xa0, integer(etype)) + _ber(0xa2, _ber(4, cipher)))


def reply(reply_etype=18, ticket_etype=18, tag=0x6d, ticket=None):
    if ticket is None:
        ticket = _ber(0x30, _ber(0xa0, _ber(2, b"\x05")) + _ber(0xa1, _ber(0x1b, b"EXAMPLE.ORG")) + _ber(0xa2, _krb_principal(b"service"))
                      + _ber(0xa3, encrypted(ticket_etype)))
    msg_type = {0x6b: b"\x0b", 0x6d: b"\x0d"}[tag]
    fields = (_ber(0xa0, _ber(2, b"\x05")) + _ber(0xa1, _ber(2, msg_type)) + _ber(0xa3, _ber(0x1b, b"EXAMPLE.ORG"))
              + _ber(0xa4, _krb_principal(b"user")) + _ber(0xa5, _ber(0x61, ticket)) + _ber(0xa6, encrypted(reply_etype, bytes(32))))
    return _ber(tag, _ber(0x30, fields))


def observe(data):
    observation = DatagramInspector().inspect(data)
    rows = {}
    for e in observation.evidence:
        if e.field in FIELDS:
            rows.setdefault(e.field, []).append(e.value)
    return observation, rows


def risks(data):
    return tuple(name for name in classify(observe(data)[0], "udp", 88).risks if name in KRB_RISKS)


class KerberosEtypeTests(unittest.TestCase):
    def test_table_follows_the_iana_registry(self):
        # IANA "Kerberos Encryption Type Numbers", written independently of the module's table.
        self.assertEqual(ETYPE_CLASSES, {1: "des", 2: "des", 3: "des", 5: "des3", 7: "des3", 16: "des3", 17: "aes-sha1", 18: "aes-sha1",
                                         19: "aes-sha2", 20: "aes-sha2", 23: "rc4", 24: "rc4", 25: "camellia", 26: "camellia"})
        self.assertEqual(WEAK_ETYPE_CLASSES, {"des", "des3", "rc4"})

    def test_offered_classes_in_preference_order(self):
        self.assertEqual(observe(KERBEROS)[1], {"kerberos_etype_preferred": ["aes-sha1"], "kerberos_etype_offered": ["aes-sha1"]})
        observation, rows = observe(request((20, 18, 17, 23, 16, 3, 26, -128)))
        self.assertEqual((observation.status, rows["kerberos_etype_preferred"], rows["kerberos_etype_offered"]),
                         ("identified", ["aes-sha2"], ["aes-sha2", "aes-sha1", "rc4", "des3", "des", "camellia", "other"]))
        self.assertEqual(observe(request((23, 18), tag=0x6c))[1]["kerberos_etype_preferred"], ["rc4"])
        self.assertEqual(risks(request((18, 17))), ())
        self.assertEqual(risks(request((18, 17, 23))), ("kerberos-weak-etype-offered",))
        self.assertEqual(risks(request((3,))), ("kerberos-weak-etype-offered",))

    def test_selected_classes_in_replies(self):
        self.assertEqual(observe(KERBEROS_AS_REP)[1], {"kerberos_reply_etype": ["aes-sha1"], "kerberos_ticket_etype": ["aes-sha1"]})
        self.assertEqual(observe(KERBEROS_TGS_REP)[1]["kerberos_ticket_etype"], ["aes-sha1"])
        kerberoastable = reply(reply_etype=18, ticket_etype=23)
        self.assertEqual((observe(kerberoastable)[1]["kerberos_ticket_etype"], risks(kerberoastable)), (["rc4"], ("kerberos-weak-etype-selected",)))
        self.assertEqual(risks(reply(reply_etype=23, ticket_etype=18, tag=0x6b)), ("kerberos-weak-etype-selected",))
        self.assertEqual(risks(reply(reply_etype=20, ticket_etype=19)), ())
        verdict = session_verdict(observe(request((18, 17, 23), tag=0x6c))[0], observe(kerberoastable)[0], "udp", 88, 100, 100)
        self.assertEqual(verdict.risks, KRB_RISKS)
        for name in KRB_RISKS:
            self.assertIn(name, RISKS)

    def test_substructure_faults_drop_labels_but_keep_the_identification(self):
        base = (_ber(0xa0, _ber(0x03, b"\x00\x40\x81\x00\x10")) + _ber(0xa2, _ber(0x1b, b"R")) + _ber(0xa5, _ber(0x18, b"20371231235959Z"))
                + _ber(0xa7, _ber(2, b"\x01")))
        unlabelled = [request(body=base),                                                             # no etype field
                      request(body=base + _ber(0xa8, _ber(0x30, b""))),                              # empty etype list
                      request(body=base + _ber(0xa8, _ber(0x30, _ber(2, b"\x00\x12")))),             # non-minimal Int32
                      request(body=base + _ber(0xa8, _ber(0x30, _ber(2, bytes(5))))),                # longer than Int32
                      request(body=base + _ber(0xa8, _ber(0x30, integer(18) * 33))),                 # more than 32 etypes
                      request(body=_ber(0xa2, _ber(0x1b, b"EXAMPLE.ORG")) + _ber(0xa0, b"\x03\x01\x00") + _ber(0xa7, _ber(2, b"\x01"))
                              + _ber(0xa8, _ber(0x30, integer(18)))),                                       # kdc-options after realm
                      request(body=base.replace(_ber(0xa2, _ber(0x1b, b"R")), b"") + _ber(0xa8, _ber(0x30, integer(18))))]  # realm missing
        for data in unlabelled:
            observation, rows = observe(data)
            self.assertEqual((observation.status, observation.application_protocol, rows), ("identified", "kerberos", {}), data.hex())
        self.assertEqual(observe(request(body=base + _ber(0xa8, _ber(0x30, integer(18) * 32))))[1]["kerberos_etype_offered"], ["aes-sha1"])
        bad_ticket = _ber(0x30, _ber(0xa0, _ber(2, b"\x05")) + _ber(0xa3, encrypted(23)))                # realm and sname missing
        observation, rows = observe(reply(ticket=bad_ticket))
        self.assertEqual((observation.status, rows), ("identified", {"kerberos_reply_etype": ["aes-sha1"]}))
        empty_cipher = _ber(0x30, _ber(0xa0, _ber(2, b"\x05")) + _ber(0xa1, _ber(0x1b, b"EXAMPLE.ORG")) + _ber(0xa2, _krb_principal(b"service"))
                            + _ber(0xa3, encrypted(23, cipher=b"")))
        observation, rows = observe(reply(ticket=empty_cipher))
        self.assertEqual((observation.status, rows), ("identified", {"kerberos_reply_etype": ["aes-sha1"]}))   # empty cipher

    def test_mutations_stay_in_closed_labels(self):
        allowed = set(ETYPE_CLASSES.values()) | {"other"}
        generator = random.Random(63)
        for base in (request((20, 18, 23, 3)), reply(23, 23)):
            for _ in range(400):
                data = bytearray(base)
                data[generator.randrange(len(data))] = generator.randrange(256)
                observation, rows = observe(bytes(data))
                for values in rows.values():
                    self.assertLessEqual(set(values), allowed)
                    self.assertEqual(observation.status, "identified")


if __name__ == "__main__":
    unittest.main()
