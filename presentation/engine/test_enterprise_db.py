"""v0.40: MSSQL TDS PRELOGIN and Oracle Net (TNS) connect packets, both directions.

Instance names, connect descriptors, thread/trace identifiers and nonces are
framing only and never appear in observations.
"""
import random
import unittest

from protocol_engine import Config, Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.dispatch import select
from protocol_engine.enterprise_db import tns_probe
from protocol_fixtures import (CQL, DNS_TCP, MODBUS, TDS_PRELOGIN, TDS_PRELOGIN_RESPONSE, TNS_ACCEPT, TNS_CONNECT, TNS_CONNECT_DEFERRED,
                               TNS_DESCRIPTOR, TNS_REFUSE, TNS_REFUSE_TEXT, TNS_RESEND, tds_prelogin, tns_connect, tns_packet)

SECRETS = ("placeholder", "12514", "VSNNUM")


def inspect(data, config=None, hint=None):
    inspector = Inspector(config, protocol_hint=hint)
    inspector.feed(data)
    return inspector


def fields(observation, prefix):
    return {e.field: e.value for e in observation.evidence if e.field.startswith(prefix)}


class EnterpriseDatabaseTests(unittest.TestCase):
    def assert_identified(self, data, protocol, scope, **expected):
        observation = inspect(data).observation
        self.assertEqual((observation.status, observation.application_protocol, observation.scope), ("identified", protocol, scope), observation)
        found = fields(observation, protocol + "_")
        for key, value in expected.items():
            self.assertEqual(found.get(key), value, (key, found))
        text = repr(observation)
        for secret in SECRETS:
            self.assertNotIn(secret, text)
        return observation

    def assert_rejected(self, data, hint=None):
        observation = inspect(data, hint=hint).observation
        self.assertNotEqual(observation.status, "identified", (data[:16].hex(), observation))
        return observation

    def test_tds_prelogin_both_directions(self):
        client = self.assert_identified(TDS_PRELOGIN, "tds", "negotiation_request", tds_encryption="off", tds_mars="off", tds_federated_auth="no")
        server = self.assert_identified(TDS_PRELOGIN_RESPONSE, "tds", "negotiation_response", tds_encryption="on")
        self.assertEqual(fields(server, "tds_"), {"tds_encryption": "on", "tds_mars": "off", "tds_federated_auth": "no"})
        verdict = session_verdict(client, server, "tcp", 1433, 94, 49, True, None)
        self.assertEqual((verdict.app, verdict.port_usage, verdict.category, verdict.subcategory, verdict.risks), ("mssql-db", "standard", "business-systems", "database", ()))
        self.assertEqual(classify(client, "tcp", 1434).risks, ("nonstandard-port",))
        for encryption, label in ((b"\x01", "on"), (b"\x02", "not-supported"), (b"\x03", "required")):
            data = tds_prelogin(((0x00, bytes(6)), (0x01, encryption)))
            self.assert_identified(data, "tds", "negotiation_request", tds_encryption=label)
            self.assertEqual(fields(inspect(data).observation, "tds_"), {"tds_encryption": label})
        with_instance = tds_prelogin(((0x00, bytes(6)), (0x01, b"\x00"), (0x02, b"placeholder\x00"), (0x04, b"\x01"), (0x06, b"\x01"), (0x07, bytes(32))))
        self.assert_identified(with_instance, "tds", "negotiation_request", tds_mars="on", tds_federated_auth="yes")
        # Options may be listed in any order and data regions may be placed anywhere after the table.
        reordered = tds_prelogin(((0x01, b"\x03"), (0x00, bytes(6))))
        self.assert_identified(reordered, "tds", "negotiation_request", tds_encryption="required")
        self.assertEqual(inspect(TDS_PRELOGIN, hint="tds").observation.application_protocol, "tds")
        self.assertEqual(inspect(TDS_PRELOGIN, Config(max_bytes=64)).observation.status, "budget_exhausted")

    def test_tds_rejections(self):
        base = tds_prelogin()
        rejected = [
            tds_prelogin(kind=0x10),                                            # LOGIN7 is outside the profile
            tds_prelogin(status=0x00),                                          # not end of message
            tds_prelogin(status=0x21),                                          # unknown status bit
            tds_prelogin(window=1),
            tds_prelogin(spid=7),                                               # client SPID must be zero
            tds_prelogin(((0x01, b"\x00"),)),                                   # VERSION missing
            tds_prelogin(((0x00, bytes(6)),)),                                  # ENCRYPTION missing
            tds_prelogin(((0x00, bytes(5)), (0x01, b"\x00"))),                  # VERSION length
            tds_prelogin(((0x00, bytes(6)), (0x01, b"\x00\x00"))),              # ENCRYPTION length
            tds_prelogin(((0x00, bytes(6)), (0x01, b"\x05"))),                  # ENCRYPTION value outside the profile
            tds_prelogin(((0x00, bytes(6)), (0x01, b"\x00"), (0x00, bytes(6)))),  # repeated token
            tds_prelogin(((0x00, bytes(6)), (0x01, b"\x00"), (0x08, b"\x00"))),  # unknown token
            tds_prelogin(((0x00, bytes(6)), (0x01, b"\x00"), (0x02, b"ab"))),    # INSTOPT not terminated
            tds_prelogin(((0x00, bytes(6)), (0x01, b"\x00"), (0x03, bytes(3)))),  # THREADID length
            tds_prelogin(((0x00, bytes(6)), (0x01, b"\x00"), (0x04, b"\x02"))),  # MARS value
            tds_prelogin(((0x00, bytes(6)), (0x01, b"\x00"), (0x05, bytes(35)))),  # TRACEID length
            tds_prelogin(((0x00, bytes(6)), (0x01, b"\x00"), (0x06, b"\x02"))),  # FEDAUTHREQUIRED value
            tds_prelogin(((0x00, bytes(6)), (0x01, b"\x00"), (0x07, bytes(31)))),  # NONCE length
            base[:8] + base[8:9] + (len(base) - 8).to_bytes(2, "big") + base[11:],  # option data beyond the packet
            base[:8] + base[8:9] + b"\x00\x02" + base[11:],                     # option data inside the table
            base[:2] + (len(base) + 1).to_bytes(2, "big") + base[4:] + b"\x00",  # trailing byte after the data
            base[:2] + b"\x00\x13" + base[4:19],                                 # shorter than the mandatory options
            base[:2] + b"\x10\x01" + base[4:],                                   # beyond the 4 KiB profile size
            b"\x12\x01\x00\x0c\x00\x00\x01\x00\x00\x00\x00\x00",                 # no terminator before the data
        ]
        for data in rejected:
            self.assert_rejected(data)
            self.assert_rejected(data, hint="tds")
        self.assertNotEqual(inspect(tds_prelogin(kind=0x10)).observation.application_protocol, "tds")   # LOGIN7 first byte routes elsewhere

    def test_tns_connect_and_server_replies(self):
        self.assert_identified(TNS_CONNECT, "tns", "negotiation_request", tns_version="316", tns_connect_data="inline")
        self.assert_identified(TNS_CONNECT_DEFERRED, "tns", "negotiation_request", tns_version="316", tns_connect_data="deferred")
        self.assert_identified(TNS_ACCEPT, "tns", "negotiation_response", tns_response="accept", tns_version="316")
        self.assert_identified(TNS_RESEND, "tns", "negotiation_response", tns_response="resend")
        self.assert_identified(TNS_REFUSE, "tns", "negotiation_response", tns_response="refuse")
        for version in (0x0134, 0x013a, 0x013f):
            self.assert_identified(tns_connect(version=version), "tns", "negotiation_request", tns_version=str(version))
        self.assert_identified(tns_connect(offset=34), "tns", "negotiation_request", tns_connect_data="inline")
        self.assert_identified(tns_connect(marker=b"\x01\x00"), "tns", "negotiation_request")
        self.assert_identified(tns_packet(4, b"\x22\x00\x00\x00"), "tns", "negotiation_response", tns_response="refuse")
        client, server = inspect(TNS_CONNECT).observation, inspect(TNS_ACCEPT).observation
        verdict = session_verdict(client, server, "tcp", 1521, 229, 32, True, None)
        self.assertEqual((verdict.app, verdict.port_usage, verdict.subcategory, verdict.risks), ("oracle", "standard", "database", ()))
        self.assertEqual(inspect(TNS_CONNECT, hint="tns").observation.application_protocol, "tns")
        self.assertEqual(inspect(TNS_CONNECT, Config(max_bytes=64)).observation.status, "budget_exhausted")

    def test_tns_rejections(self):
        rejected = [
            tns_connect(version=0x0133), tns_connect(version=0x0140),            # version outside 308..319
            tns_connect(compatible=0x012d),                                      # version-compatible must be 300
            tns_connect(marker=b"\x00\x02"),                                     # byte-order marker
            tns_connect(offset=33), tns_connect(offset=75),                      # connect data offset range
            tns_connect(descriptor=b""),                                         # no descriptor
            tns_connect(descriptor=b"DESCRIPTION"),                              # not parenthesised
            tns_connect(descriptor=b"(DESCRIPTION=\x01)"),                       # not printable
            TNS_CONNECT[:-1],                                                    # incomplete stays detecting
            TNS_CONNECT[:2] + b"\x00\x01" + TNS_CONNECT[4:],                     # packet checksum
            TNS_CONNECT[:5] + b"\x01" + TNS_CONNECT[6:],                         # reserved byte
            TNS_CONNECT[:6] + b"\x00\x01" + TNS_CONNECT[8:],                     # header checksum
            tns_packet(3, bytes(30)),                                            # ACK/other types are outside the profile
            tns_packet(11, b"\x00"),                                             # RESEND with body
            tns_packet(4, b"\x22\x00\x00\x05(ERR)x"),                            # REFUSE length mismatch
            tns_packet(4, b"\x22\x00\x00\x03abc"),                               # REFUSE data not a descriptor
            tns_packet(2, b"\x01\x3c" + bytes(6) + b"\x00\x02" + bytes(14)),     # ACCEPT marker
            tns_packet(2, b"\x01\x40" + bytes(6) + b"\x00\x01" + bytes(14)),     # ACCEPT version
            tns_packet(2, b"\x01\x3c" + bytes(6) + b"\x00\x01" + b"\x00\x04\x00\x10" + bytes(12)),  # ACCEPT data region
            b"\x20\x01\x00\x00\x01\x00\x00\x00" + bytes(40),                      # beyond the 8 KiB profile size
        ]
        for data in rejected:
            observation = self.assert_rejected(data)
            if data is TNS_CONNECT[:-1]:
                self.assertEqual(observation.status, "detecting")
        trailing = inspect(TNS_CONNECT + b"x").observation
        self.assertEqual((trailing.status, trailing.application_protocol), ("identified", "tns"))  # next message is not consumed

    def test_dispatch_neighbours_are_unchanged(self):
        self.assertEqual(select(TDS_PRELOGIN[:24]), "tds")
        self.assertEqual(select(TDS_PRELOGIN_RESPONSE[:24]), "tds")
        self.assertEqual(select(CQL[:24]), "cql")
        self.assertEqual(select(b"\x04\x01" + bytes(7)), "tds")           # compressed CQL with a 64 KiB-aligned body never occurs
        self.assertEqual(select(b"\x04\x01\x00\x01\x07\x00\x00\x00\x20"), "cql")
        self.assertEqual(select(b"\x04\x00\x00\x00\x00"), "ethernet-ip")
        self.assertEqual(select(TNS_CONNECT[:24]), "tns")
        self.assertEqual(select(TNS_RESEND), "tns")
        self.assertIsNone(select(TNS_CONNECT[:9]))
        self.assertEqual(select(DNS_TCP[:24]), "dns")
        self.assertEqual(select(MODBUS[:24]), "modbus")
        self.assertEqual(inspect(CQL).observation.application_protocol, "cql/4")
        self.assertEqual(inspect(DNS_TCP).observation.application_protocol, "dns")
        self.assertFalse(tns_probe(b"\x00\x08\x00\x00\x0b\x00\x00"))
        self.assertTrue(tns_probe(b"\x00\x08\x00\x00\x0b\x00\x00\x00"))
        self.assertFalse(tns_probe(b"\x00\x40\x00\x00\x01\x00\x00\x00\x01"))

    def test_mutations_never_raise_and_never_leak(self):
        generator = random.Random(40)
        for base in (TDS_PRELOGIN, TDS_PRELOGIN_RESPONSE, TNS_CONNECT, TNS_ACCEPT, TNS_REFUSE):
            for _ in range(300):
                data = bytearray(base)
                for _ in range(generator.randint(1, 3)):
                    data[generator.randrange(len(data))] = generator.randrange(256)
                inspector = inspect(bytes(data))
                self.assertIn(inspector.observation.status, ("identified", "unknown", "malformed", "detecting", "budget_exhausted"))
                self.assertLessEqual(inspector.metrics.bytes_inspected, len(data))
                text = repr(inspector.observation)
                self.assertNotIn(TNS_DESCRIPTOR[:20].decode(), text)
                self.assertNotIn(TNS_REFUSE_TEXT[:12].decode(), text)


if __name__ == "__main__":
    unittest.main()
