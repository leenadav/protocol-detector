"""v0.43: response-direction messages for SNMP (every PDU kind) and DNS (message kind and rcode)."""
import random
import unittest

from analyze_pcap import Analyzer
from make_sample_pcap import udp_frame
from packets import decode_packet
from protocol_engine import Config, DatagramInspector, Inspector
from protocol_engine.appid import classify
from protocol_engine.risks import RISKS
from protocol_fixtures import (DNS, DNS_NXDOMAIN, DNS_RESPONSE, SNMP, SNMP_INFORM, SNMP_RESPONSE, SNMP_SET, SNMP_TRAP_V1, SNMP_TRAP_V2,
                               SNMPV3_DISCOVERY, _ber, snmp_fields, snmp_message)


def inspect(data, hint=None, config=None):
    return DatagramInspector(config).inspect(data, hint)


def fields(observation, prefix):
    return {e.field: e.value for e in observation.evidence if e.field.startswith(prefix)}


SYS_DESCR = _ber(6, b"\x2b\x06\x01\x02\x01\x01\x01\x00")


def binding(value):
    return _ber(0x30, SYS_DESCR + value)


class ResponseDirectionTests(unittest.TestCase):
    def test_snmp_pdu_kinds_and_values_never_emitted(self):
        expected = {SNMP: ("snmp/2c", "get"), SNMP_RESPONSE: ("snmp/2c", "response"), SNMP_SET: ("snmp/2c", "set"), SNMP_INFORM: ("snmp/2c", "inform"),
                    SNMP_TRAP_V2: ("snmp/2c", "trap"), SNMP_TRAP_V1: ("snmp/1", "trap"), SNMPV3_DISCOVERY: ("snmp/3", "get")}
        for data, (protocol, name) in expected.items():
            observation = inspect(data)
            self.assertEqual((observation.status, observation.application_protocol, fields(observation, "snmp_pdu")), ("identified", protocol, {"snmp_pdu": name}), data.hex())
            text = repr(observation)
            for leak in ("placeholder", "public", "c0000209"):
                self.assertNotIn(leak, text)
            self.assertEqual(inspect(data, "snmp").application_protocol, protocol)
        for kind, name in ((0xa0, "get"), (0xa1, "get-next"), (0xa2, "response"), (0xa3, "set"), (0xa4, "trap")):
            body = snmp_fields(bindings=binding(_ber(5, b"") if kind in (0xa0, 0xa1) else _ber(2, b"\x01")))
            if kind == 0xa4:
                body = SNMP_TRAP_V1[SNMP_TRAP_V1.index(b"\xa4") + 2:]
            self.assertEqual(fields(inspect(snmp_message(kind, body, version=0)), "snmp_pdu"), {"snmp_pdu": name}, kind)
        for kind in (0xa5, 0xa6, 0xa7, 0xa8):
            self.assertNotEqual(inspect(snmp_message(kind, snmp_fields(bindings=binding(_ber(2, b"\x01"))), version=0)).status, "identified", kind)  # v1 has no v2 PDUs
        self.assertNotEqual(inspect(snmp_message(0xa4, SNMP_TRAP_V1[SNMP_TRAP_V1.index(b"\xa4") + 2:], version=1)).status, "identified")  # v2c has no v1 trap
        for value in (_ber(0x40, bytes(4)), _ber(0x41, b"\x7f"), _ber(0x42, b"\x00\xff"), _ber(0x43, b"\x01"), _ber(0x44, b"xx"), _ber(0x46, b"\x00" + bytes(8)),
                      _ber(0x80, b""), _ber(0x81, b""), _ber(0x82, b""), _ber(6, b"\x2b\x06"), _ber(4, b""), _ber(5, b"")):
            self.assertEqual(fields(inspect(snmp_message(0xa2, snmp_fields(bindings=binding(value)))), "snmp_pdu"), {"snmp_pdu": "response"}, value.hex())
        response = inspect(snmp_message(0xa2, snmp_fields(status=2, index=1, bindings=binding(_ber(5, b"")))))
        self.assertEqual(fields(response, "snmp_pdu"), {"snmp_pdu": "response"})
        verdict = classify(inspect(SNMP_TRAP_V2), "udp", 162)
        self.assertEqual((verdict.app, verdict.port_usage), ("snmp", "standard"))
        self.assertEqual(classify(inspect(SNMP_RESPONSE), "udp", 161).app, "snmp")

    def test_snmp_rejections(self):
        rejected = [
            snmp_message(0xa2, snmp_fields(status=19, bindings=binding(_ber(5, b"")))),       # error-status beyond RFC 3416
            snmp_message(0xa3, snmp_fields(status=1, bindings=binding(_ber(2, b"\x01")))),     # set with an error status
            snmp_message(0xa6, snmp_fields(index=1, bindings=binding(_ber(2, b"\x01")))),      # inform with an error index
            snmp_message(0xa2, snmp_fields(bindings=binding(_ber(0x40, bytes(3))))),          # IpAddress of three bytes
            snmp_message(0xa2, snmp_fields(bindings=binding(_ber(0x80, b"\x00")))),            # exception with content
            snmp_message(0xa2, snmp_fields(bindings=binding(_ber(0x41, bytes(6))))),           # Counter32 too long
            snmp_message(0xa2, snmp_fields(bindings=binding(_ber(0x46, bytes(10))))),          # Counter64 too long
            snmp_message(0xa2, snmp_fields(bindings=binding(_ber(0x30, b"")))),                # SEQUENCE is not a value
            snmp_message(0xa2, snmp_fields(bindings=binding(_ber(0x45, b"\x01")))),            # NsapAddress is outside the SMI profile
            snmp_message(0xa2, snmp_fields(bindings=binding(b""))),                            # binding without value
            snmp_message(0xa2, snmp_fields(bindings=binding(_ber(2, b"\x01") + _ber(2, b"\x01")))),  # two values
            snmp_message(0xa0, snmp_fields(bindings=binding(_ber(2, b"\x01")))),               # get with a value
            snmp_message(0xa9, snmp_fields(bindings=binding(_ber(5, b"")))),                    # unknown kind
            SNMP_TRAP_V1.replace(b"\x40\x04", b"\x40\x03", 1)[:-1],                            # agent address length
            snmp_message(0xa4, _ber(6, b"\x2b\x06") + _ber(0x40, bytes(4)) + _ber(2, b"\x07") + _ber(2, b"\x00") + _ber(0x43, b"\x00") + _ber(0x30, b""), version=0),  # generic trap 7
            snmp_message(0xa4, _ber(6, b"\x2b\x06") + _ber(0x40, bytes(4)) + _ber(2, b"\x00") + _ber(2, b"\x00") + _ber(2, b"\x00") + _ber(0x30, b""), version=0),      # time stamp tag
            snmp_message(0xa7, snmp_fields(bindings=b"".join(binding(_ber(2, b"\x01")) for _ in range(129)))),    # binding budget
        ]
        for data in rejected:
            observation = inspect(data)
            self.assertNotEqual(observation.status, "identified", (data[:24].hex(), observation.reason))
        self.assertEqual(inspect(rejected[-1]).status, "budget_exhausted")

    def test_dns_message_kind_rcode_and_risk(self):
        query = inspect(DNS)
        self.assertEqual(fields(query, "dns_"), {"dns_message": "query", "dns_query_type": "a"})
        response = inspect(DNS_RESPONSE)
        self.assertEqual((response.application_protocol, fields(response, "dns_")), ("dns", {"dns_message": "response", "dns_rcode": "noerror", "dns_query_type": "a"}))
        self.assertNotIn("192.0.2.1", repr(response))
        nxdomain = inspect(DNS_NXDOMAIN)
        self.assertEqual(fields(nxdomain, "dns_rcode"), {"dns_rcode": "nxdomain"})
        self.assertEqual(classify(nxdomain, "udp", 53).risks, ("dns-error-response",))
        self.assertEqual(classify(response, "udp", 53).risks, ())
        self.assertIn("dns-error-response", RISKS)
        for rcode, label, risky in ((1, "formerr", False), (2, "servfail", True), (5, "refused", True), (9, "notauth", False), (11, "other", False), (15, "other", False)):
            data = DNS_NXDOMAIN[:3] + bytes([0x80 | rcode]) + DNS_NXDOMAIN[4:]
            observation = inspect(data)
            self.assertEqual(fields(observation, "dns_rcode"), {"dns_rcode": label}, rcode)
            self.assertEqual(classify(observation, "udp", 53).risks, ("dns-error-response",) if risky else (), rcode)
        heuristic = inspect(DNS_RESPONSE, config=Config(heuristics=True))
        self.assertTrue({"dns_message", "dns_rcode", "dns_query_shape"} <= set(fields(heuristic, "dns_")))
        tcp = Inspector()
        tcp.feed(len(DNS_NXDOMAIN).to_bytes(2, "big") + DNS_NXDOMAIN)
        self.assertEqual((tcp.observation.application_protocol, fields(tcp.observation, "dns_")), ("dns", {"dns_message": "response", "dns_rcode": "nxdomain", "dns_query_type": "a"}))
        self.assertEqual(classify(tcp.observation, "tcp", 53).risks, ("dns-error-response",))
        # Queries never carry answers, authority records, the AA bit or a response code.
        for mutated in (DNS[:6] + b"\x00\x01" + DNS[8:], DNS[:8] + b"\x00\x01" + DNS[10:], DNS[:2] + b"\x05\x00" + DNS[4:], DNS[:3] + b"\x03" + DNS[4:]):
            self.assertNotEqual(inspect(mutated).status, "identified", mutated[:12].hex())
        client, server = ("192.0.2.10", 52000), ("192.0.2.53", 53)
        frames = [udp_frame(client, server, DNS), udp_frame(server, client, DNS_NXDOMAIN)]
        records = []
        analyzer = Analyzer(on_session=records.append)
        for number, data in enumerate(frames):
            analyzer.process(number, decode_packet(data))
        analyzer.finish("done")
        self.assertEqual((records[0]["app"], records[0]["client_protocol"], records[0]["server_protocol"], records[0]["risks"]), ("dns", "dns", "dns", ["dns-error-response"]))
        only_client = []
        analyzer = Analyzer(on_session=only_client.append)
        analyzer.process(0, decode_packet(frames[0]))
        analyzer.finish("done")
        self.assertEqual((only_client[0]["app"], only_client[0]["server_protocol"], only_client[0]["risks"]), ("dns", None, []))

    def test_mutations_never_raise_or_leak(self):
        generator = random.Random(43)
        for base in (DNS_RESPONSE, DNS_NXDOMAIN, SNMP_RESPONSE, SNMP_SET, SNMP_TRAP_V1, SNMP_TRAP_V2, SNMP_INFORM):
            for _ in range(300):
                data = bytearray(base)
                data[generator.randrange(len(data))] = generator.randrange(256)
                observation = inspect(bytes(data))
                self.assertIn(observation.status, ("identified", "unknown", "malformed", "budget_exhausted"))
                self.assertNotIn("placeholder", repr(observation))


if __name__ == "__main__":
    unittest.main()
