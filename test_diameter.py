"""Diameter capabilities exchange: header flags, AVP framing, mandatory AVPs, result classes, isolation."""
import random
import unittest

from protocol_engine import Config, Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.diameter import result_class
from protocol_fixtures import DIAMETER_CAPABILITIES, DIAMETER_CEA, DIAMETER_CER, STREAM_CASES, diameter_avp, diameter_message, xdr


def values(observation):
    return {e.field: e.value for e in observation.evidence}


def inspect(data, config=None):
    inspector = Inspector(config)
    inspector.feed(data)
    return inspector


def without(code):
    return tuple(avp for avp in DIAMETER_CAPABILITIES if int.from_bytes(avp[:4], "big") != code)


class DiameterTests(unittest.TestCase):
    def test_fixtures_identify_at_the_last_byte_with_closed_evidence(self):
        cer = inspect(DIAMETER_CER).observation
        self.assertEqual((cer.status, cer.application_protocol, cer.scope, values(cer)["diameter_message"]), ("identified", "diameter", "negotiation_request", "cer"))
        cea = inspect(DIAMETER_CEA).observation
        self.assertEqual((cea.scope, values(cea)["diameter_message"], values(cea)["diameter_result"]), ("negotiation_response", "cea", "success"))
        for observation in (cer, cea):
            text = repr(observation)
            for secret in ("peer.example", "example", "demo-stack", "192"):
                self.assertNotIn(secret, text)
            self.assertEqual(classify(observation).app, "diameter")
        verdict = session_verdict(cer, cea, "tcp", 3868)
        self.assertEqual((verdict.app, verdict.port_usage, verdict.category), ("diameter", "standard", "business-systems"))
        for data in (DIAMETER_CER, DIAMETER_CEA):
            for end in range(len(data)):
                self.assertEqual(inspect(data[:end]).observation.status, "detecting", end)
            expected = inspect(data).observation
            for split in range(len(data) + 1):
                inspector = Inspector()
                inspector.feed(data[:split])
                inspector.feed(data[split:])
                self.assertEqual(inspector.observation, expected, split)

    def test_result_code_classes(self):
        for code, label in ((1001, "informational"), (2001, "success"), (2002, "success"), (3001, "protocol-error"), (4001, "transient-failure"),
                            (5010, "permanent-failure")):
            self.assertEqual(result_class(code), label)
            data = diameter_message(0x20 if code >= 3000 else 0, (diameter_avp(268, xdr(code)),) + DIAMETER_CAPABILITIES)
            self.assertEqual(values(inspect(data).observation)["diameter_result"], label, code)
        for code in (0, 999, 6000, 70000):
            data = diameter_message(0, (diameter_avp(268, xdr(code)),) + DIAMETER_CAPABILITIES)
            self.assertEqual(inspect(data).observation.status, "malformed", code)

    def test_header_rules(self):
        body = b"".join(DIAMETER_CAPABILITIES)
        for data, status in ((b"\x02" + DIAMETER_CER[1:], "unknown"),                                   # version 2
                             (diameter_message(0x80, DIAMETER_CAPABILITIES, code=280), "unknown"),      # DWR outside the profile
                             (diameter_message(0x80, DIAMETER_CAPABILITIES, application=4), "unknown"),
                             (diameter_message(0x81, DIAMETER_CAPABILITIES), "unknown"),                # reserved flag: never routed
                             (diameter_message(0xc0, DIAMETER_CAPABILITIES), "malformed"),              # proxiable
                             (diameter_message(0xa0, DIAMETER_CAPABILITIES), "malformed"),              # request with error
                             (diameter_message(0x10, (diameter_avp(268, xdr(2001)),) + DIAMETER_CAPABILITIES), "malformed"),   # answer with T
                             (DIAMETER_CER[:1] + (len(DIAMETER_CER) + 1).to_bytes(3, "big") + DIAMETER_CER[4:], "malformed"),
                             (DIAMETER_CER[:1] + (16).to_bytes(3, "big") + DIAMETER_CER[4:], "malformed")):
            self.assertEqual(inspect(data).observation.status, status, data[:8])
        self.assertEqual(inspect(DIAMETER_CER, Config(max_bytes=64)).observation.status, "budget_exhausted")
        self.assertEqual(len(body) % 4, 0)

    def test_avp_rules(self):
        cases = (
            (without(264), "malformed"), (without(296), "malformed"), (without(257), "malformed"), (without(266), "malformed"), (without(269), "malformed"),
            (DIAMETER_CAPABILITIES + (diameter_avp(264, b"again.example"),), "malformed"),          # Origin-Host twice
            (without(264) + (diameter_avp(264, b"peer.example", flags=0),), "malformed"),           # mandatory AVP without M
            (without(264) + (diameter_avp(264, b"has space"),), "malformed"),
            (without(264) + (diameter_avp(264, b""),), "malformed"),
            (without(264) + (diameter_avp(264, b"x" * 256),), "malformed"),
            (without(257) + (diameter_avp(257, b"\x00\x01\x0a\x00"),), "malformed"),                # IPv4 with 2 bytes
            (without(257) + (diameter_avp(257, b"\x00\x02" + bytes(16)),), "identified"),           # IPv6
            (without(257) + (diameter_avp(257, b"\x00\x03" + bytes(4)),), "malformed"),
            (without(266) + (diameter_avp(266, b"\x00\x00\x01"),), "malformed"),                    # Unsigned32 with 3 bytes
            (DIAMETER_CAPABILITIES + (diameter_avp(257, b"\x00\x01" + bytes((10, 0, 0, 1))),), "identified"),   # several Host-IP-Address
            (DIAMETER_CAPABILITIES + (diameter_avp(265, xdr(10415)), diameter_avp(265, xdr(13019))), "identified"),
            (DIAMETER_CAPABILITIES + (diameter_avp(1, xdr(7), vendor=10415),), "identified"),       # vendor-specific AVP, not validated
            (DIAMETER_CAPABILITIES + (diameter_avp(260, diameter_avp(266, xdr(10415)) + diameter_avp(258, xdr(16777251))),), "identified"),
            (DIAMETER_CAPABILITIES + (diameter_avp(999, b"abc", flags=0x41),), "malformed"),        # reserved AVP flag
            (DIAMETER_CAPABILITIES + (diameter_avp(999, b"abc")[:-1] + b"\x01",), "malformed"),     # non-zero padding
            (DIAMETER_CAPABILITIES + (b"\x00\x00\x03\xe7\x00\x00\x00\x04",), "malformed"),          # AVP length 4 < header
            (DIAMETER_CAPABILITIES + (b"\x00\x00\x03\xe7\x00\x00\x00\x40",), "malformed"),          # AVP beyond the message
            (DIAMETER_CAPABILITIES + (b"\x00\x00\x03\xe7",), "malformed"),                          # truncated AVP header
        )
        for avps, status in cases:
            self.assertEqual(inspect(diameter_message(0x80, avps)).observation.status, status, avps[-1][:12])
        many = DIAMETER_CAPABILITIES + tuple(diameter_avp(265, xdr(i)) for i in range(130))
        self.assertEqual(inspect(diameter_message(0x80, many)).observation.status, "budget_exhausted")
        self.assertEqual(inspect(diameter_message(0x80, many[:120])).observation.status, "identified")
        self.assertEqual(inspect(diameter_message(0x80, many[:10]), Config(max_headers=4)).observation.status, "budget_exhausted")
        self.assertEqual(inspect(diameter_message(0, DIAMETER_CAPABILITIES)).observation.status, "malformed")   # CEA without Result-Code

    def test_isolation_from_neighbours_and_mutations(self):
        for data, protocol in STREAM_CASES:
            if protocol != "diameter" and data[:1] == b"\x01":
                self.assertEqual(inspect(data).observation.application_protocol, protocol)
        rng = random.Random(5152)
        for base in (DIAMETER_CER, DIAMETER_CEA):
            for _ in range(600):
                data = bytearray(base)
                for _ in range(rng.randrange(1, 4)):
                    data[rng.randrange(len(data))] = rng.randrange(256)
                inspector = Inspector()
                inspector.feed(bytes(data))
                inspector.end()
                self.assertIn(inspector.observation.status, ("identified", "unknown", "malformed", "incomplete", "budget_exhausted"))
                self.assertLessEqual(inspector.metrics.bytes_inspected, len(data))
                self.assertNotIn("demo-stack", repr(inspector.observation))


if __name__ == "__main__":
    unittest.main()
