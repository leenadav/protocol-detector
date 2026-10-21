"""v0.38: SNMPv3 message framing (RFC 3412) without exposing users, engines or keys."""
import unittest

from protocol_engine import Config, DatagramInspector
from protocol_engine.appid import classify
from protocol_fixtures import SNMP, SNMPV3_DISCOVERY, SNMPV3_ENCRYPTED, _ber, _snmpv3


def inspect(data, hint=None, config=None):
    return DatagramInspector(config).inspect(data, hint)


def fields(observation, *names):
    return {e.field: e.value for e in observation.evidence if e.field in names}


def scoped(kind=0xa0, bindings=b"", first=b"\x00", second=b"\x00", engine=b"", name=b""):
    pdu = _ber(kind, _ber(2, b"\x01") + _ber(2, first) + _ber(2, second) + _ber(0x30, bindings))
    return _ber(0x30, _ber(4, engine) + _ber(4, name) + pdu)


class SNMPv3Tests(unittest.TestCase):
    def test_discovery_and_encrypted_messages_identify_without_secrets(self):
        discovery = inspect(SNMPV3_DISCOVERY)
        self.assertEqual((discovery.status, discovery.application_protocol), ("identified", "snmp/3"))
        self.assertEqual(fields(discovery, "snmp_security", "snmp_scoped_pdu", "snmp_flags"), {"snmp_security": "usm", "snmp_scoped_pdu": "plaintext", "snmp_flags": "reportable"})
        encrypted = inspect(SNMPV3_ENCRYPTED)
        self.assertEqual(fields(encrypted, "snmp_security", "snmp_scoped_pdu", "snmp_flags"), {"snmp_security": "usm", "snmp_scoped_pdu": "encrypted", "snmp_flags": "authprivreportable"})
        self.assertNotIn("operator", repr(encrypted))
        self.assertNotIn("1f88", repr(encrypted))
        self.assertEqual(inspect(SNMP).application_protocol, "snmp/2c")
        self.assertEqual(inspect(SNMPV3_DISCOVERY, "snmp").application_protocol, "snmp/3")
        verdict = classify(encrypted, "udp", 161)
        self.assertEqual((verdict.app, verdict.port_usage, verdict.risks), ("snmp", "standard", ()))
        self.assertEqual(classify(discovery, "udp", 161).risks, ())
        self.assertEqual(classify(inspect(SNMP), "udp", 161).risks, ("cleartext-credential-protocol",))  # community string
        binding = _ber(0x30, _ber(6, b"\x2b\x06\x01\x02\x01\x01\x01\x00") + _ber(5, b""))
        report_binding = _ber(0x30, _ber(6, b"\x2b\x06\x01\x06\x03\x0f\x01\x01\x04\x00") + _ber(0x41, b"\x05"))
        for message in (_snmpv3(0x04, b"", b"", b"", b"", scoped(0xa1, binding)),
                        _snmpv3(0x05, b"\x80\x00\x00\x01", b"u", bytes(12), b"", scoped(0xa5, binding * 3, b"\x00", b"\x0a")),
                        _snmpv3(0x00, b"\x80\x00\x00\x01", b"", b"", b"", scoped(0xa8, report_binding, b"\x00", b"\x00", b"\x80\x00\x00\x01")),
                        _snmpv3(0x04, b"", b"", b"", b"", scoped(0xa0, binding * 128))):
            self.assertEqual(inspect(message).application_protocol, "snmp/3", message.hex())

    def test_rejections(self):
        binding = _ber(0x30, _ber(6, b"\x2b\x06\x01\x02\x01\x01\x01\x00") + _ber(5, b""))
        rejected = [
            _snmpv3(0x02, b"", b"", b"", b"", scoped()),                                   # privacy without authentication
            _snmpv3(0x08, b"", b"", b"", b"", scoped()),                                   # reserved flag bit
            _snmpv3(0x01, b"\x80\x00\x00\x01", b"u", b"", b"", scoped()),                   # auth flag without parameters
            _snmpv3(0x03, b"\x80\x00\x00\x01", b"u", bytes(12), b"", _ber(4, bytes(8))),   # priv flag without parameters
            _snmpv3(0x03, b"\x80\x00\x00\x01", b"u", bytes(12), bytes(8), _ber(4, b"")),   # empty encrypted PDU
            _snmpv3(0x03, b"\x80\x00\x00\x01", b"u", bytes(12), bytes(8), scoped()),       # plaintext PDU under privacy
            _snmpv3(0x04, b"x" * 33, b"", b"", b"", scoped()),                             # engine id too long
            _snmpv3(0x04, b"", b"u" * 33, b"", b"", scoped()),                             # user too long
            _snmpv3(0x04, b"", b"", b"", b"", scoped(0xa3, binding)),                      # Set request outside the profile
            _snmpv3(0x04, b"", b"", b"", b"", scoped(0xa0, binding, b"\x01")),             # error status on a request
            _snmpv3(0x04, b"", b"", b"", b"", scoped(0xa0, _ber(0x30, _ber(6, b"\x2b\x06") + _ber(4, b"v")))),  # value instead of NULL
            _snmpv3(0x04, b"", b"", b"", b"", scoped(0xa0, binding * 129)),                # binding budget
            SNMPV3_DISCOVERY + b"\x00", SNMPV3_DISCOVERY[:-1],
            _snmpv3(0x04, b"", b"", b"", b"", scoped()).replace(b"\x02\x03\x00\xff\xe3", b"\x02\x02\x01\x00"),  # msgMaxSize 256 < 484
            _snmpv3(0x04, b"", b"", b"", b"", scoped()).replace(b"\x02\x01\x03\x04", b"\x02\x01\x00\x04", 1),   # security model 0
        ]
        for data in rejected:
            result = inspect(data)
            self.assertNotEqual(result.status, "identified", data.hex())
        self.assertEqual(inspect(_snmpv3(0x04, b"", b"", b"", b"", scoped(0xa0, binding * 129))).status, "budget_exhausted")
        other_model = _ber(0x30, _ber(2, b"\x03") + _ber(0x30, _ber(2, b"\x01") + _ber(2, b"\x00\xff\xe3") + _ber(4, b"\x04") + _ber(2, b"\x04")) + _ber(4, b"") + scoped())
        self.assertEqual(fields(inspect(other_model), "snmp_security"), {"snmp_security": "model-4"})
        self.assertEqual(inspect(_ber(0x30, _ber(2, b"\x02") + _ber(4, b"c") + scoped())).status, "unknown")  # version 2 (not 2c) stays outside
        self.assertEqual(inspect(SNMPV3_ENCRYPTED, config=Config(max_headers=1)).application_protocol, "snmp/3")


if __name__ == "__main__":
    unittest.main()
