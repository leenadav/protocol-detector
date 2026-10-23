"""v0.62: SNMPv3 security level (RFC 3411) and the unauthenticated / no-privacy risks with the RFC 3414 exemptions."""
import random
import unittest

from protocol_engine import DatagramInspector
from protocol_engine.appid import classify
from protocol_engine.risks import RISKS
from protocol_fixtures import SNMP, SNMPV3_DISCOVERY, SNMPV3_ENCRYPTED, _ber, _snmpv3

ENGINE = b"\x80\x00\x1f\x88\x80\x01\x02\x03\x04"
BINDING = _ber(0x30, _ber(6, b"\x2b\x06\x01\x02\x01\x01\x01\x00") + _ber(5, b""))
SNMP_RISKS = ("snmpv3-unauthenticated", "snmpv3-no-privacy")


def scoped(kind=0xa0, bindings=BINDING, engine=ENGINE):
    pdu = _ber(kind, _ber(2, b"\x01") + _ber(2, b"\x00") + _ber(2, b"\x00") + _ber(0x30, bindings))
    return _ber(0x30, _ber(4, engine) + _ber(4, b"") + pdu)


def observe(data):
    return DatagramInspector().inspect(data)


def labels(observation):
    return {e.field: e.value for e in observation.evidence if e.field in ("snmp_security_level", "snmp_usm_discovery")}


def risks(observation):
    return tuple(name for name in classify(observation, "udp", 161).risks if name in SNMP_RISKS)


class SnmpSecurityLevelTests(unittest.TestCase):
    def test_levels_follow_msg_flags(self):
        cases = ((_snmpv3(0x04, ENGINE, b"operator", b"", b"", scoped()), "no-auth-no-priv", ("snmpv3-unauthenticated",)),
                 (_snmpv3(0x05, ENGINE, b"operator", bytes(12), b"", scoped()), "auth-no-priv", ("snmpv3-no-privacy",)),
                 (SNMPV3_ENCRYPTED, "auth-priv", ()))
        for data, level, expected in cases:
            observation = observe(data)
            self.assertEqual((observation.status, labels(observation), risks(observation)),
                             ("identified", {"snmp_security_level": level}, expected), level)
        self.assertEqual(labels(observe(SNMP)), {})                              # v1/v2c carry no securityLevel
        self.assertEqual(risks(observe(SNMP)), ())

    def test_discovery_and_reports_are_exempt(self):
        discovery = observe(SNMPV3_DISCOVERY)
        self.assertEqual((labels(discovery), risks(discovery)),
                         ({"snmp_security_level": "no-auth-no-priv", "snmp_usm_discovery": "request"}, ()))
        report_binding = _ber(0x30, _ber(6, b"\x2b\x06\x01\x06\x03\x0f\x01\x01\x04\x00") + _ber(0x41, b"\x05"))
        report = observe(_snmpv3(0x00, ENGINE, b"", b"", b"", scoped(0xa8, report_binding)))       # usmStatsUnknownEngineIDs
        self.assertEqual((labels(report), risks(report)), ({"snmp_security_level": "no-auth-no-priv"}, ()))
        timed = observe(_snmpv3(0x01, ENGINE, b"operator", bytes(12), b"", scoped(0xa8, report_binding)))  # time-window report
        self.assertEqual(risks(timed), ())
        # An empty engine ID with authentication is not a discovery request.
        authenticated = observe(_snmpv3(0x05, b"", b"operator", bytes(12), b"", scoped(engine=b"")))
        self.assertEqual((labels(authenticated), risks(authenticated)), ({"snmp_security_level": "auth-no-priv"}, ("snmpv3-no-privacy",)))
        for name in SNMP_RISKS:
            self.assertIn(name, RISKS)

    def test_mutations_stay_in_closed_labels(self):
        generator = random.Random(62)
        allowed = {"snmp_security_level": {"no-auth-no-priv", "auth-no-priv", "auth-priv"}, "snmp_usm_discovery": {"request"}}
        for base in (SNMPV3_DISCOVERY, SNMPV3_ENCRYPTED, _snmpv3(0x05, ENGINE, b"operator", bytes(12), b"", scoped())):
            for _ in range(300):
                data = bytearray(base)
                data[generator.randrange(len(data))] = generator.randrange(256)
                observation = observe(bytes(data))
                for name, value in labels(observation).items():
                    self.assertIn(value, allowed[name])
                    self.assertEqual(observation.application_protocol, "snmp/3")


if __name__ == "__main__":
    unittest.main()
