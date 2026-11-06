"""v0.59: smart-home LAN datagrams (LIFX LAN, Tuya LAN 3.3, TP-Link Smart Home) and multicast DNS layouts seen in real captures."""
import random
import unittest

from protocol_engine import Config
from protocol_engine.appid import classify
from protocol_engine.datagram import DatagramInspector
from protocol_fixtures import (DNS, KASA_REPLY, KASA_SYSINFO, LIFX_GET_SERVICE, LIFX_GET_VERSION, LIFX_STATE_SERVICE, MDNS_QUERY_AA,
                               MDNS_REVERSE_PROBE, MDNS_SRV_POINTER, TUYA_UDP_NEW, kasa, lifx, tuya)

NEW = ((LIFX_GET_SERVICE, "lifx-lan"), (LIFX_STATE_SERVICE, "lifx-lan"), (LIFX_GET_VERSION, "lifx-lan"),
       (TUYA_UDP_NEW, "tuya-lan"), (KASA_SYSINFO, "tplink-smarthome"), (KASA_REPLY, "tplink-smarthome"))
ALLOWED = {"identified", "unknown", "malformed", "budget_exhausted"}


def datagram(data, hint=None, config=None):
    return DatagramInspector(config).inspect(data, hint)


def fields(observation, *names):
    return {e.field: e.value for e in observation.evidence if e.field in names}


class SmartHomeProfileTests(unittest.TestCase):
    def test_fixtures_identify_without_hints(self):
        for data, protocol in NEW:
            observation = datagram(data)
            self.assertEqual((observation.status, observation.application_protocol), ("identified", protocol), protocol)
            self.assertEqual(classify(observation, "udp").app, protocol)

    def test_evidence_is_fixed_vocabulary(self):
        self.assertEqual(fields(datagram(LIFX_GET_SERVICE), "lifx_message", "lifx_tagged"), {"lifx_message": "getservice", "lifx_tagged": "yes"})
        self.assertEqual(fields(datagram(LIFX_STATE_SERVICE), "lifx_message"), {"lifx_message": "stateservice"})
        self.assertEqual(fields(datagram(TUYA_UDP_NEW), "tuya_command"), {"tuya_command": "udp-new"})
        self.assertEqual(fields(datagram(KASA_SYSINFO), "tplink_module", "tplink_modules"), {"tplink_module": "system", "tplink_modules": "2"})
        text = repr(datagram(KASA_REPLY))
        self.assertNotIn("placeholder", text)          # device alias never emitted

    def test_every_truncation_fails_closed(self):
        for data, protocol in NEW:
            for cut in range(len(data)):
                observation = datagram(data[:cut])
                self.assertNotEqual(observation.application_protocol, protocol, (protocol, cut))

    def test_mutations_never_crash(self):
        rng = random.Random(59)
        for data, protocol in NEW:
            for _ in range(300):
                mutated = bytearray(data)
                for _ in range(rng.randint(1, 3)):
                    mutated[rng.randrange(len(mutated))] = rng.randrange(256)
                self.assertIn(datagram(bytes(mutated)).status, ALLOWED)

    def test_lifx_rules(self):
        self.assertEqual(datagram(LIFX_GET_SERVICE[:-1] + b"\x01").status, "malformed")               # reserved word after the type must be zero
        self.assertNotEqual(datagram(lifx(2, b"\x00")).status, "identified")                          # GetService carries no payload
        self.assertNotEqual(datagram(lifx(2, tagged=True, target=b"\x01" + bytes(5))).status, "identified")   # tagged needs zero target
        self.assertEqual(datagram(lifx(999, b"\x00\x01")).status, "identified")                        # unknown type: size unchecked
        self.assertEqual(fields(datagram(lifx(999)), "lifx_message"), {"lifx_message": "other"})
        self.assertNotEqual(datagram(lifx(0)).status, "identified")

    def test_tuya_rules(self):
        bad_crc = bytearray(TUYA_UDP_NEW)
        bad_crc[-5] ^= 1
        self.assertEqual(datagram(bytes(bad_crc)).status, "malformed")
        self.assertEqual(fields(datagram(tuya(0x77, b"\x00" * 4)), "tuya_command"), {"tuya_command": "other"})

    def test_kasa_rules_and_budget(self):
        self.assertNotEqual(datagram(kasa(b'{"unknown_module":{}}')).status, "identified")
        self.assertNotEqual(datagram(kasa(b'{"system":1}')).status, "identified")
        self.assertNotEqual(datagram(kasa(b'{"system":{}} trailing')).status, "identified")
        deep = b'{"system":' + b'{"a":' * 9 + b'{}' + b'}' * 9 + b'}'
        self.assertEqual(datagram(kasa(deep)).status, "malformed")                                    # nesting budget
        self.assertEqual(datagram(KASA_SYSINFO, config=Config(max_bytes=64)).status, "identified")
        self.assertEqual(datagram(kasa(b'{"system":{"a":"' + b"x" * 200 + b'"}}'), config=Config(max_bytes=64)).status, "budget_exhausted")

    def test_hint_never_establishes_identity(self):
        for hint in ("lifx-lan", "tuya-lan", "tplink-smarthome"):
            self.assertNotEqual(datagram(DNS, hint=hint).status, "identified")
            self.assertNotEqual(datagram(b"\x00" * 40, hint=hint).status, "identified")


class MulticastDnsLayoutTests(unittest.TestCase):
    def test_pointer_into_srv_target(self):
        self.assertEqual(datagram(MDNS_SRV_POINTER).application_protocol, "mdns")

    def test_aa_on_query_is_ignored(self):
        self.assertEqual(datagram(MDNS_QUERY_AA).application_protocol, "mdns")

    def test_reverse_mapping_probe(self):
        observation = datagram(MDNS_REVERSE_PROBE)
        self.assertEqual((observation.application_protocol, fields(observation, "mdns_profile")), ("mdns", {"mdns_profile": "probe"}))

    def test_trailing_byte_still_rejected(self):
        self.assertNotEqual(datagram(MDNS_QUERY_AA + b"\x00").status, "identified")

    def test_truncations(self):
        for data in (MDNS_SRV_POINTER, MDNS_REVERSE_PROBE):
            for cut in range(len(data)):
                self.assertNotEqual(datagram(data[:cut]).status, "identified", cut)


if __name__ == "__main__":
    unittest.main()
