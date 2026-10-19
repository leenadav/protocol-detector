"""RADIUS structural profiles, explicit candidate context and no auth claims."""
import json
import random
import struct
import subprocess
import sys
import unittest
from protocol_engine import Config, DatagramInspector
from protocol_fixtures import RADIUS, DATAGRAM_CASES, HINTED_DATAGRAM_CASES


def attr(kind, value):
    return bytes((kind, len(value) + 2)) + value


def request(attributes, authenticator=bytes(range(16)), code=1):
    return struct.pack('!BBH', code, 123, 20 + len(attributes)) + authenticator + attributes


NAS = attr(4, bytes.fromhex('c0000201'))
PAP = attr(2, b'x' * 16)


class RadiusTests(unittest.TestCase):
    def inspect(self, data, config=None):
        return DatagramInspector(config).inspect(data, 'radius')

    def assert_identified(self, data):
        result = self.inspect(data)
        self.assertEqual(result.status, 'identified', result)
        self.assertEqual(result.application_protocol, 'radius')
        self.assertIsNone(result.application)
        self.assertIsNone(result.hostname)
        self.assertIsNone(result.encryption)
        self.assertEqual(result.evidence[-1].strength, 'context')
        self.assertIn('unverified', result.reason)
        return result

    def test_pap_chap_state_and_nas_alternatives(self):
        for nas in (NAS, attr(32, b'private-nas'), NAS + attr(32, b'private-nas')):
            for auth in (PAP, attr(3, bytes(17)), attr(24, b'private-state'),
                         PAP + attr(24, b'private-state'), attr(3, bytes(17)) + attr(60, bytes(16))):
                result = self.assert_identified(request(nas + auth))
                self.assertNotIn('private', repr(result))
        self.assert_identified(RADIUS)

    def test_published_rfc2865_pap_and_chap_vectors(self):
        # RFC2865 sections 7.1 and 7.2, public synthetic examples. These bytes
        # come from the specification, not our encoder. No secret is used.
        # https://www.rfc-editor.org/rfc/rfc2865.html#section-7
        for hex_data in (
            '010000380f403f9473978057bd83d5cb98f4227a01066e656d6f02120dbe708d93d413ce3196e43f782a0aee0406c0a80110050600000003',
            '010100472aee86f08d0d55969ca5978e0d3367a20108666c6f707379031316e97557c316185895f293ff63440772750406c0a80110050600000014060600000002070600000001'):
            self.assert_identified(bytes.fromhex(hex_data))

    def test_supported_widths_binary_strings_and_repeatable_attributes(self):
        attributes = NAS + PAP + attr(1, b'\xff\0')
        for kind in (5, 6, 7, 8, 9, 12, 13, 14, 61, 62):
            attributes += attr(kind, b'\0\0\0\x01')
        for kind in (19, 24, 30, 31, 32, 33, 60):
            attributes += attr(kind, b'\xff\0')
        attributes += attr(26, bytes.fromhex('00000009') + b'opaque vendor bytes')
        attributes += attr(80, bytes(16))
        self.assert_identified(request(attributes))
        for kind, value in ((13, bytes(4)), (14, bytes(4)), (26, bytes(4) + b'x'), (33, b'x')):
            self.assert_identified(request(NAS + PAP + attr(kind, value) * 3))

    def test_authenticators_are_not_claimed_to_be_verified(self):
        for authenticator in (bytes(16), b'\xff' * 16, bytes(range(16))):
            self.assert_identified(request(NAS + PAP + attr(80, b'\xff' * 16), authenticator))
        # The result is structural; no secret or verification API exists here.
        self.assertNotIn('authenticated', repr(self.inspect(RADIUS)))

    def test_length_header_and_datagram_boundaries(self):
        for end in range(len(RADIUS)):
            self.assertNotEqual(self.inspect(RADIUS[:end]).status, 'identified', end)
        for length in (0, 19, 4097, 65535, len(RADIUS) + 1):
            data = RADIUS[:2] + struct.pack('!H', length) + RADIUS[4:]
            self.assertEqual(self.inspect(data).status, 'malformed')
        self.assertEqual(self.inspect(RADIUS + b'padding').status, 'unknown')
        self.assertEqual(self.inspect(RADIUS + RADIUS).status, 'unknown')
        for code in (0, 2, 3, 4, 5, 11, 12, 255):
            self.assertEqual(self.inspect(bytes([code]) + RADIUS[1:]).status, 'unknown')

    def test_invalid_attribute_widths_and_tlv_lengths(self):
        for tail in (b'\x04', b'\x04\0', b'\x04\x01', b'\x04\xffx', attr(4, bytes(3)),
                     attr(5, bytes(5)), attr(1, b''), attr(24, b''), attr(2, bytes(15)),
                     attr(2, bytes(17)), attr(2, bytes(144)), attr(3, bytes(16)),
                     attr(26, bytes(4)), attr(26, b'\x01' + bytes(4)), attr(80, bytes(15))):
            result = self.inspect(request(NAS + PAP + tail))
            self.assertEqual(result.status, 'malformed', (tail, result))

    def test_required_fields_singletons_and_unsupported_extensions(self):
        self.assertEqual(self.inspect(request(PAP)).status, 'malformed')
        self.assertEqual(self.inspect(request(NAS)).status, 'unknown')
        self.assertEqual(self.inspect(request(NAS + PAP + attr(3, bytes(17)))).status, 'malformed')
        for kind, value in ((1, b'x'), (2, bytes(16)), (3, bytes(17)), (4, bytes(4)), (24, b'x'), (80, bytes(16))):
            self.assertEqual(self.inspect(request(NAS + PAP + attr(kind, value) * 2)).status, 'malformed')
        for kind in (0, 10, 18, 79, 241, 255):
            self.assertEqual(self.inspect(request(NAS + PAP + attr(kind, b'x'))).status, 'unknown')
        for size in range(16, 129, 16):
            self.assert_identified(request(NAS + attr(2, bytes(size))))

    def test_byte_attribute_count_budgets_and_exact_rfc_packet_limit(self):
        self.assertEqual(self.inspect(RADIUS, Config(max_headers=2)).status, 'budget_exhausted')
        data = request(NAS + PAP + attr(33, b'x') * 127)
        self.assertEqual(self.inspect(data).status, 'budget_exhausted')
        self.assertEqual(self.inspect(data, Config(max_headers=4096)).status, 'budget_exhausted')
        self.assertEqual(self.inspect(data, Config(max_bytes=64)).status, 'budget_exhausted')
        # 20 header + 6 NAS + 18 PAP + 15*255 + 227 = 4096.
        data = request(NAS + PAP + attr(33, bytes(253)) * 15 + attr(33, bytes(225)))
        self.assertEqual(len(data), 4096)
        self.assert_identified(data)
        self.assertEqual(self.inspect(request(data[20:] + attr(33, b'x'))).status, 'malformed')

    def test_explicit_candidate_does_not_reinterpret_other_families(self):
        for data, _ in DATAGRAM_CASES:
            self.assertNotEqual(self.inspect(data).status, 'identified')
        automatic = DatagramInspector().inspect(RADIUS)
        self.assertNotEqual(automatic.application_protocol, 'radius')
        self.assertEqual(DatagramInspector().inspect(RADIUS[:28], 'radius').status, 'malformed')
        self.assertNotEqual(DatagramInspector().inspect(RADIUS[28:], 'radius').status, 'identified')

    def test_valid_dns_radius_overlap_demonstrates_why_hint_is_required(self):
        # Both are structurally valid. RADIUS authenticator bytes become DNS
        # QDCOUNT and label; NAS/State TLVs finish the question and QTYPE/QCLASS.
        authenticator = b'\0\x01' + bytes(6) + b'\x0c' + b'a' * 7
        data = request(attr(4, bytes.fromhex('c0000200')) + attr(24, b'\0\x01'), authenticator)
        self.assert_identified(data)
        dns = DatagramInspector().inspect(data, 'dns')
        self.assertEqual(dns.application_protocol, 'dns', dns)
        # RADIUS is deliberately not part of automatic competition yet. Existing
        # DNS coverage remains available; neither encoding proves sender intent.
        self.assertEqual(DatagramInspector().inspect(data).application_protocol, 'dns')

    def test_mutations_bounded_candidate_work(self):
        rng = random.Random(1010)
        for _ in range(1000):
            data = bytearray(RADIUS)
            for _ in range(rng.randrange(1, 5)):
                data[rng.randrange(len(data))] = rng.randrange(256)
            inspector = DatagramInspector()
            result = inspector.inspect(bytes(data), 'radius')
            self.assertIn(result.status, ('identified', 'unknown', 'malformed', 'budget_exhausted'))
            self.assertEqual(inspector.metrics.parser_calls, 1)
            self.assertLessEqual(inspector.metrics.bytes_inspected, len(data))

    def test_offline_cli_explicit_udp_candidate(self):
        result = subprocess.run([sys.executable, '-B', 'analyze_pcap.py', 'sample-radius.pcap',
                                 '--udp-hint', 'radius', '--json', '--events-only'],
                                capture_output=True, check=True, timeout=3)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(rows[0]['classification']['application_protocol'], 'radius')
        self.assertEqual(rows[0]['classification']['evidence'][-1]['field'], 'candidate_hint')
        self.assertEqual(rows[-1]['summary']['udp'], 1)


if __name__ == '__main__':
    unittest.main()
