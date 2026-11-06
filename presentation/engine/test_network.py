import random
import struct
import unittest
from protocol_engine import Config, DatagramInspector, Inspector
from protocol_engine.datagram import VALIDATORS
from protocol_fixtures import BGP, SMB311, SNMP, TFTP, NTP, NETWORK_STREAM_CASES


class NetworkProtocolTests(unittest.TestCase):
    def stream(self, data, **kwargs):
        inspector = Inspector(**kwargs)
        inspector.feed(data)
        return inspector.observation

    def test_bgp_marker_type_version_lengths_and_capabilities(self):
        for offset, value in ((0, 0), (18, 2), (19, 3), (23, 1), (28, 3), (30, 8), (32, 4)):
            data = bytearray(BGP)
            data[offset] = value
            self.assertNotEqual(self.stream(bytes(data)).status, 'identified', offset)
        bare = BGP[:16] + struct.pack('!H', 29) + BGP[18:28] + b'\x00'
        self.assertEqual(self.stream(bare).application_protocol, 'bgp/4')
        oversized = BGP[:16] + b'\x10\x01' + BGP[18:]
        self.assertEqual(self.stream(oversized).status, 'malformed')

    def test_smb_declared_size_bounded_before_buffering(self):
        data = b'\x00\xff\xff\xff\xfeSMB'
        self.assertEqual(self.stream(data).status, 'budget_exhausted')

    def test_smb_fields_context_offsets_lengths_and_missing_preauth(self):
        for offset, value in ((8, 63), (16, 1), (20, 1), (24, 4), (40, 1), (68, 35),
                              (70, 0), (72, 0), (74, 1), (96, 105), (100, 0), (108, 2),
                              (110, 7), (112, 1), (116, 0), (118, 1), (120, 2)):
            data = bytearray(SMB311)
            data[offset] = value
            self.assertNotEqual(self.stream(bytes(data)).status, 'identified', offset)
        self.assertEqual(self.stream(SMB311).scope, 'negotiation_request')
        self.assertIsNone(self.stream(SMB311).encryption)

    def test_smb_multiple_contexts_and_unknown_framing(self):
        data = bytearray(SMB311)
        data[100:102] = (2).to_bytes(2, 'little')
        data += bytes(2) + struct.pack('<HHIHH', 2, 4, 0, 1, 2)
        data[:4] = (len(data) - 4).to_bytes(4, 'big')
        self.assertEqual(self.stream(bytes(data)).application_protocol, 'smb2')
        data[128:130] = b'\x09\x00'  # oversized context body
        self.assertNotEqual(self.stream(bytes(data)).status, 'identified')

    def test_snmp_v1_v2_read_requests(self):
        for version, kinds in ((0, (0xa0, 0xa1)), (1, (0xa0, 0xa1, 0xa5))):
            for kind in kinds:
                data = bytearray(SNMP)
                data[4], data[13] = version, kind
                result = DatagramInspector().inspect(bytes(data))
                self.assertEqual(result.application_protocol, 'snmp/' + ('1' if version == 0 else '2c'))
                self.assertNotIn('public', repr(result))
        for offset, value in ((1, 37), (4, 3), (13, 0xa9), (20, 1), (28, 0x30), (30, 0x80), (38, 4)):   # 0xa2 (response) is accepted since v0.43
            data = bytearray(SNMP)
            data[offset] = value
            self.assertNotEqual(DatagramInspector().inspect(bytes(data)).status, 'identified', offset)

    def test_snmp_oid_and_indefinite_ber_rejected(self):
        for data in (SNMP + b'\x00', SNMP[:1] + b'\x80' + SNMP[2:], SNMP[:-3] + b'\x80' + SNMP[-2:]):
            self.assertNotEqual(DatagramInspector().inspect(data, 'snmp').status, 'identified')

    def test_tftp_modes_options_limits(self):
        udp = DatagramInspector()
        for mode in (b'octet', b'NETASCII', b'mail'):
            for opcode in (1, 2):
                self.assertEqual(udp.inspect(bytes((0, opcode)) + b'f\0' + mode + b'\0').application_protocol, 'tftp')
        for suffix in (b'blksize\0007\0', b'timeout\0000\0', b'windowsize\0000\0',
                       b'blksize\0008\0BLKSIZE\0009\0', b'empty\0\0', b'tsize\0001\0'):
            self.assertNotEqual(udp.inspect(b'\0\1f\0octet\0' + suffix).status, 'identified', suffix)
        for data in (TFTP[:-1], b'\0\1\0octet\0', b'\0\1f\0bad\0', b'\0\1' + b'a' * 510 + b'\0octet\0'):
            self.assertNotEqual(udp.inspect(data).status, 'identified')

    def test_ntp_requires_hint_and_never_claims_authentication(self):
        udp = DatagramInspector()
        self.assertEqual(udp.inspect(NTP).status, 'unknown')
        result = udp.inspect(NTP, 'ntp')
        self.assertEqual(result.application_protocol, 'ntp/4')
        self.assertIn('caller hint', result.reason)
        server = b'\x24\x02' + bytes(38) + b'\x01' * 8
        self.assertEqual(udp.inspect(server, 'ntp').status, 'identified')
        for data in (NTP[:-1], NTP + bytes(4), b'\x24' + bytes(47), b'\x23\x11' + bytes(46), b'\x26' + bytes(47)):
            self.assertNotEqual(udp.inspect(data, 'ntp').status, 'identified')

    def test_all_hint_paths_and_mutations_stay_bounded(self):
        rng = random.Random(606)
        for data, protocol in NETWORK_STREAM_CASES:
            for _ in range(300):
                mutant = bytearray(data)
                mutant[rng.randrange(len(mutant))] = rng.randrange(256)
                result = self.stream(bytes(mutant))
                self.assertIn(result.status, ('identified', 'detecting', 'unknown', 'malformed', 'budget_exhausted'))
        udp = DatagramInspector(Config(max_bytes=1024))
        for data in (SNMP, TFTP, NTP):
            for _ in range(300):
                mutant = bytearray(data)
                mutant[rng.randrange(len(mutant))] = rng.randrange(256)
                udp.inspect(bytes(mutant))
        for length in range(130):
            data = bytes(rng.randrange(256) for _ in range(length))
            for hint in VALIDATORS:
                udp.inspect(data, hint)


if __name__ == '__main__':
    unittest.main()
