"""FastCGI specification sections 3.3/3.4/5.1/5.2; rsync daemon greeting.

Synthetic independent record encoders exercise record and TCP fragmentation
separately. No process execution or external traffic is used.
"""
import gc
import random
import struct
import unittest
import weakref
from protocol_engine import Config, Inspector
from protocol_engine.dispatch import select
from protocol_engine.wire import dns_probe
from protocol_fixtures import FASTCGI, RSYNC, STREAM_CASES


def record(kind, data=b'', request=1, padding=b'', reserved=0, version=1):
    return struct.pack('!BBHHBB', version, kind, request, len(data), len(padding), reserved) + data + padding


def begin(role=1, flags=1, reserved=bytes(5), **kwargs):
    return record(1, struct.pack('!HB', role, flags) + reserved, **kwargs)


def pair(name, value, wide=False):
    def length(size):
        return struct.pack('!I', size | 0x80000000) if wide or size >= 128 else bytes([size])
    return length(len(name)) + length(len(value)) + name + value


def inspect(data, **kwargs):
    engine = Inspector(**kwargs)
    engine.feed(data)
    return engine


class GatewayTests(unittest.TestCase):
    def assert_protocol(self, data, protocol, **kwargs):
        engine = inspect(data, **kwargs)
        self.assertEqual(engine.observation.status, 'identified', engine.observation)
        self.assertEqual(engine.observation.application_protocol, protocol)
        self.assertIsNone(engine.observation.hostname)
        self.assertIsNone(engine.observation.application)
        self.assertIsNone(engine.observation.encryption)
        return engine

    def test_fastcgi_all_roles_ids_flags_and_arbitrary_padding(self):
        for role in (1, 2, 3):
            for flags in (0, 1):
                for request in (1, 256, 65535):
                    data = begin(role, flags, request=request, padding=b'\xff' * 255)
                    data += record(4, pair(b'PRIVATE_NAME', b'private-value'), request=request, padding=b'\xfe\x80')
                    data += record(4, request=request, padding=b'end')
                    engine = self.assert_protocol(data, 'fastcgi/1')
                    self.assertEqual(engine.observation.scope, 'initial_params')
                    self.assertNotIn('private', repr(engine.observation))
                    self.assertEqual(engine.observation.evidence[-1].strength, 'offered')

    def test_fastcgi_parameter_bytes_can_cross_every_record_boundary(self):
        params = pair(b'x' * 128, b'y' * 129) + pair(b'\0\xff', b'\0\xff')
        for split in range(1, len(params)):
            data = begin() + record(4, params[:split], padding=b'PAD') + record(4, params[split:]) + record(4)
            self.assert_protocol(data, 'fastcgi/1')
        for params in (b'', pair(b'', b''), pair(b'x', b'y', wide=True), pair(b'x', b'a') * 2):
            self.assert_protocol(begin() + (record(4, params) if params else b'') + record(4), 'fastcgi/1')

    def test_fastcgi_nested_record_and_tcp_fragmentation(self):
        params = pair(b'REQUEST_METHOD', b'GET')
        data = begin() + b''.join(record(4, bytes([byte]), padding=b'X') for byte in params) + record(4)
        for width in (1, 2, 7, 8, 13, 64):
            engine = Inspector()
            for pos in range(0, len(data), width):
                engine.feed(data[pos:pos + width])
            self.assertEqual(engine.observation.application_protocol, 'fastcgi/1')

    def test_fastcgi_requires_params_terminator_and_padding_completion(self):
        data = begin(padding=b'PAD') + record(4, pair(b'x', b'y')) + record(4, padding=b'END')
        for end in range(len(data)):
            engine = inspect(data[:end])
            self.assertEqual(engine.observation.status, 'detecting', end)
            engine.end()
            self.assertEqual(engine.observation.status, 'incomplete')
        engine = self.assert_protocol(data + b'opaque application body', 'fastcgi/1')
        self.assertEqual(engine.metrics.bytes_inspected, len(data))

    def test_fastcgi_invalid_parameter_lengths_and_limits(self):
        for params in (b'\x80', b'\x80\0\0', b'\x01', b'\x01\x80\0', b'\x04\x02abc', b'\x01\0x\x01'):
            result = inspect(begin() + record(4, params) + record(4)).observation
            self.assertEqual(result.status, 'malformed', (params, result))
        for params in (bytes.fromhex('ffffffff00'), bytes.fromhex('00ffffffff'), pair(b'x', b'y') * 129):
            result = inspect(begin() + record(4, params) + record(4)).observation
            self.assertEqual(result.status, 'budget_exhausted', result)
        data = begin() + b''.join(record(4, b'x') for _ in range(128))
        self.assertEqual(inspect(data).observation.status, 'budget_exhausted')
        self.assertEqual(inspect(FASTCGI, config=Config(max_headers=2)).observation.status, 'budget_exhausted')

    def test_fastcgi_header_budget_preflight_and_exact_byte_boundary(self):
        data = begin() + struct.pack('!BBHHBB', 1, 4, 1, 65535, 0, 0)
        engine = inspect(data)
        self.assertEqual(engine.observation.status, 'budget_exhausted')
        self.assertIsNone(engine._parser)
        data = begin(padding=bytes(40)) + record(4)
        self.assertEqual(len(data), 64)
        self.assert_protocol(data, 'fastcgi/1', config=Config(max_bytes=64))
        self.assertEqual(inspect(begin(padding=bytes(41)) + record(4), config=Config(max_bytes=64)).observation.status, 'budget_exhausted')

    def test_fastcgi_conservative_profile_does_not_claim_other_records(self):
        starts = (begin(role=4), begin(flags=2), begin(reserved=b'\x01' + bytes(4)),
                  begin(reserved=bytes(4)), begin(reserved=bytes(6)), begin(request=0),
                  begin(reserved=bytes(5), version=2), begin(reserved=bytes(5), padding=b'', request=1)[:7] + b'\x01' + begin()[8:],
                  record(9, pair(b'FCGI_MAX_CONNS', b''), request=0))
        for data in starts:
            result = inspect(data + record(4), protocol_hint='fastcgi').observation
            self.assertIn(result.status, ('unknown', 'malformed'), result)
        for tail in (record(4, request=2), record(5), record(1, bytes(8)), record(2), record(9, request=0)):
            self.assertEqual(inspect(begin() + tail).observation.status, 'unknown')

    def test_fastcgi_and_tcp_dns_candidates_are_disjoint(self):
        for padding in range(256):
            data = begin(padding=bytes(padding)) + record(4)
            self.assertEqual(select(data[:24]), 'fastcgi')
            self.assertFalse(dns_probe(data[2:14]))
        # Valid 257-byte DNS body deliberately overlaps FCGI version/type,
        # request ID and content length, but DNS QDCOUNT has low byte one.
        dns = bytes.fromhex('000180080001000000000001') + bytes.fromhex('0000010001')   # a response: queries carry rcode zero (v0.43)
        dns += b'\0' + struct.pack('!HHIH', 65000, 1, 0, 229) + bytes(229)
        self.assertEqual(len(dns), 257)
        data = b'\x01\x01' + dns
        for split in range(len(data) + 1):
            engine = Inspector()
            engine.feed(data[:split]); engine.feed(data[split:])
            self.assertEqual(engine.observation.application_protocol, 'dns', split)

    def test_rsync_final_versions_and_digest_grammar(self):
        for version in range(27, 33):
            for suffix in (b'.0', b'.000'):
                data = b'@RSYNCD: ' + str(version).encode() + suffix + b' sha512 sha256 new-digest2\n'
                self.assert_protocol(data, 'rsync')
            if version < 32:
                self.assert_protocol(b'@RSYNCD: ' + str(version).encode() + b'.0\n', 'rsync')
            if version < 30:
                self.assert_protocol(b'@RSYNCD: ' + str(version).encode() + b'\n', 'rsync')
        for line in (b'@RSYNCD: 30\n', b'@RSYNCD: 32.0\n', b'@RSYNCD: 32.0 \n', b'@RSYNCD: 32.0 sha512  md5\n',
                     b'@RSYNCD: 32.0 sha512\r\n', b'@RSYNCD: 31.0 md5\0\n', b'@RSYNCD: AUTHREQD abc\n',
                     b'@RSYNCD: 31.0 sha_256\n', b'@RSYNCD: +31.0\n', b'@RSYNCD: 31.0 SHA512\n'):
            self.assertEqual(inspect(line).observation.status, 'malformed', line)
        for line in (b'@RSYNCD: 33.0 sha512\n', b'@RSYNCD: 26\n', b'@RSYNCD: 31.1\n', b'@RSYNCD: 31.0 md5 md5\n'):
            self.assertEqual(inspect(line).observation.status, 'unknown')

    def test_rsync_line_and_offer_budgets(self):
        for data, config in ((RSYNC, Config(max_line=16)), (RSYNC, Config(max_headers=1)),
                             (b'@RSYNCD: 31.0 ' + b'a' * 33 + b'\n', Config()),
                             (b'@RSYNCD: 31.0 ' + b' '.join(b'd' + str(i).encode() for i in range(17)) + b'\n', Config()),
                             (b'@RSYNCD: 31.0 ' + b'a' * 500, Config())):
            self.assertEqual(inspect(data, config=config).observation.status, 'budget_exhausted')
        engine = self.assert_protocol(RSYNC + b'opaque module data', 'rsync')
        self.assertEqual(engine.metrics.bytes_inspected, len(RSYNC))

    def test_hint_is_not_proof_and_no_confusion_with_existing_protocols(self):
        for hint in ('fastcgi', 'rsync'):
            for data, expected in STREAM_CASES:
                if expected.split('/')[0] != hint:
                    self.assertNotEqual(inspect(data, protocol_hint=hint).observation.status, 'identified', (hint, expected))

    def test_terminal_state_releases_buffers_without_cyclic_gc(self):
        enabled = gc.isenabled()
        gc.disable()
        try:
            for data in (FASTCGI, RSYNC):
                engine = inspect(data[:-1])
                reference = weakref.ref(engine._parser)
                engine.feed(data[-1:])
                self.assertIsNone(reference())
                calls = engine.metrics.parser_calls
                self.assertEqual(engine.feed(bytes(65536)), ())
                self.assertEqual(engine.metrics.parser_calls, calls)
        finally:
            if enabled:
                gc.enable()

    def test_random_fragmentation_does_not_change_classification(self):
        rng = random.Random(909)
        for original in (FASTCGI, RSYNC):
            for _ in range(300):
                data = bytearray(original)
                index = rng.randrange(len(data)); data[index] = rng.randrange(256)
                data = bytes(data)
                whole, split = inspect(data), Inspector()
                pos = 0
                while pos < len(data):
                    width = rng.randrange(1, 18)
                    split.feed(data[pos:pos + width]); pos += width
                whole.end(); split.end()
                self.assertEqual(whole.observation, split.observation)
                self.assertLessEqual(split.metrics.candidates_selected, 1)


if __name__ == '__main__':
    unittest.main()
