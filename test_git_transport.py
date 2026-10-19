"""Git service framing, bounded ambiguity routing and metadata minimization."""
import gc
import random
import unittest
import weakref
from dataclasses import asdict

from protocol_engine import Inspector, Config, supported_protocols
from protocol_engine.dispatch import select, LOOKAHEAD
from protocol_engine.registry import PARSERS
from protocol_fixtures import GIT, STREAM_CASES
from test_engine import HTTP


def packet(body):
    return ('%04x' % (len(body)+4)).encode('ascii') + body


def inspect(data, hint=None, config=None):
    engine = Inspector(config=config, protocol_hint=hint)
    engine.feed(data)
    return engine


class GitTransportTests(unittest.TestCase):
    def test_commands_optional_host_and_version_offers(self):
        for command in (b'git-upload-pack', b'git-receive-pack', b'git-upload-archive'):
            for host in (b'', b'host=example.com\0', b'host=192.0.2.1:9418\0'):
                for extras in (b'', b'\0version=1\0', b'\0version=2\0feature=opaque\0'):
                    data = packet(command+b' /demo.git\0'+host+extras)
                    for hint in (None, 'git'):
                        engine = inspect(data, hint)
                        self.assertEqual(engine.observation.status, 'identified', data)
                        self.assertEqual(engine.observation.application_protocol, 'git')
                        self.assertEqual(engine.observation.scope, 'service_request')
                        self.assertIsNone(engine.observation.hostname)
                        self.assertIsNone(engine.observation.application)
                        self.assertEqual(engine.metrics.bytes_inspected, len(data))

    def test_every_split_and_single_byte_fragmentation(self):
        expected = inspect(GIT).observation
        for cut in range(len(GIT)+1):
            engine = Inspector();engine.feed(GIT[:cut]);engine.feed(GIT[cut:])
            self.assertEqual(engine.observation, expected, cut)
            self.assertEqual(engine.metrics.bytes_inspected, len(GIT))
            self.assertEqual(engine.metrics.candidates_selected, 1)
        engine = Inspector()
        for byte in GIT:engine.feed(bytes([byte]))
        self.assertEqual(engine.observation, expected)
        self.assertEqual(engine.metrics.bytes_inspected, len(GIT))

    def test_complete_frame_required_and_trailing_data_not_charged(self):
        for cut in range(len(GIT)):
            engine = inspect(GIT[:cut]);engine.end()
            self.assertNotEqual(engine.observation.status, 'identified', cut)
        engine = inspect(GIT+b'private packfile contents'*1000)
        self.assertEqual(engine.observation.status, 'identified')
        self.assertEqual(engine.metrics.bytes_inspected, len(GIT))
        self.assertNotIn('project.git', repr(asdict(engine.observation)))
        self.assertNotIn('example.com', repr(asdict(engine.observation)))

    def test_http_extension_methods_with_git_looking_prefix_are_preserved(self):
        for method in (b'000f', b'abcd', b'0033git-upload-pack', b'ffffgit-receive-pack', b'0000git-upload-archive'):
            data = method+b' / HTTP/1.1\r\nHost: example.com\r\n\r\n'
            for cut in range(len(data)+1):
                engine = Inspector();engine.feed(data[:cut]);engine.feed(data[cut:])
                self.assertEqual(engine.observation.application_protocol, 'http/1.1', (method, cut))
                self.assertEqual(engine.metrics.bytes_inspected, len(data))

    def test_hint_is_strict_and_internal_router_is_not_a_hint(self):
        with self.assertRaises(ValueError):Inspector(protocol_hint='git_text')
        self.assertNotIn('git_text', PARSERS)
        for data, protocol in STREAM_CASES:
            if protocol != 'git':
                self.assertNotEqual(inspect(data, 'git').observation.status, 'identified', protocol)
        self.assertNotEqual(inspect(HTTP, 'git').observation.status, 'identified')

    def test_bad_lengths_empty_flush_and_mismatched_payload(self):
        for header in (b'0000', b'0001', b'0002', b'0003', b'0004', b'ffff', b'gggg', b'003F'):
            self.assertEqual(inspect(header+GIT[4:], 'git').observation.status, 'malformed', header)
        self.assertEqual(inspect(b'0008git-upload-pack /x\0', 'git').observation.status, 'malformed')
        engine = inspect(b'0100'+GIT[4:], 'git');engine.end()
        self.assertEqual(engine.observation.status, 'incomplete')

    def test_bad_service_fields_and_authorities(self):
        for body in (b'git-upload-pack /x', b'git-upload-pack \0', b'git-unknown /x\0',
                     b'git-upload-pack /x\0host=\0', b'git-upload-pack /x\0host=bad host\0',
                     b'git-upload-pack /x\0host=example.com:0\0', b'git-upload-pack /x\0host=example.com:65536\0',
                     b'git-upload-pack /x\0host=[::1]\0', b'git-upload-pack /x\0version=2\0',
                     b'git-upload-pack /x\0\0', b'git-upload-pack /x\0host=example.com\0host=other\0'):
            self.assertNotEqual(inspect(packet(body), 'git').observation.status, 'identified', body)

    def test_unsupported_fields_do_not_promote_version_or_opaque_metadata(self):
        for extras in (b'version=3\0', b'version\0', b'version=2\0version=1\0', b'x=with space\0', b'\0'):
            self.assertNotEqual(inspect(packet(b'git-upload-pack /x\0\0'+extras)).observation.status, 'identified')
        result = inspect(GIT).observation
        offers = [e for e in result.evidence if e.field=='offered_version']
        self.assertEqual([(e.value, e.strength) for e in offers], [('2', 'offered')])
        self.assertEqual(result.application_protocol, 'git')

    def test_budgets_bound_advertised_size_discriminator_and_parameters(self):
        samples = [(b'0100git-upload-pack /x\0', Config(max_bytes=64)),
                   (packet(b'git-upload-pack /'+b'a'*100+b'\0'), Config(max_line=32)),
                   (packet(b'git-upload-pack /x\0\0a\0b\0'), Config(max_headers=1)),
                   (packet(b'git-upload-pack /x\0\0x='+b'a'*513+b'\0'), Config()),
                   (b'ffffgit-upload-pack '+b'x'*200, Config(max_line=32))]
        for data, config in samples:
            engine = inspect(data, config=config)
            self.assertEqual(engine.observation.status, 'budget_exhausted', data[:40])
            self.assertLessEqual(engine.metrics.bytes_inspected, config.max_bytes)
            self.assertIsNone(engine._parser)

    def test_prefix_selection_resolves_within_lookahead(self):
        self.assertEqual(select(GIT[:LOOKAHEAD]), 'git_text')
        for width in range(1,8):self.assertIsNone(select(GIT[:width]))
        for first in range(256):
            self.assertIsNotNone(select(bytes([first])*LOOKAHEAD))
        self.assertTrue(any(e.family=='git' and not e.requires_hint for e in supported_protocols()))

    def test_mutation_fragmentation_equivalence_and_terminal_release(self):
        rng = random.Random(16016)
        for _ in range(1000):
            data = bytearray(GIT)
            for _ in range(rng.randrange(1,4)):data[rng.randrange(len(data))]=rng.randrange(256)
            data = bytes(data)
            whole=inspect(data);split=Inspector();pos=0
            while pos<len(data):
                size=rng.randrange(1,14);split.feed(data[pos:pos+size]);pos+=size
            whole.end();split.end()
            self.assertEqual(whole.observation, split.observation, data)
            self.assertLessEqual(split.metrics.candidates_selected, 1)
        enabled=gc.isenabled();gc.disable()
        try:
            engine=inspect(GIT[:-1]);ref=weakref.ref(engine._parser)
            engine.feed(GIT[-1:]);self.assertIsNone(ref())
            calls=engine.metrics.parser_calls;engine.feed(bytes(65536))
            self.assertEqual(engine.metrics.parser_calls,calls)
        finally:
            if enabled:gc.enable()
