"""Protocol semantics, ambiguity, resource exhaustion and trust-boundary tests."""
import gc
import json
import random
import unittest
import weakref
from protocol_engine import Config, Inspector
from protocol_fixtures import STOMP, STOMP_SERVER, NATS_INFO, NATS_CONNECT, IMAP, RDP, SERVICE_STREAM_CASES


def inspect(data, **kwargs):
    engine = Inspector(**kwargs)
    engine.feed(data)
    return engine


def nats_connect(**overrides):
    fields = dict(verbose=False, pedantic=False, tls_required=False, lang='python', version='1.0')
    fields.update(overrides)
    return b'CONNECT ' + json.dumps(fields).encode() + b'\r\n'


def rdp(optional=b'', flags=0, security=3, correlation=b''):
    body = b'\xe0\0\0\0\0\0' + optional + bytes([1, flags, 8, 0]) + security.to_bytes(4, 'little') + correlation
    return b'\x03\0' + (len(body) + 5).to_bytes(2, 'big') + bytes([len(body)]) + body


class ServiceTests(unittest.TestCase):
    def assert_protocol(self, data, protocol, **kwargs):
        engine = inspect(data, **kwargs)
        self.assertEqual(engine.observation.status, 'identified', engine.observation)
        self.assertEqual(engine.observation.application_protocol, protocol)
        self.assertIsNone(engine.observation.encryption)
        self.assertIsNone(engine.observation.application)
        self.assertIsNone(engine.observation.hostname)
        return engine

    def assert_rejected(self, data, **kwargs):
        result = inspect(data, **kwargs).observation
        self.assertNotEqual(result.status, 'identified', result)
        return result

    def test_http_extension_methods_win_over_shared_text_prefixes(self):
        for method in (b'CONNECT', b'CONNECTED', b'STOMP', b'INFO', b'info', b'*', b'SSH-2.0-demo'):
            data = method + b' { HTTP/1.1\r\nHost: example.com\r\n\r\n'
            for split in range(len(data) + 1):
                engine = Inspector()
                engine.feed(data[:split]); engine.feed(data[split:])
                self.assertEqual(engine.observation.application_protocol, 'http/1.1', (method, split))

    def test_stomp_line_endings_commands_and_escapes(self):
        for data in (STOMP, STOMP.replace(b'\n', b'\r\n'), STOMP_SERVER,
                     STOMP.replace(b'CONNECT', b'STOMP'),
                     STOMP.replace(b'CONNECT', b'STOMP').replace(b'host:example.com', b'host:tenant\\cname'),
                     STOMP.replace(b'\n\n', b'\nx\\cy:v\\r\\n\\c\\\\\n\n').replace(b'CONNECT', b'STOMP'),
                     STOMP.replace(b'host:example.com', 'host:שרת.example'.encode()),
                     STOMP.replace(b'\n\n', b'\nlogin:user\npasscode:private-test-value\n\n')):
            result = self.assert_protocol(data, 'stomp').observation
            self.assertNotIn('private-test-value', repr(result))
        for data in (STOMP.replace(b'\n\n', b'\n\nbody'),
                     STOMP.replace(b'host:example.com', b'host:'),
                     STOMP.replace(b'accept-version:1.1,1.2', b'accept-version:1.0'),
                     STOMP.replace(b'host:', b'host\r:'),
                     STOMP.replace(b'host:', b'host\0:'),
                     STOMP.replace(b'host:example.com', b'host:\xff'),
                     STOMP.replace(b'\n\n', b'\ncontent-length:1\n\n'),
                     STOMP.replace(b'0,10000', b'-1,10000'),
                     STOMP.replace(b'CONNECT', b'STOMP').replace(b'host:example.com', b'host:x\\t'),
                     STOMP.replace(b'CONNECT', b'STOMP').replace(b'host:example.com', b'host:x:y'),
                     STOMP_SERVER.replace(b'version:1.2', b'version:9.9')):
            self.assert_rejected(data)

    def test_stomp_duplicate_first_value_and_resource_bounds(self):
        self.assert_protocol(STOMP.replace(b'\n\n', b'\ncontent-length:0\ncontent-length:999\nhost:\n\n'), 'stomp')
        self.assert_rejected(STOMP.replace(b'host:example.com', b'host:\nhost:example.com'))
        for data, config in ((STOMP, Config(max_headers=1)), (STOMP, Config(max_line=16)),
                             (STOMP.replace(b'\n\n', b'\nx:y' * 129 + b'\n\n'), Config()),
                             (STOMP, Config(max_bytes=64))):
            self.assertEqual(inspect(data, config=config).observation.status, 'budget_exhausted')

    def test_nats_types_case_tabs_and_no_identity_or_credentials_promotion(self):
        for data in (NATS_INFO, NATS_CONNECT, NATS_INFO.replace(b'INFO ', b'info\t'),
                     nats_connect(user='private-test-value', password='private-test-value', tls_required=True),
                     nats_connect(extension={'nested': [1, 2, None, 'braces { \\" ]']})):
            result = self.assert_protocol(data, 'nats').observation
            self.assertNotIn('private-test-value', repr(result))
        for data in (b'INFO {}\r\n', b'CONNECT {}\r\n', NATS_INFO.replace(b'4222', b'true'),
                     NATS_INFO.replace(b'4222', b'0'), NATS_INFO.replace(b'1048576', b'-1'),
                     nats_connect(verbose=0), nats_connect(protocol=True), nats_connect(protocol=2),
                     nats_connect(lang=None), nats_connect(headers=1), nats_connect(user=[]),
                     nats_connect(connect_urls=[True]), NATS_CONNECT.replace(b'false', b'null', 1)):
            self.assert_rejected(data)

    def test_nats_json_errors_and_nested_limits(self):
        for tail in (b',"verbose":true', b',"x":NaN', b',"x":Infinity', b',"x":1e9999',
                     b',"x":"\\ud800"', b',"x":{"a":1,"a":2}', b',"x":"\xff"'):
            self.assertEqual(inspect(NATS_CONNECT[:-3] + tail + b'}\r\n').observation.status, 'malformed')
        huge_number = NATS_CONNECT[:-3] + b',"x":' + b'9' * 1000 + b'}\r\n'
        deep = NATS_CONNECT[:-3] + b',"x":' + b'[' * 100 + b'0' + b']' * 100 + b'}\r\n'
        many = nats_connect(x=list(range(600)))
        for data in (huge_number, deep, many):
            self.assertEqual(inspect(data).observation.status, 'budget_exhausted')
        self.assertEqual(inspect(NATS_CONNECT, config=Config(max_headers=2)).observation.status, 'budget_exhausted')
        self.assertEqual(inspect(NATS_CONNECT, config=Config(max_line=16)).observation.status, 'budget_exhausted')

    def test_imap_requires_revision_capability_and_complete_structure(self):
        for data in (IMAP, IMAP.replace(b'* OK', b'* PREAUTH'), b'* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\n',
                     b'* capability imap4REV2 AUTH=PLAIN\r\n',
                     '* OK [CAPABILITY IMAP4rev2] שרת מוכן\r\n'.encode()):
            self.assert_protocol(data, 'imap')
        for data in (b'* OK ready\r\n', b'* OK [CAPABILITY OTHER] ready\r\n', b'* CAPABILITY XIMAP4rev2\r\n',
                     b'* OK [CAPABILITY IMAP4rev2]\r\n',
                     b'* CAPABILITY IMAP4rev2 (wrong)\r\n', b'* CAPABILITY IMAP4rev2  STARTTLS\r\n',
                     b'* OK [CAPABILITY IMAP4rev2] \x00\r\n', b'* OK [CAPABILITY IMAP4rev2] \xff\r\n'):
            self.assert_rejected(data)
        self.assertEqual(inspect(IMAP, config=Config(max_headers=2)).observation.status, 'budget_exhausted')
        # Since v0.27 a tagged client command is structural IMAP evidence in its own right.
        self.assertEqual(self.assert_protocol(b'A001 CAPABILITY\r\n', 'imap').observation.scope, 'initial_message')

    def test_rdp_cookie_correlation_and_security_offers(self):
        correlation = b'\x06\x00\x24\x00' + bytes(range(1, 17)) + bytes(16)
        for data in (RDP, rdp(), rdp(b'Cookie: mstshash=private-test-value\r\n'),
                     rdp(flags=8, correlation=correlation), rdp(flags=3, security=0x1f), rdp(security=0)):
            result = self.assert_protocol(data, 'rdp').observation
            self.assertEqual(result.scope, 'negotiation_request')
            self.assertNotIn('private-test-value', repr(result))
        self.assertEqual(inspect(bytes.fromhex('0300000b06e00000000000')).observation.status, 'unknown')
        for data in (rdp(flags=4), rdp(flags=8), rdp(correlation=correlation),
                     rdp(flags=8, correlation=correlation[:-1] + b'\x01'),
                     rdp(b'Cookie: mstshash=x\x00\r\n'), rdp(b'Cookie: mstshash=x\n'),
                     RDP[:4] + b'\x01' + RDP[5:], RDP[:10] + b'\x01' + RDP[11:],
                     RDP[:6] + b'\x01' + RDP[7:], RDP[:13] + b'\x09' + RDP[14:]):
            self.assert_rejected(data)
        self.assertEqual(inspect(rdp(security=0x20)).observation.status, 'unknown')

    def test_rdp_header_bounds_before_growth(self):
        for header in (b'\x03\x01\0\x13', b'\x03\0\0\x0a', b'\x03\0\xff\xff'):
            engine = inspect(header)
            self.assertEqual(engine.observation.status, 'malformed')
            self.assertIsNone(engine._parser)
        self.assertEqual(inspect(b'\x03\0\x01\x04', config=Config(max_bytes=64)).observation.status, 'budget_exhausted')

    def test_state_released_without_gc_and_hint_does_not_identify_junk(self):
        enabled = gc.isenabled()
        gc.disable()
        try:
            for data, _ in SERVICE_STREAM_CASES:
                engine = inspect(data[:-1])
                parser = weakref.ref(engine._parser)
                engine.feed(data[-1:])
                self.assertIsNone(parser())
                self.assertFalse(engine._prefix)
        finally:
            if enabled: gc.enable()
        for hint in ('stomp', 'rdp'):
            self.assert_rejected(b'unknown data\r\n' * 20, protocol_hint=hint)

    def test_seeded_arbitrary_protocol_bodies_do_not_crash(self):
        rng = random.Random(71019)
        for prefix in (b'CONNECT\n', b'INFO ', b'* CAPABILITY ', b'\x03\x00'):
            for length in range(150):
                data = prefix + bytes(rng.randrange(256) for _ in range(length)) + b'\r\n\x00'
                whole = inspect(data)
                fragmented = Inspector()
                for index in range(0, len(data), 3):
                    fragmented.feed(data[index:index + 3])
                whole.end(); fragmented.end()
                self.assertEqual(whole.observation, fragmented.observation)


if __name__ == '__main__':
    unittest.main()
