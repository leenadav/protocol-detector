"""Database wire semantics, independent published vectors and candidate provenance."""
import contextlib
import gc
import io
import json
import random
import struct
import subprocess
import sys
import unittest
import weakref
from pathlib import Path
from protocol_engine import Config, Inspector
from protocol_engine.bson import BSONValidator
from protocol_engine.database import crc32c
from protocol_engine.parsers import ParseError
from protocol_fixtures import MYSQL, MONGODB, HINTED_STREAM_CASES, STREAM_CASES


def document(*elements):
    data = b''.join(elements)
    return struct.pack('<i', len(data) + 5) + data + b'\0'


def element(kind, name, data):
    return bytes([kind]) + name.encode() + b'\0' + data


def string(value):
    return struct.pack('<i', len(value) + 1) + value + b'\0'


def command(*extra):
    return document(element(16, 'ping', struct.pack('<i', 1)), element(2, '$db', string(b'admin')), *extra)


def sequence(name, *documents):
    data = name.encode() + b'\0' + b''.join(documents)
    return b'\1' + struct.pack('<i', len(data) + 4) + data


def mongo(sections=None, flags=0, response=0):
    if sections is None:
        sections = b'\0' + command()
    data = struct.pack('<iiiiI', 20 + len(sections) + (4 if flags & 1 else 0), 123, response, 2013, flags) + sections
    return data + struct.pack('<I', crc32c(data)) if flags & 1 else data


def inspect(data, hint='mongodb', **kwargs):
    result = Inspector(protocol_hint=hint, **kwargs)
    result.feed(data)
    return result


class DatabaseTests(unittest.TestCase):
    def test_catalog_marks_explicit_selection_and_hints_remain_context(self):
        from protocol_engine import supported_protocols
        self.assertEqual({entry.family for entry in supported_protocols() if entry.requires_hint}, {'mysql', 'mongodb', 'ntp', 'radius'})
        result = inspect(MONGODB, source='decrypted').observation
        self.assertTrue(any(e.field == 'application_protocol' and e.source == 'decrypted' for e in result.evidence))
        self.assertTrue(any(e.field == 'candidate_hint' and e.strength == 'context' for e in result.evidence))
        self.assertFalse(any(e.field == 'encryption' for e in result.evidence))

    def assert_identified(self, data, hint='mongodb', **kwargs):
        engine = inspect(data, hint, **kwargs)
        result = engine.observation
        self.assertEqual((result.status, result.application_protocol), ('identified', hint), result)
        self.assertIsNone(result.application)
        self.assertIsNone(result.hostname)
        self.assertIsNone(result.encryption)
        self.assertTrue(any(e.field == 'candidate_hint' and e.value == hint and e.source == 'caller' and e.strength == 'context' for e in result.evidence))
        return engine

    def test_database_all_split_points_bytewise_and_eof(self):
        for data, protocol, hint in HINTED_STREAM_CASES:
            expected = self.assert_identified(data, hint).observation
            for split in range(len(data) + 1):
                engine = Inspector(protocol_hint=hint)
                engine.feed(data[:split]); engine.feed(data[split:])
                self.assertEqual(engine.observation, expected)
                self.assertEqual(engine.metrics.bytes_inspected, len(data))
                self.assertEqual(engine.metrics.candidates_selected, 1)
            engine = Inspector(protocol_hint=hint)
            for byte in data:
                self.assertEqual(engine.observation.status, 'detecting')
                engine.feed(bytes([byte]))
            self.assertEqual(engine.observation, expected)
            for size in range(len(data)):
                partial = inspect(data[:size], hint);partial.end()
                self.assertEqual(partial.observation.status, 'incomplete')

    def test_candidate_is_required_and_wrong_candidate_never_identifies(self):
        for data, _, hint in HINTED_STREAM_CASES:
            self.assertNotEqual(inspect(data, None).observation.status, 'identified')
            for other in ('mysql', 'mongodb'):
                if other != hint:
                    self.assertNotEqual(inspect(data, other).observation.status, 'identified')
        for hint in ('mysql', 'mongodb'):
            for data, _ in STREAM_CASES:
                self.assertNotEqual(inspect(data, hint).observation.status, 'identified')

    def test_completed_inspection_releases_state_and_skips_later_messages(self):
        enabled = gc.isenabled();gc.disable()
        try:
            for data, _, hint in HINTED_STREAM_CASES:
                engine = inspect(data[:-1], hint)
                reference = weakref.ref(engine._parser)
                engine.feed(data[-1:] + b'private-database-value' * 100)
                self.assertIsNone(reference())
                self.assertEqual(engine.metrics.bytes_inspected, len(data))
                calls = engine.metrics.parser_calls
                engine.feed(b'later' * 10000)
                self.assertEqual(engine.metrics.parser_calls, calls)
                self.assertNotIn('private-database-value', repr(engine.observation))
        finally:
            if enabled:gc.enable()

    def test_mysql_plugin_variants_and_no_version_identity(self):
        for plugin in (b'mysql_native_password', b'caching_sha2_password', b'sha256_password'):
            payload = MYSQL[4:].replace(b'caching_sha2_password', plugin)
            data = len(payload).to_bytes(3, 'little') + b'\0' + payload
            result = self.assert_identified(data, 'mysql').observation
            self.assertNotIn('8.0.36-demo', repr(result))
            self.assertEqual(result.scope, 'protocol_header')
            self.assertTrue(any(e.field == 'mysql_tls_supported' and e.value == 'true' and e.strength == 'offered' for e in result.evidence))

    def test_mysql_header_lengths_reserved_fields_and_unsupported_profiles(self):
        start = MYSQL.index(b'\0', 5) + 1
        for offset, byte in ((3, 1), (start + 12, 1), (start + 15, 0), (start + 21, 1), (start + 43, 1), (len(MYSQL) - 1, 1)):
            data = bytearray(MYSQL);data[offset] = byte
            self.assertNotEqual(inspect(bytes(data), 'mysql').observation.status, 'identified', offset)
        for offset, byte in ((4, 9), (start + 20, 0), (start + 14, 0), (start + 18, 0)):
            data = bytearray(MYSQL);data[offset] = byte
            self.assertEqual(inspect(bytes(data), 'mysql').observation.status, 'unknown')
        self.assertEqual(inspect(b'\xff\xff\xff\0', 'mysql').observation.status, 'budget_exhausted')
        self.assertEqual(inspect(b'\x01\0\0\0', 'mysql').observation.status, 'malformed')
        payload = MYSQL[4:] + b'extra'
        self.assertEqual(inspect(len(payload).to_bytes(3, 'little') + b'\0' + payload, 'mysql').observation.status, 'malformed')

    def test_mongo_sections_in_either_order_and_reply(self):
        seq = sequence('documents', document(element(16, '_id', struct.pack('<i', 1))))
        for sections in (b'\0' + command(), seq + b'\0' + command(), b'\0' + command() + seq,
                         sequence('documents') + b'\0' + command()):
            self.assert_identified(mongo(sections))
        self.assert_identified(mongo(b'\0' + document(element(1, 'ok', struct.pack('<d', 1))), response=123))
        self.assert_identified(mongo(flags=0x80000000))  # Unknown optional bits ignored by observer.
        for data in (mongo(b'\0' + command() + b'\0' + command()), mongo(seq),
                     mongo(seq + seq + b'\0' + command()),
                     mongo(seq + b'\0' + command(element(4, 'documents', document()))),
                     mongo(b'\0' + document(element(16, 'hello', struct.pack('<i', 1)))),
                     mongo(b'\0' + document(element(2, '$db', string(b'admin')), element(16, 'hello', struct.pack('<i', 1)))),
                     mongo(b'\0' + document(element(16, 'hello', struct.pack('<i', 1)), element(2, '$db', string(b'')))),
                     mongo(flags=0x10000, response=123)):
            self.assertEqual(inspect(data).observation.status, 'malformed')
        for data in (mongo(b'\3' + command()), mongo(sequence('nested.path') + b'\0' + command()), mongo(flags=4)):
            self.assertEqual(inspect(data).observation.status, 'unknown')

    def test_mongo_checksum_against_published_crc_vectors_and_corruption(self):
        # RFC3720 B.4, bytes as published (not generated by our encoder).
        for data, expected in ((bytes(32), 'aa36918a'), (b'\xff' * 32, '43aba862'),
                               (bytes(range(32)), '4e79dd46'), (bytes(reversed(range(32))), '5cdb3f11')):
            self.assertEqual(crc32c(data).to_bytes(4, 'little').hex(), expected)
        valid = mongo(flags=1)
        self.assert_identified(valid)
        for offset in (4, 24, len(valid) - 1):
            bad = bytearray(valid);bad[offset] ^= 1
            self.assertEqual(inspect(bytes(bad)).observation.status, 'malformed')

    def test_crc_chunk_tails_and_checksum_budget_are_explicit(self):
        # Independent bit-at-a-time oracle exercises every slicing-by-eight tail.
        rng = random.Random(83019)
        for length in range(100):
            data = bytes(rng.randrange(256) for _ in range(length))
            value = 0xffffffff
            for byte in data:
                value ^= byte
                for _ in range(8):value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
            self.assertEqual(crc32c(data), value ^ 0xffffffff)
        data = mongo(flags=1)
        self.assert_identified(data, config=Config(max_crc32c_bytes=len(data)-4))
        for limit in (0, len(data)-5):
            self.assertEqual(inspect(data, config=Config(max_crc32c_bytes=limit)).observation.status, 'budget_exhausted')
        large = mongo(b'\0' + command(element(5, 'data', struct.pack('<iB', 5000, 0) + bytes(5000))), flags=1)
        self.assertEqual(inspect(large).observation.status, 'budget_exhausted')
        header_only = inspect(large[:20])
        self.assertEqual(header_only.observation.status, 'budget_exhausted')
        self.assertIsNone(header_only._parser)
        self.assert_identified(large, config=Config(max_crc32c_bytes=65536))
        for value in (-1, True, 1.5, 1048577):
            with self.assertRaises(ValueError):Config(max_crc32c_bytes=value)

    def test_bson_published_boolean_and_document_vectors(self):
        # Small hexadecimal fixtures from the MongoDB BSON corpus:
        # https://github.com/mongodb/specifications/tree/master/source/bson-corpus/tests
        valid = ('090000000862000100', '090000000862000000',
                 '0D000000037800050000000000', '150000000378000D00000002000200000062000000',
                 '160000000378000E0000000261000200000062000000',
                 '180000000378001000000002612E62000200000063000000')
        invalid = ('090000000862000200', '09000000086200FF00',
                   '1800000003666F6F000F0000001062617200FFFFFF7F0000',
                   '1500000003666F6F000A0000000862617200010000',
                   '1C00000003666F6F001200000002626172000500000062617A000000',
                   '150000000378000D00000010610000010000000000')
        for encoded in valid:
            data = bytes.fromhex(encoded)
            end, _ = BSONValidator(data, Config()).document(0, len(data))
            self.assertEqual(end, len(data))
        for encoded in invalid:
            data = bytes.fromhex(encoded)
            with self.assertRaises(ParseError): BSONValidator(data, Config()).document(0, len(data))

    def test_bson_all_scalar_types_and_nested_values(self):
        fixed = ((1, struct.pack('<d', float('nan'))), (6, b''), (7, bytes(12)), (8, b'\1'),
                 (9, bytes(8)), (10, b''), (16, bytes(4)), (17, bytes(8)), (18, bytes(8)),
                 (19, bytes(16)), (127, b''), (255, b''))
        scoped = string(b'not executed') + document(element(16, 'x', bytes(4)))
        values = fixed + ((2, string('שלום\0world'.encode())), (3, document(element(10, '', b''))),
                          (4, document(element(10, '0', b''), element(8, '1', b'\0'))),
                          (5, struct.pack('<iB', 3, 0) + b'abc'), (11, b'pattern\0im\0'),
                          (12, string(b'namespace') + bytes(12)), (13, string(b'code')),
                          (14, string(b'symbol')), (15, struct.pack('<i', len(scoped) + 4) + scoped))
        for kind, value in values:
            self.assert_identified(mongo(b'\0' + command(element(kind, 'x', value))))

    def test_bson_invalid_encodings_lengths_and_duplicates(self):
        scoped = string(b'code') + document()
        bad_values = ((2, struct.pack('<i', 0)), (2, string(b'\xff')), (8, b'\2'),
                      (4, document(element(10, '1', b''))), (4, document(element(10, '00', b''))),
                      (5, struct.pack('<iB', -1, 0)), (5, struct.pack('<iB', 0, 4)),
                      (5, struct.pack('<iB', 4, 2) + struct.pack('<i', 1)),
                      (5, struct.pack('<iB', 0, 10)), (11, b'pattern\0mi\0'),
                      (11, b'pattern\0ii\0'), (11, b'pattern\0z\0'), (20, b''),
                      (15, struct.pack('<i', len(scoped) + 5) + scoped + b'\0'),
                      (3, document(element(10, 'same', b''), element(10, 'same', b''))))
        for kind, value in bad_values:
            self.assertEqual(inspect(mongo(b'\0' + command(element(kind, 'x', value)))).observation.status, 'malformed', kind)
        self.assertEqual(inspect(mongo(b'\0' + command(element(16, 'ping', bytes(4))))).observation.status, 'malformed')

    def test_bson_valid_binary_subtypes_and_no_payload_disclosure(self):
        for subtype in tuple(range(10)) + (128, 255):
            value = bytes(16) if subtype in (3, 4, 5) else b'private-database-value'
            if subtype == 2:value = struct.pack('<i', len(value)) + value
            data = mongo(b'\0' + command(element(5, 'data', struct.pack('<iB', len(value), subtype) + value)))
            engine = self.assert_identified(data)
            self.assertNotIn('private-database-value', repr(engine.observation))

    def test_resource_budgets_before_frame_growth_and_during_nested_validation(self):
        for size in (65537, 0x7fffffff):
            engine = inspect(struct.pack('<iiiiI', size, 1, 0, 2013, 0))
            self.assertEqual(engine.observation.status, 'budget_exhausted')
            self.assertIsNone(engine._parser)
        for size in (-1, 0, 25):
            self.assertEqual(inspect(struct.pack('<iiiiI', size, 1, 0, 2013, 0)).observation.status, 'malformed')
        nested = document()
        for _ in range(16):nested = document(element(3, 'x', nested))
        cases = (mongo(b'\0' + command(element(3, 'nested', nested))),
                 mongo(b'\0' + command(*(element(10, 'x' + str(i), b'') for i in range(129)))),
                 mongo(sequence('documents', *(document() for _ in range(129))) + b'\0' + command()),
                 mongo(b'\0' + command(element(10, 'x' * 1025, b''))))
        for data in cases:self.assertEqual(inspect(data).observation.status, 'budget_exhausted')
        self.assertEqual(inspect(MONGODB, config=Config(max_headers=1)).observation.status, 'budget_exhausted')
        self.assertEqual(inspect(MYSQL, 'mysql', config=Config(max_bytes=64)).observation.status, 'budget_exhausted')

    def test_seeded_mutations_and_random_frames_do_not_crash(self):
        rng = random.Random(81019)
        bases = HINTED_STREAM_CASES + ((mongo(flags=1), 'mongodb', 'mongodb'),)
        for base, _, hint in bases:
            for _ in range(300):
                data = bytearray(base);data[rng.randrange(len(data))] = rng.randrange(256);data = bytes(data)
                whole = inspect(data, hint)
                partial = Inspector(protocol_hint=hint)
                for pos in range(0, len(data), 3):partial.feed(data[pos:pos + 3])
                whole.end();partial.end()
                self.assertEqual(whole.observation, partial.observation)
                self.assertLessEqual(partial.metrics.bytes_inspected, len(data))
                self.assertLessEqual(partial.metrics.candidates_selected, 1)
        for size in range(300):
            random_bytes = bytes(rng.randrange(256) for _ in range(size))
            inspect(mongo(b'\0' + random_bytes))
            inspect(size.to_bytes(3, 'little') + b'\0' + random_bytes, 'mysql')

    def test_capture_candidates_reassemble_and_preserve_context_without_port_inference(self):
        from live_capture import CaptureMonitor, readable
        from capture_stream import CaptureRecord
        from make_sample_pcap import database_frames
        for hint in ('mysql', 'mongodb'):
            events = [];monitor = CaptureMonitor(events.append, tcp_hint=hint)
            automatic = CaptureMonitor(lambda event:None)
            for index, data in enumerate(database_frames(hint)):
                record = CaptureRecord(index, data, len(data), 1)
                monitor.accept(record, index);automatic.accept(record, index)
            self.assertEqual(monitor.counts['identified'], 1)
            self.assertEqual(automatic.counts['identified'], 0)
            self.assertEqual(events[-1]['candidate_hint'], hint)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):readable(events[-1])
            self.assertIn('[candidate: ' + hint + ']', output.getvalue())
        with self.assertRaises(ValueError):CaptureMonitor(lambda event:None, tcp_hint='invalid')

    def test_cli_live_stdin_and_offline_hint_paths(self):
        import tempfile
        from make_sample_pcap import database_frames, pcap_bytes
        root = Path(__file__).parent
        for hint in ('mysql', 'mongodb'):
            data = pcap_bytes(database_frames(hint))
            output = subprocess.check_output([sys.executable, '-B', str(root/'live_capture.py'), '--stdin', '--duration', '0', '--json', '--tcp-hint', hint], input=data)
            rows = [json.loads(line) for line in output.splitlines()]
            self.assertEqual(rows[-1]['counts']['identified'], 1)
            self.assertEqual(rows[0]['tcp_hint'], hint)
            self.assertTrue(any(row.get('candidate_hint') == hint for row in rows))
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory)/'database.pcap';path.write_bytes(data)
                output = subprocess.check_output([sys.executable, '-B', str(root/'analyze_pcap.py'), str(path), '--json', '--events-only', '--tcp-hint', hint])
                rows = [json.loads(line) for line in output.splitlines()]
                self.assertEqual(rows[0]['classification']['application_protocol'], hint)

    def test_checksum_budget_reaches_capture_cli_and_never_skips_validation(self):
        from make_sample_pcap import frame, pcap_bytes, A, B
        data = mongo(flags=1)
        capture = pcap_bytes([frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, 1000, 9000, 24, data)])
        root = Path(__file__).parent
        for limit, status in ((0, 'budget_exhausted'), (4096, 'identified')):
            output = subprocess.check_output([sys.executable, '-B', str(root/'live_capture.py'), '--stdin', '--duration', '0', '--json', '--all-events', '--tcp-hint', 'mongodb', '--crc32c-byte-limit', str(limit)], input=capture)
            rows = [json.loads(line) for line in output.splitlines()]
            self.assertEqual(rows[-1]['counts'].get(status), 1)
            self.assertEqual(rows[0]['crc32c_byte_limit'], limit)
            self.assertEqual(rows[1]['status'], status)
            self.assertEqual(rows[1]['candidate_hint'], 'mongodb')


if __name__ == '__main__':
    unittest.main()
