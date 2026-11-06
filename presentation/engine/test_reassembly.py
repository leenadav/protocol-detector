"""Independent byte-map oracle for bounded initial-prefix reassembly."""
import random
import tracemalloc
import unittest
from sessions import Stream, StreamError, MODULUS


class RecordingInspector:
    def __init__(self):
        self.chunks = []
        self.invalidations = []

    def feed(self, data):
        self.chunks.append(data)
        return (data,)

    def invalidate(self, reason):
        self.invalidations.append(reason)
        return ('invalidated',)


class ReassemblyTests(unittest.TestCase):
    def stream(self, size=128, first=0, prefix_only=False):
        return Stream(first, size, RecordingInspector, False, prefix_only)

    def assert_state(self, stream, expected):
        ready = 0
        while ready in expected:
            ready += 1
        self.assertEqual(stream.stored, len(expected))
        self.assertEqual(stream.contiguous, ready)
        self.assertEqual(stream.highest_end, max(expected, default=-1) + 1)
        self.assertEqual(bytes(stream.present), bytes(int(i in expected) for i in range(stream.limit)))
        for i, value in expected.items():
            self.assertEqual(stream.buffer[i], value)
        self.assertEqual(b''.join(stream.inspector.chunks), bytes(expected[i] for i in range(ready)))
        self.assertTrue(all(stream.inspector.chunks))
        self.assertEqual(len(stream.buffer), stream.limit)
        self.assertEqual(len(stream.present), stream.limit)

    def test_exhaustive_small_window_presence_and_all_intervals(self):
        # All 256 arrangements of holes, every nonempty interval. The oracle
        # stores individual bytes independently of the production bitmap code.
        data = bytes(range(8))
        for mask in range(256):
            for start in range(8):
                for end in range(start + 1, 9):
                    stream = self.stream(8)
                    expected = {}
                    for i in reversed(range(8)):
                        if mask & (1 << i):
                            stream.feed(i, data[i:i + 1])
                            expected[i] = data[i]
                    old_ready = stream.contiguous
                    old_calls = len(stream.inspector.chunks)
                    stream.feed(start, data[start:end])
                    expected.update((i, data[i]) for i in range(start, end))
                    self.assert_state(stream, expected)
                    self.assertEqual(len(stream.inspector.chunks) - old_calls,
                                     int(stream.contiguous > old_ready))

    def test_seeded_overlaps_reordering_duplicates_and_wrap(self):
        rng = random.Random(11011)
        for prefix_only in (False, True):
            for first in (0, MODULUS - 33):
                for _ in range(30):
                    data = bytes(rng.randrange(256) for _ in range(257))
                    stream = self.stream(257, first, prefix_only)
                    expected = {}
                    for _ in range(100):
                        start = rng.randrange(257)
                        end = min(257, start + rng.randrange(1, 100))
                        payload = data[start:end]
                        if prefix_only and end == 257:
                            payload += b'ignored bytes'
                        stream.feed((first + start) % MODULUS, payload)
                        expected.update((i, data[i]) for i in range(start, end))
                        self.assert_state(stream, expected)
                    stream.feed(first, data)
                    self.assert_state(stream, dict(enumerate(data)))

    def test_conflicts_are_atomic_even_after_new_bytes_and_before_gap_fill(self):
        for occupied in ((127,), (0, 127), tuple(range(1, 128, 2)), tuple(range(128))):
            for bad_index in (occupied[0], occupied[-1]):
                stream = self.stream()
                for i in reversed(occupied):
                    stream.feed(i, b'A')
                before = (bytes(stream.buffer), bytes(stream.present), stream.stored,
                          stream.contiguous, stream.highest_end, tuple(stream.inspector.chunks))
                payload = bytearray(b'A' * 128)
                payload[bad_index] = ord('B')
                with self.assertRaises(StreamError):
                    stream.feed(0, bytes(payload))
                self.assertEqual(before, (bytes(stream.buffer), bytes(stream.present), stream.stored,
                                         stream.contiguous, stream.highest_end, tuple(stream.inspector.chunks)))
                self.assertEqual(stream.events, ('invalidated',))
                self.assertEqual(len(stream.inspector.invalidations), 1)
                with self.assertRaises(StreamError):
                    stream.feed(0, b'A')
                self.assertEqual(stream.events, ())
                self.assertEqual(len(stream.inspector.invalidations), 1)

    def test_pending_duplicate_does_not_feed_or_inflate_counts(self):
        stream = self.stream()
        stream.feed(50, b'A' * 78)
        for _ in range(20):
            stream.feed(50, b'A' * 78)
            self.assertEqual(stream.events, ())
        self.assertEqual(stream.stored, 78)
        self.assertEqual(stream.inspector.chunks, [])
        stream.feed(0, b'A' * 50)
        self.assertEqual(stream.inspector.chunks, [b'A' * 128])

    def test_clipped_overlap_validates_retained_bytes_only(self):
        stream = self.stream(8, MODULUS - 4, True)
        stream.feed(0, b'EFGH')
        stream.feed(MODULUS - 4, b'ABCDEFGHignored')
        stream.feed(0, b'EFGHdifferent outside window')
        stream.feed(4, b'any later payload')
        self.assert_state(stream, dict(enumerate(b'ABCDEFGH')))
        self.assertEqual(stream.events, ())
        with self.assertRaises(StreamError):
            stream.feed(0, b'EFGXignored')

    def test_strict_outside_window_is_atomic(self):
        stream = self.stream(8)
        stream.feed(4, b'EFGH')
        before = bytes(stream.buffer), bytes(stream.present), stream.stored
        with self.assertRaises(StreamError):
            stream.feed(0, b'ABCDEFGHI')
        self.assertEqual(before, (bytes(stream.buffer), bytes(stream.present), stream.stored))
        self.assertEqual(stream.inspector.chunks, [])

    def test_zero_filled_payload_and_many_isolated_holes(self):
        stream = self.stream(65536)
        for i in range(1, 65536, 2):
            stream.feed(i, b'\0')
        stream.feed(0, bytes(65536))
        self.assertEqual(stream.stored, 65536)
        self.assertEqual(stream.contiguous, 65536)
        self.assertEqual(stream.inspector.chunks, [bytes(65536)])

    def test_large_operations_have_window_bounded_temporary_memory(self):
        stream = self.stream(65536)
        payload = b'A' * 65536
        tracemalloc.start()
        try:
            stream.feed(1, payload[1:])
            stream.feed(0, payload[:1])
            for _ in range(100):
                stream.feed(0, payload)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        # Includes the recorder retaining its emitted prefix. No per-byte
        # Python list, interval tree or history accumulating on retransmission.
        self.assertLess(peak, 6 * stream.limit)
        self.assertEqual(stream.inspector.chunks, [payload])

    def test_late_conflict_invalidates_real_identification(self):
        stream = Stream(0, 128, compatibility=False)
        request = b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'
        stream.feed(10, request[10:])
        stream.feed(0, request[:10])
        self.assertEqual(stream.inspector.observation.status, 'identified')
        stream.feed(0, request)
        self.assertEqual(stream.events, ())
        with self.assertRaises(StreamError):
            stream.feed(len(request)-1, b'X')
        self.assertEqual(stream.inspector.observation.status, 'invalidated')


if __name__ == '__main__':
    unittest.main()
