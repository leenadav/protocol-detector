"""Review regression: a pre-origin FIN must not become a future boundary."""
import unittest

from analyze_pcap import Analyzer
from capture_stream import CaptureRecord
from live_capture import CaptureMonitor
from make_sample_pcap import A, B, REQUEST, frame
from packets import decode_packet

MOD = 2**32


def packets(first, offset, payload=b'', identified=False):
    result = [frame(A, B, (first-1) % MOD, 0, 2), frame(B, A, 8999, first, 18)]
    if identified:
        result.append(frame(A, B, first, 9000, 24, REQUEST))
    result.append(frame(A, B, (first+offset) % MOD, 9000, 25, payload))
    return result


class FinOriginTests(unittest.TestCase):
    def test_wholly_pre_origin_fin_cannot_authorize_later_data(self):
        for first in (0, 1, 1000, MOD-8):
            for offset, payload in ((-1, b''), (-2, b'X'), (-30, b'old'), (-2**31, b'')):
                with self.subTest(first=first, offset=offset):
                    analyzer = Analyzer(compact=True)
                    for i, data in enumerate(packets(first, offset, payload)):
                        message = analyzer.process(i, decode_packet(data))
                    self.assertTrue(message.startswith('INVALIDATED'))
                    self.assertEqual(analyzer.last_classification.status, 'invalidated')
                    self.assertFalse(analyzer.tracked)
                    self.assertFalse(analyzer.manager.connections)
                    message = analyzer.process(10, decode_packet(frame(A, B, first, 9000, 24, REQUEST)))
                    self.assertTrue(message.startswith('SKIP'))
                    self.assertIsNone(analyzer.last_classification)

    def test_pre_origin_fin_retracts_already_identified_direction(self):
        for first in (0, 1, 1000, MOD-8):
            events = []
            monitor = CaptureMonitor(events.append)
            for i, data in enumerate(packets(first, -2, b'X', identified=True)):
                monitor.accept(CaptureRecord(i, data, len(data), 1), i)
            self.assertEqual([e['status'] for e in events], ['identified', 'invalidated'])
            self.assertEqual(monitor.counts['invalidated'], 1)
            self.assertFalse(monitor.analyzer.tracked)

    def test_fin_ending_at_origin_closes_empty_direction(self):
        for first in (0, 1, 1000, MOD-8):
            analyzer = Analyzer(compact=True)
            for i, data in enumerate(packets(first, -3, b'old')):
                analyzer.process(i, decode_packet(data))
            self.assertEqual(analyzer.last_classification.status, 'incomplete')
            state = next(iter(analyzer.tracked.values()))
            self.assertEqual(state['fin'][A], 0)
            result = analyzer.process(10, decode_packet(frame(A, B, first, 9000, 24, REQUEST)))
            self.assertTrue(result.startswith('INVALIDATED'))
            self.assertEqual(analyzer.last_classification.status, 'invalidated')

    def test_crossing_origin_and_unambiguous_future_fin_remain_supported(self):
        for first in (0, 1, 1000, MOD-8):
            analyzer = Analyzer(compact=True)
            for i, data in enumerate(packets(first, -3, b'old' + REQUEST)):
                analyzer.process(i, decode_packet(data))
            self.assertEqual(analyzer.last_classification.status, 'identified')
            self.assertEqual(next(iter(analyzer.tracked.values()))['fin'][A], len(REQUEST))
            analyzer = Analyzer(compact=True)
            for i, data in enumerate(packets(first, 2**31-1)):
                analyzer.process(i, decode_packet(data))
            self.assertEqual(next(iter(analyzer.tracked.values()))['fin'][A], 2**31-1)
            analyzer.process(10, decode_packet(frame(A, B, first, 9000, 24, REQUEST)))
            self.assertEqual(analyzer.last_classification.status, 'identified')

    def test_pre_origin_payload_without_fin_is_still_ignored(self):
        analyzer = Analyzer(compact=True)
        sequence = packets(0, -2, b'X')
        sequence[-1] = frame(A, B, MOD-2, 9000, 24, b'X')
        for i, data in enumerate(sequence):
            analyzer.process(i, decode_packet(data))
        self.assertTrue(analyzer.tracked)
        analyzer.process(10, decode_packet(frame(A, B, 0, 9000, 24, REQUEST)))
        self.assertEqual(analyzer.last_classification.status, 'identified')
