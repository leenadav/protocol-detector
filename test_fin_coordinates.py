"""Absolute-coordinate oracle for payload/FIN comparisons around the origin."""
import unittest

from analyze_pcap import Analyzer
from capture_stream import CaptureRecord
from live_capture import CaptureMonitor
from make_sample_pcap import A, B, REQUEST, frame
from packets import decode_packet

MOD = 2**32


class FinCoordinateTests(unittest.TestCase):
    def ready(self, first, boundary, prefill=False):
        analyzer = Analyzer(compact=True, byte_limit=64)
        packets = [frame(A, B, (first-1) % MOD, 0, 2), frame(B, A, 8999, first, 18)]
        if prefill:
            packets.append(frame(A, B, first, 9000, 24, REQUEST))
        packets.append(frame(A, B, (first+boundary) % MOD, 9000, 17))
        for i, packet in enumerate(packets):
            analyzer.process(i, decode_packet(packet))
        self.assertTrue(analyzer.tracked)
        return analyzer

    def test_absolute_end_oracle_after_observed_fin(self):
        # No modular arithmetic in the oracle: offsets are independent absolute
        # positions relative to the retained origin, before encoding wire seqs.
        for first in (0, 1000, MOD-8):
            for boundary, prefill in ((0, False), (8, False), (40, True), (64, True), (80, True)):
                for start in (-10, -5, -1, 0, 1, 7, 8, 39, 40, 63, 64, 79, 80, 85):
                    for length in (0, 1, 4, 12):
                        for fin in (False, True):
                            with self.subTest(first=first, boundary=boundary, start=start, length=length, fin=fin):
                                analyzer = self.ready(first, boundary, prefill)
                                end = start + length
                                rejected = (length > 0 and end > boundary) or (fin and end != boundary)
                                payload = bytes(REQUEST[i] if 0 <= i < len(REQUEST) else 88
                                                for i in range(start, end))
                                packet = frame(A, B, (first+start) % MOD, 9000, 25 if fin else 24, payload)
                                message = analyzer.process(10, decode_packet(packet))
                                self.assertEqual(message.startswith('INVALIDATED'), rejected)
                                self.assertEqual(bool(analyzer.tracked), not rejected)
                                if rejected:
                                    self.assertEqual(analyzer.last_classification.status, 'invalidated')
                                else:
                                    connection = next(iter(analyzer.manager.connections.values()))
                                    stream = connection['directions'][A]
                                    before = set(range(len(REQUEST))) if prefill else set()
                                    retained = before | set(range(max(0, start), min(64, end)))
                                    self.assertEqual(stream.stored, len(retained))
                                    self.assertEqual(stream.highest_end, max(retained, default=-1)+1)

    def test_live_old_payload_does_not_retract_completed_direction(self):
        for first in (0, 1, 1000, MOD-8):
            events = []
            monitor = CaptureMonitor(events.append)
            packets = [frame(A,B,(first-1)%MOD,0,2), frame(B,A,8999,first,18),
                       frame(A,B,first,9000,25,REQUEST), frame(A,B,(first-3)%MOD,9000,24,b'XX')]
            for i, packet in enumerate(packets):
                monitor.accept(CaptureRecord(i, packet, len(packet), 1), i)
            self.assertEqual([e['status'] for e in events], ['identified'])
            self.assertEqual(monitor.counts['invalidated'], 0)
            self.assertTrue(monitor.analyzer.tracked)
            # A crossing segment whose retained end really exceeds FIN still
            # retracts; ignoring the entire leading segment would be unsafe.
            bad = frame(A,B,(first-3)%MOD,9000,24,b'old'+REQUEST+b'X')
            monitor.accept(CaptureRecord(5, bad, len(bad), 1), 5)
            self.assertEqual([e['status'] for e in events], ['identified', 'invalidated'])
