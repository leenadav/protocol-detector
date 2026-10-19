"""Observed TCP FIN boundaries (RFC9293 3.4) versus capture/timeout boundaries."""
import gc
import io
from contextlib import redirect_stdout
import tempfile
import unittest
import weakref
from analyze_pcap import Analyzer
from capture_stream import CaptureRecord
from live_capture import CaptureMonitor, readable, run_capture
from make_sample_pcap import A, B, REQUEST, frame, pcap_bytes
from packets import decode_tcp
from protocol_engine import Inspector
from sessions import Stream
from proxy_demo import client_hello


class LifecycleTests(unittest.TestCase):
    def ready(self, first=1000, server=9000, **kwargs):
        analyzer = Analyzer(**kwargs)
        analyzer.process(0, decode_tcp(frame(A, B, (first - 1) % 2**32, 0, 2)))
        analyzer.process(0, decode_tcp(frame(B, A, (server - 1) % 2**32, first, 18)))
        return analyzer

    def send(self, analyzer, source=A, sequence=1000, flags=24, data=b'', now=1):
        destination, ack = (B, 9000) if source == A else (A, 1000)
        return analyzer.process(now, decode_tcp(frame(source, destination, sequence % 2**32, ack, flags, data)))

    def stream(self, analyzer, source=A):
        return analyzer.manager.connections[analyzer.manager.key(A, B)]['directions'][source]

    def test_partial_fin_and_duplicate_fin_finish_only_once(self):
        analyzer = self.ready()
        self.send(analyzer, flags=25, data=b'GET / HTTP/1.1\r\n')
        self.assertEqual(analyzer.last_classification.status, 'incomplete')
        self.assertIn('contiguous TCP FIN', analyzer.last_classification.reason)
        self.assertEqual(len(analyzer.last_events), 1)
        self.assertIsNone(self.stream(analyzer).inspector._parser)
        self.send(analyzer, flags=25, data=b'GET / HTTP/1.1\r\n')
        self.assertEqual(analyzer.last_events, ())
        self.assertTrue(analyzer.tracked)

    def test_fin_with_gap_waits_and_then_identifies(self):
        analyzer = self.ready()
        self.send(analyzer, sequence=1000 + len(REQUEST), flags=17)
        self.assertEqual(analyzer.last_classification.status, 'detecting')
        self.send(analyzer, sequence=1011, data=REQUEST[11:])
        self.assertEqual(analyzer.last_classification.status, 'detecting')
        self.send(analyzer, data=REQUEST[:11])
        self.assertEqual(analyzer.last_classification.application_protocol, 'http/1.1')
        self.assertEqual(len(analyzer.last_events), 1)
        self.assertTrue(analyzer.tracked)  # Only one direction closed.

    def test_fin_with_gap_then_incomplete_after_contiguous_fill(self):
        analyzer = self.ready()
        partial = REQUEST[:-2]
        self.send(analyzer, sequence=1000 + len(partial), flags=17)
        self.send(analyzer, data=partial)
        self.assertEqual(analyzer.last_classification.status, 'incomplete')
        self.assertEqual(len(analyzer.last_events), 1)

    def test_half_close_does_not_end_opposite_direction(self):
        analyzer = self.ready()
        self.send(analyzer, flags=17)
        self.assertEqual(self.stream(analyzer).inspector.observation.status, 'incomplete')
        self.assertEqual(self.stream(analyzer, B).inspector.observation.status, 'detecting')
        self.send(analyzer, source=B, sequence=9000, flags=25, data=b'SSH-2.0-demo\r\n')
        self.assertEqual(analyzer.last_classification.application_protocol, 'ssh')
        self.assertFalse(analyzer.tracked)
        self.assertFalse(analyzer.manager.connections)

    def test_fin_sequence_wrap_and_conflicting_late_retransmission(self):
        first = 2**32 - 8
        analyzer = self.ready(first=first)
        self.send(analyzer, sequence=first + len(REQUEST), flags=17)
        self.send(analyzer, sequence=first, data=REQUEST)
        self.assertEqual(analyzer.last_classification.status, 'identified')
        message = self.send(analyzer, sequence=first, data=b'X')
        self.assertIn('INVALIDATED', message)
        self.assertEqual(analyzer.last_classification.status, 'invalidated')
        self.assertFalse(analyzer.tracked)

    def test_data_beyond_fin_and_changed_fin_are_rejected(self):
        for sequence, flags, data in ((1000, 24, b'X'), (1001, 17, b'')):
            analyzer = self.ready()
            self.send(analyzer, flags=17)
            self.assertIn('INVALIDATED', self.send(analyzer, sequence=sequence, flags=flags, data=data))
            self.assertFalse(analyzer.tracked)

    def test_fin_rejects_stored_tail_even_when_gap_prevents_inspection(self):
        analyzer = self.ready()
        self.send(analyzer, sequence=1020, data=b'abc')
        self.assertEqual(self.stream(analyzer).highest_end, 23)
        self.assertEqual(self.stream(analyzer).contiguous, 0)
        self.assertIn('INVALIDATED', self.send(analyzer, sequence=1022, flags=17))

    def test_highest_retained_end_matches_presence_without_scanning_in_hot_path(self):
        stream = Stream(1000, 64, compatibility=False, prefix_only=True)
        for sequence, payload in ((1010, b'abc'), (1000, b'x' * 10), (1010, b'abc'),
                                  (1000, b'x' * 10), (1060, b'z' * 20), (1200, b'ignored'), (1100, b'')):
            stream.feed(sequence, payload)
            expected = max((i + 1 for i, present in enumerate(stream.present) if present), default=0)
            self.assertEqual(stream.highest_end, expected)
        self.assertEqual(stream.highest_end, 64)

    def test_capture_end_releases_states_and_records_direction_reason(self):
        retired = []
        analyzer = self.ready(on_retire=lambda source, dest, event: retired.append((source, dest, event)))
        self.send(analyzer, data=b'GET / HTTP/1.1\r\n')
        self.send(analyzer, source=B, sequence=9000, data=b'SSH-2.0-demo\r\n')
        analyzer.finish()
        self.assertFalse(analyzer.tracked)
        self.assertFalse(analyzer.manager.connections)
        self.assertEqual(len(retired), 1)
        source, dest, event = retired[0]
        self.assertEqual((source, dest), (A, B))
        self.assertEqual(event.observation.status, 'incomplete')
        self.assertIn('Capture ended', event.observation.reason)
        analyzer.finish()
        self.assertEqual(len(retired), 1)

    def test_timeout_and_rst_have_distinct_reasons(self):
        for mode in ('timeout', 'reset'):
            retired = []
            analyzer = self.ready(idle_timeout=2, on_retire=lambda a, b, event: retired.append(event))
            self.send(analyzer, data=b'GET ')
            if mode == 'timeout':
                analyzer.expire(4)
            else:
                self.send(analyzer, flags=4)
            self.assertEqual(len(retired), 2)
            self.assertTrue(all(event.observation.status == 'incomplete' for event in retired))
            self.assertTrue(all(('timeout' if mode == 'timeout' else 'RST') in event.observation.reason for event in retired))
            self.assertFalse(analyzer.tracked)

    def test_reassembly_and_inspection_budgets_agree(self):
        analyzer = self.ready(compact=True, byte_limit=64)
        data = b'GET / HTTP/1.1\r\nX-Long: ' + b'a' * 200
        self.send(analyzer, data=data)
        self.assertEqual(analyzer.last_classification.status, 'budget_exhausted')
        self.assertEqual(self.stream(analyzer).inspector.metrics.bytes_inspected, 64)
        self.assertIsNone(self.stream(analyzer).inspector._parser)
        self.send(analyzer, sequence=1000 + len(data), flags=17)
        self.assertEqual(analyzer.last_classification.status, 'budget_exhausted')
        self.assertEqual(analyzer.last_events, ())
        with self.assertRaises(ValueError):
            Analyzer(byte_limit=63)

    def test_live_regular_file_end_and_deadline_finalization(self):
        packets = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, 1000, 9000, 24, b'GET ')]
        for limit in (0, 3):
            with tempfile.TemporaryFile() as stream:
                stream.write(pcap_bytes(packets)); stream.seek(0)
                events = []
                status = run_capture(stream, events.append, duration=0, max_packets=limit, all_events=True)
            self.assertEqual(status, 0)
            closed = [event for event in events if event.get('boundary') == 'observation_retired']
            self.assertEqual(len(closed), 2)
            self.assertTrue(all(event['timestamp'] is None for event in closed))
            self.assertTrue(all(('stopped' if limit else 'input EOF') in event['reason'] for event in closed))
            self.assertEqual(events[-1]['active_connections'], 0)
            self.assertEqual(events[-1]['counts']['incomplete'], 2)

    def test_capture_gap_retracts_instead_of_fabricating_eof(self):
        events = []
        monitor = CaptureMonitor(events.append, all_events=True)
        packets = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, 1000, 9000, 24, b'GET ')]
        for index, packet in enumerate(packets):
            monitor.accept(CaptureRecord(index, packet, len(packet), 1), index)
        monitor.invalidate_all('Synthetic capture gap')
        monitor.analyzer.finish()
        self.assertFalse(any(event.get('status') == 'incomplete' for event in events))
        self.assertTrue(any(event['type'] == 'capture_gap' for event in events))

    def test_monitor_has_no_owner_callback_reference_cycle(self):
        enabled = gc.isenabled(); gc.disable()
        try:
            monitor = CaptureMonitor(lambda event: None)
            reference = weakref.ref(monitor)
            analyzer_reference = weakref.ref(monitor.analyzer)
            del monitor
            self.assertIsNone(reference())
            self.assertIsNone(analyzer_reference())
        finally:
            if enabled: gc.enable()

    def test_custom_end_reason_propagates_to_inner_and_is_bounded(self):
        engine = Inspector(); engine.feed(client_hello()); engine.feed_decrypted(b'GET ')
        engine.end('Caller stopped observation')
        self.assertEqual(engine.observation.status, 'incomplete')
        self.assertIn('Caller stopped observation', engine.observation.reason)
        for reason in ('', 'x' * 257, None, 1):
            with self.assertRaises(ValueError):
                Inspector().end(reason)
            analyzer = self.ready()
            with self.assertRaises(ValueError):
                analyzer.finish(reason)
            self.assertTrue(analyzer.tracked)
        with self.assertRaises(ValueError):
            Analyzer(udp_hint='invalid')

    def test_readable_incomplete_summary_and_reason(self):
        output = io.StringIO()
        with redirect_stdout(output):
            readable({'type': 'classification', 'status': 'incomplete', 'protocol': None,
                      'source': A, 'destination': B, 'reason': 'Capture input EOF'})
            readable({'type': 'summary', 'elapsed_seconds': 1, 'counts': {'incomplete': 2},
                      'protocols': {}, 'capture_stats': None})
        self.assertIn('Capture input EOF', output.getvalue())
        self.assertIn('incomplete=2', output.getvalue())


if __name__ == '__main__':
    unittest.main()
