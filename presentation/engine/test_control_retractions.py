"""Control-path rejection must reach consumers of classification events."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from analyze_pcap import Analyzer, analyze
from capture_stream import CaptureRecord
from live_capture import CaptureMonitor
from make_sample_pcap import A, B, REQUEST, frame, pcap_bytes
from packets import decode_packet


def cases():
    handshake = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18)]
    request = frame(A, B, 1000, 9000, 24, REQUEST)
    finished = frame(A, B, 1000, 9000, 25, REQUEST)
    response = frame(B, A, 9000, 1000, 24, b'SSH-2.0-demo\r\n')
    return {
        'beyond_fin': (handshake + [finished, frame(A, B, 1000+len(REQUEST), 9000, 24, b'X')], A),
        'changed_fin': (handshake + [finished, frame(A, B, 1001+len(REQUEST), 9000, 17)], A),
        'fin_before_data': (handshake + [request, frame(A, B, 1001, 9000, 17)], A),
        'urgent': (handshake + [request, frame(A, B, 1000, 9000, 56)], A),
        'missing_ack': (handshake + [request, frame(A, B, 1000, 9000, 8)], A),
        'changed_server_isn': (handshake + [response, frame(B, A, 8998, 1000, 18)], B),
        'bad_syn_ack': (handshake + [response, frame(B, A, 8999, 1001, 18)], B),
        'client_syn_ack': (handshake + [request, frame(A, B, 999, 9000, 18)], A),
    }


class ControlRetractionTests(unittest.TestCase):
    def test_analyzer_rejects_with_directional_event_and_releases_state(self):
        for compact in (False, True):
            for name, (packets, source) in cases().items():
                with self.subTest(compact=compact, case=name):
                    retired = []
                    analyzer = Analyzer(compact=compact, on_retire=lambda a, b, e: retired.append((a, e)))
                    for i, data in enumerate(packets):
                        message = analyzer.process(i, decode_packet(data))
                    self.assertTrue(message.startswith('INVALIDATED'))
                    self.assertIsNotNone(analyzer.last_classification)
                    self.assertEqual(analyzer.last_classification.status, 'invalidated')
                    self.assertEqual(len(analyzer.last_events), 1)
                    self.assertEqual(analyzer.last_events[0].revision, 2)
                    self.assertIsNone(analyzer.last_classification.application_protocol)
                    self.assertFalse(analyzer.tracked)
                    self.assertFalse(analyzer.manager.connections)
                    self.assertFalse(any(a == source for a, _ in retired))
                    analyzer.process(10, decode_packet(packets[-1]))
                    self.assertEqual(analyzer.last_events, ())

    def test_offline_events_only_preserves_retraction_and_frame(self):
        for name, (packets, source) in cases().items():
            for events_only in (False, True):
                with self.subTest(case=name, events_only=events_only), tempfile.TemporaryDirectory() as directory:
                    path = Path(directory)/'synthetic.pcap'
                    path.write_bytes(pcap_bytes(packets))
                    output = io.StringIO()
                    with redirect_stdout(output):
                        analyze(path, json_output=True, events_only=events_only)
                    rows = [json.loads(line) for line in output.getvalue().splitlines()]
                    directional = [r for r in rows if r.get('source') == list(source) and r.get('classification')]
                    self.assertEqual([r['classification']['status'] for r in directional], ['identified', 'invalidated'])
                    self.assertEqual(directional[-1]['frame'], 4)
                    self.assertEqual(directional[-1]['events'][0]['kind'], 'invalidated')

    def test_live_retraction_is_emitted_once_and_counted(self):
        for name, (packets, source) in cases().items():
            for all_events in (False, True):
                with self.subTest(case=name, all_events=all_events):
                    events = []
                    monitor = CaptureMonitor(events.append, all_events=all_events)
                    for i, data in enumerate(packets):
                        monitor.accept(CaptureRecord(i, data, len(data), 1), i)
                    directional = [e for e in events if e.get('source') == source]
                    self.assertEqual([e['status'] for e in directional], ['identified', 'invalidated'])
                    self.assertEqual(directional[-1]['timestamp'], 3)
                    self.assertEqual(monitor.counts['invalidated'], 1)
                    self.assertEqual(monitor.counts['stream_invalidations'], 1)
                    self.assertFalse(monitor.analyzer.tracked)

    def test_normal_retirement_keeps_completed_initial_observation(self):
        for boundary in ('rst', 'timeout', 'eof'):
            retired = []
            analyzer = Analyzer(on_retire=lambda a, b, e: retired.append(e))
            for i, data in enumerate(cases()['urgent'][0][:-1]):
                analyzer.process(i, decode_packet(data))
            if boundary == 'rst':
                analyzer.process(3, decode_packet(frame(A, B, 1040, 9000, 4)))
            elif boundary == 'timeout':
                analyzer.expire(100)
            else:
                analyzer.finish()
            self.assertFalse(any(e.observation.status == 'invalidated' for e in retired))
            self.assertFalse(analyzer.tracked)
