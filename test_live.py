import json
import os
import random
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from capture_stream import CaptureRecord, PcapStreamDecoder
from live_capture import CaptureDiagnostics, CaptureMonitor, capture_command, run_capture
from link_packets import decode_frame
from packets import CaptureError, PacketError
from make_sample_pcap import A, B, REQUEST, frame, pcap_bytes, sample_frames, udp_frame
from protocol_fixtures import DNS


def ip6(payload, protocol=17, extension=b''):
    return (struct.pack('!IHBB', 6 << 28, len(payload) + len(extension), protocol, 64)
            + socket.inet_pton(socket.AF_INET6, '2001:db8::1')
            + socket.inet_pton(socket.AF_INET6, '2001:db8::2') + extension + payload)


class LiveCaptureTests(unittest.TestCase):
    def test_pcap_stream_all_splits_and_endian_precisions(self):
        for endian in ('<', '>'):
            for nano in (False, True):
                data = pcap_bytes([sample_frames()[0], sample_frames()[7]], endian, nano)
                for cut in range(len(data) + 1):
                    decoder = PcapStreamDecoder()
                    records = decoder.feed(data[:cut]) + decoder.feed(data[cut:])
                    decoder.end()
                    self.assertEqual(len(records), 2)
                    self.assertEqual(decode_frame(records[1].data).payload, REQUEST[:11])

    def test_pcap_bytewise_multiple_records_and_truncation_metadata(self):
        data = bytearray(pcap_bytes(sample_frames()))
        data[36:40] = (999).to_bytes(4, 'little')
        decoder, records = PcapStreamDecoder(), []
        for byte in data:
            records.extend(decoder.feed(bytes([byte])))
        decoder.end()
        self.assertTrue(records[0].truncated)
        self.assertFalse(records[1].truncated)
        self.assertFalse(decoder.buffer)

    def test_pcap_malformed_length_eof_closed_and_buffer_bound(self):
        valid = pcap_bytes(sample_frames())
        for size in (0, 10, 25, len(valid) - 1):
            decoder = PcapStreamDecoder()
            decoder.feed(valid[:size])
            with self.assertRaises(CaptureError): decoder.end()
        bad = bytearray(valid[:40])
        bad[32:36] = (0xffffffff).to_bytes(4, 'little')
        decoder = PcapStreamDecoder()
        with self.assertRaises(CaptureError): decoder.feed(bytes(bad))
        self.assertFalse(decoder.buffer)
        with self.assertRaises(CaptureError): decoder.feed(b'')
        with self.assertRaises(CaptureError): PcapStreamDecoder().feed(bytes(65537))

    def test_supported_link_headers_ipv4(self):
        eth = frame(A, B, 1000, 9000, 24, REQUEST)
        raw = eth[14:]
        forms = ((1, eth), (101, raw), (228, raw), (0, struct.pack('<I', 2) + raw),
                 (0, struct.pack('>I', 2) + raw), (108, struct.pack('!I', 2) + raw),
                 (113, bytes(14) + b'\x08\x00' + raw), (276, b'\x08\x00' + bytes(18) + raw))
        for kind, data in forms:
            self.assertEqual(decode_frame(data, kind).payload, REQUEST)
        vlan = eth[:12] + b'\x81\x00\x00\x01\x86\xdd' + raw
        with self.assertRaises(PacketError): decode_frame(vlan)

    def test_ipv6_is_rejected_on_every_supported_link_wrapper(self):
        udp = struct.pack('!HHHH', 55555, 55556, 8 + len(DNS), 0) + DNS
        raw = ip6(udp)
        ethernet = bytes(12) + b'\x86\xdd' + raw
        forms = [(229, raw), (101, raw), (228, raw), (1, ethernet),
                 (1, bytes(12) + b'\x81\x00\x00\x01\x86\xdd' + raw),
                 (113, bytes(14) + b'\x86\xdd' + raw), (276, b'\x86\xdd' + bytes(18) + raw)]
        for family in (24, 28, 30):
            for endian in ('<', '>'):
                forms.append((0, struct.pack(endian + 'I', family) + raw))
            forms.append((108, struct.pack('!I', family) + raw))
        for kind, data in forms:
            with self.subTest(linktype=kind, prefix=data[:4]):
                with self.assertRaisesRegex(PacketError, 'IPv4 only'):
                    decode_frame(data, kind)

    def test_ipv6_pcap_linktype_rejected_and_mixed_capture_skips_ipv6(self):
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 229)
        with self.assertRaisesRegex(CaptureError, 'Unsupported capture link type'):
            PcapStreamDecoder().feed(header)
        events = []
        monitor = CaptureMonitor(events.append)
        raw = ip6(struct.pack('!HHHH', 1, 2, 8 + len(DNS), 0) + DNS)
        ipv6 = bytes(12) + b'\x86\xdd' + raw
        ipv4 = udp_frame(A, B, DNS)
        for i, data in enumerate((ipv6, ipv4)):
            monitor.accept(CaptureRecord(i, data, len(data), 1), i)
        self.assertEqual(monitor.counts['unsupported_or_malformed_packets'], 1)
        self.assertEqual(monitor.counts['identified'], 1)
        self.assertEqual(events[0]['protocol'], 'dns')

    def test_packet_fuzz_no_unhandled_exceptions(self):
        rng = random.Random(6006)
        for length in range(200):
            data = bytes(rng.randrange(256) for _ in range(length))
            for link in (0, 1, 101, 108, 113, 228, 229, 276):
                try: decode_frame(data, link)
                except PacketError: pass

    def test_monitor_complete_pipeline_no_payload_output(self):
        events = []
        monitor = CaptureMonitor(events.append)
        for index, data in enumerate(sample_frames()):
            monitor.accept(CaptureRecord(index, data, len(data), 1), index)
        protocols = {event['protocol'] for event in events if event['type'] == 'classification'}
        self.assertEqual(protocols, {'ssh', 'http/1.1'})
        self.assertNotIn('Host:', repr(events))
        self.assertNotIn('example.com', repr(events))
        self.assertEqual(monitor.counts['packets'], 12)

    def test_truncation_discards_active_state_and_reports_gap(self):
        events = []
        monitor = CaptureMonitor(events.append)
        for index, data in enumerate(sample_frames()[:3]):
            monitor.accept(CaptureRecord(index, data, len(data), 1), index)
        data = sample_frames()[7]
        monitor.accept(CaptureRecord(4, data, len(data) + 1, 1), 4)
        self.assertFalse(monitor.analyzer.tracked)
        self.assertTrue(any(event['type'] == 'capture_gap' for event in events))
        monitor.accept(CaptureRecord(5, data, len(data), 1), 5)
        self.assertEqual(monitor.counts['tcp_without_start'], 1)

    def test_connection_limits_idle_expiry_and_no_start(self):
        monitor = CaptureMonitor(lambda event: None, max_connections=1, idle_timeout=2)
        for i, data in enumerate((frame(A, B, 999, 0, 2), frame(('192.0.2.3', 10), B, 1, 0, 2))):
            monitor.accept(CaptureRecord(i, data, len(data), 1), i)
        self.assertEqual(monitor.counts['connection_limit'], 1)
        monitor.analyzer.expire(4)
        self.assertFalse(monitor.analyzer.tracked)

    def test_retransmitted_handshake_keeps_state_tables_consistent(self):
        monitor = CaptureMonitor(lambda event: None, idle_timeout=3)
        packets = ((0, frame(A, B, 999, 0, 2)), (0, frame(B, A, 8999, 1000, 18)),
                   (2, frame(A, B, 999, 0, 2)), (4, frame(B, A, 8999, 1000, 18)),
                   (5, frame(A, B, 1000, 9000, 24, REQUEST)))
        for now, data in packets:
            monitor.accept(CaptureRecord(now, data, len(data), 1), now)
        self.assertEqual(monitor.counts['identified'], 1)

    def test_reassembly_memory_bound_and_release(self):
        monitor = CaptureMonitor(lambda event: None, max_connections=8, byte_limit=1024, idle_timeout=60)
        for i in range(12):
            source = ('192.0.2.1', 50000 + i)
            for data in (frame(source, B, 999, 0, 2), frame(B, source, 8999, 1000, 18)):
                monitor.accept(CaptureRecord(i, data, len(data), 1), i)
        connections = monitor.analyzer.manager.connections
        self.assertEqual(len(connections), 8)
        allocated = sum(len(stream.buffer) + len(stream.present)
                        for conn in connections.values() for stream in conn['directions'].values())
        self.assertEqual(allocated, 8 * 4 * 1024)
        monitor.analyzer.expire(100)
        self.assertFalse(connections)

    def test_fin_beyond_prefix_closes_without_retraction(self):
        events = []
        monitor = CaptureMonitor(events.append, byte_limit=64)
        packets = (frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18),
                   frame(A, B, 1000, 9000, 24, REQUEST + b'x' * 1000),
                   frame(A, B, 1000 + len(REQUEST) + 1000, 9000, 17),
                   frame(B, A, 9000, 2041, 17))
        for i, data in enumerate(packets):
            monitor.accept(CaptureRecord(i, data, len(data), 1), i)
        self.assertFalse(monitor.analyzer.tracked)
        self.assertEqual(monitor.counts['stream_invalidations'], 0)

    def test_runtime_process_failure_and_invalid_cli_limits(self):
        proc = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stderr.write("permission denied"); sys.exit(7)'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        events = []
        self.assertEqual(run_capture(proc.stdout, events.append, duration=2, process=proc), 1)
        self.assertEqual(events[-1]['capture_quality'], 'failed')
        self.assertIn('permission denied', next(e['reason'] for e in events if e['type'] == 'error'))
        for option, value in (('--duration', 'nan'), ('--duration', '-1'), ('--max-connections', '100000'),
                              ('--byte-limit', '1'), ('--stats-interval', 'inf')):
            result = subprocess.run([sys.executable, '-B', 'live_capture.py', '--stdin', option, value],
                                    input=b'', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(result.returncode, 2)

    def test_long_stream_stays_initial_scope_and_overlap_retracts(self):
        events = []
        monitor = CaptureMonitor(events.append, byte_limit=64)
        packets = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18),
                   frame(A, B, 1000, 9000, 24, REQUEST + b'x' * 1000),
                   frame(A, B, 2040, 9000, 24, b'x' * 1000)]
        for i, data in enumerate(packets):
            monitor.accept(CaptureRecord(i, data, len(data), 1), i)
        self.assertEqual(monitor.counts['identified'], 1)
        self.assertEqual(monitor.counts['stream_invalidations'], 0)
        conflict = frame(A, B, 1000, 9000, 24, b'X')
        monitor.accept(CaptureRecord(5, conflict, len(conflict), 1), 5)
        self.assertEqual(events[-1]['status'], 'invalidated')

    def test_diagnostics_bounded_and_final_line(self):
        diag = CaptureDiagnostics()
        for _ in range(20): diag.feed(b'x' * 65536)
        self.assertLessEqual(len(diag.pending), 8192)
        self.assertLessEqual(len(diag.tail), 4096)
        diag.feed(b'\n10 packets captured\n3 packets dropped by kernel')
        diag.end()
        self.assertEqual(diag.stats, {'captured': 10, 'dropped_by_kernel': 3})

    def test_command_arguments_are_not_shell_code(self):
        bpf = 'tcp and port 8080; $(touch /tmp/never-created)'
        cmd = capture_command('lo0', bpf, '/usr/sbin/tcpdump')
        self.assertEqual(cmd[-1], "ip and (" + bpf + ")")
        self.assertEqual(cmd[-2], '--')
        for interface in ('', '-i', 'lo0;echo bad', '$(bad)'):
            with self.assertRaises(ValueError): capture_command(interface, 'tcp', '/usr/sbin/tcpdump')

    def test_pipe_eof_and_process_cleanup_and_loss_exit_code(self):
        data = pcap_bytes(sample_frames())
        code = 'import sys; sys.stdout.buffer.write(%r); sys.stdout.flush(); sys.stderr.write("12 packets captured\\n2 packets dropped by kernel\\n")' % data
        proc = subprocess.Popen([sys.executable, '-c', code], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        events = []
        status = run_capture(proc.stdout, events.append, duration=2, process=proc)
        self.assertEqual(status, 2)
        self.assertIsNotNone(proc.poll())
        self.assertTrue(proc.stdout.closed)
        self.assertEqual(events[-1]['capture_stats']['dropped_by_kernel'], 2)

    def test_idle_deadline_without_packets(self):
        reader, writer = os.pipe()
        try:
            with os.fdopen(reader, 'rb', buffering=0) as stream:
                events, start = [], time.monotonic()
                self.assertEqual(run_capture(stream, events.append, duration=.05), 0)
                self.assertLess(time.monotonic() - start, 1)
                self.assertEqual(events[-1]['stop_reason'], 'limit_or_interrupt')
                self.assertTrue(os.get_blocking(stream.fileno()))
        finally:
            os.close(writer)

    def test_regular_file_eof_without_selector_registration(self):
        data = pcap_bytes([udp_frame(A, B, DNS)] * 1500)
        self.assertGreater(len(data), 65536)
        with tempfile.TemporaryFile() as stream:
            stream.write(data); stream.seek(0)
            blocking = os.get_blocking(stream.fileno())
            events = []
            with patch('live_capture.selectors.DefaultSelector') as selector, patch('live_capture.os.read', wraps=os.read) as read:
                self.assertEqual(run_capture(stream, events.append, duration=0, stats_interval=0), 0)
            selector.return_value.register.assert_not_called()
            selector.return_value.select.assert_not_called()
            self.assertTrue(all(call.args[1] <= 65536 for call in read.call_args_list))
            self.assertEqual(events[-1]['counts']['packets'], 1500)
            self.assertEqual(events[-1]['stop_reason'], 'eof')
            self.assertEqual(os.get_blocking(stream.fileno()), blocking)
            self.assertFalse(stream.closed)

    def test_regular_file_cli_eof_is_finite_with_unlimited_duration(self):
        # A child timeout catches the former macOS EOF hang rather than hanging
        # the suite; epoll systems also exercise the no-registration path.
        for data, status in ((pcap_bytes(sample_frames()), 0), (b'', 1), (pcap_bytes(sample_frames())[:-1], 1)):
            with tempfile.TemporaryFile() as stream:
                stream.write(data); stream.seek(0)
                result = subprocess.run([sys.executable, '-B', 'live_capture.py', '--stdin', '--duration', '0', '--json'],
                                        stdin=stream, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
            self.assertEqual(result.returncode, status, result.stderr)
            summary = json.loads(result.stdout.splitlines()[-1])
            self.assertEqual(summary['stop_reason'], 'eof' if status == 0 else 'error')

    def test_regular_file_packet_limit_and_deadline(self):
        for options in ({'max_packets': 1}, {'duration': 1e-9}):
            with tempfile.TemporaryFile() as stream:
                stream.write(pcap_bytes(sample_frames())); stream.seek(0)
                events = []
                self.assertEqual(run_capture(stream, events.append, **options), 0)
                self.assertEqual(events[-1]['stop_reason'], 'limit_or_interrupt')
                self.assertEqual(events[-1]['counts'].get('packets', 0), 1 if 'max_packets' in options else 0)

    def test_max_packets_and_truncated_pipe_exit(self):
        for data, limit, expected in ((pcap_bytes(sample_frames()), 1, 0), (b'bad', 0, 1)):
            proc = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdout.buffer.write(%r)' % data],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            events = []
            self.assertEqual(run_capture(proc.stdout, events.append, duration=2, max_packets=limit, process=proc), expected)
            if limit: self.assertEqual(events[-1]['counts']['packets'], 1)


if __name__ == '__main__':
    unittest.main()
