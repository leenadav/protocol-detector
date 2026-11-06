"""Regressions reproduced from GitHub review #1 and adjacent boundary cases."""
import io
import json
import random
import struct
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from analyze_pcap import Analyzer, analyze
from capture_stream import CaptureRecord, PcapStreamDecoder
from link_packets import decode_frame
from live_capture import CaptureMonitor
from make_sample_pcap import A, B, C, D, REQUEST, frame, pcap_bytes, udp_frame
from packets import CaptureError, PacketError, decode_packet, read_pcap, read_pcap_records
from sessions import MODULUS, Stream, StreamError
from test_reassembly import RecordingInspector


def capture(records, endian='<', nano=False):
    """Independent PCAP record encoder with separate captured/wire lengths."""
    magic = 0xa1b23c4d if nano else 0xa1b2c3d4
    data = struct.pack(endian+'IHHIIII', magic, 2, 4, 0, 0, 65535, 1)
    for index, (payload, original) in enumerate(records):
        data += struct.pack(endian+'IIII', 1700000000+index, 0, len(payload), original) + payload
    return data


class LeadingOverlapTests(unittest.TestCase):
    def ready(self, first=0, compact=True):
        analyzer = Analyzer(compact=compact)
        analyzer.process(0, decode_packet(frame(A, B, (first-1) % MODULUS, 0, 2)))
        analyzer.process(0, decode_packet(frame(B, A, 8999, first, 18)))
        return analyzer

    def send(self, analyzer, sequence, payload, flags=24):
        return analyzer.process(1, decode_packet(frame(A, B, sequence % MODULUS, 9000, flags, payload)))

    def test_review_wraparound_conflict_retracts_identification(self):
        for first in (0, 1, 1000, MODULUS-8):
            analyzer = self.ready(first)
            self.send(analyzer, first, REQUEST)
            self.assertEqual(analyzer.last_classification.status, 'identified')
            result = self.send(analyzer, first-1, b'X' + b'X' + REQUEST[1:])
            self.assertIn('INVALIDATED', result)
            self.assertEqual(analyzer.last_classification.status, 'invalidated')
            self.assertFalse(analyzer.tracked)
            self.assertFalse(analyzer.manager.connections)

    def test_leading_overlap_matches_existing_fin_instead_of_false_retraction(self):
        for first in (0, 1000, MODULUS-8):
            analyzer = self.ready(first)
            self.send(analyzer, first, REQUEST, 25)
            self.assertEqual(analyzer.last_classification.status, 'identified')
            self.send(analyzer, first-3, b'old' + REQUEST, 25)
            self.assertTrue(analyzer.tracked)
            self.assertEqual(analyzer.last_classification.status, 'identified')
            self.assertEqual(analyzer.last_events, ())
            self.send(analyzer, first-3, b'old' + REQUEST[:-1] + b'X')
            self.assertEqual(analyzer.last_classification.status, 'invalidated')

    def test_leading_overlap_fin_gap_and_payload_beyond_fin(self):
        analyzer = self.ready()
        self.send(analyzer, len(REQUEST), b'', 17)
        self.send(analyzer, 10, REQUEST[10:])
        self.assertEqual(analyzer.last_classification.status, 'detecting')
        self.send(analyzer, -2, b'xx' + REQUEST[:10])
        self.assertEqual(analyzer.last_classification.status, 'identified')
        self.assertIn('INVALIDATED', self.send(analyzer, -2, b'xx' + REQUEST + b'extra'))
        self.assertFalse(analyzer.tracked)

    def test_live_monitor_emits_leading_overlap_invalidation(self):
        events = []
        monitor = CaptureMonitor(events.append)
        packets = [frame(A,B,MODULUS-1,0,2), frame(B,A,8999,0,18),
                   frame(A,B,0,9000,24,REQUEST), frame(A,B,MODULUS-1,9000,24,b'XX'+REQUEST[1:])]
        for i, data in enumerate(packets):
            monitor.accept(CaptureRecord(i, data, len(data), 1), i)
        statuses = [event['status'] for event in events if event['type']=='classification']
        self.assertEqual(statuses, ['identified', 'invalidated'])

    def test_seeded_prefix_clipping_matches_absolute_offset_oracle(self):
        rng = random.Random(12012)
        for first in (0, 11, MODULUS-7):
            for _ in range(30):
                data = bytes(rng.randrange(256) for _ in range(64))
                stream = Stream(first,64,RecordingInspector,False,True)
                expected = {}
                for _ in range(100):
                    start = rng.randrange(-100,130)
                    end = start + rng.randrange(1,150)
                    payload = bytes(data[i] if 0 <= i < 64 else 255 for i in range(start,end))
                    stream.feed((first+start)%MODULUS,payload)
                    expected.update((i,data[i]) for i in range(max(start,0),min(end,64)))
                    contiguous = 0
                    while contiguous in expected: contiguous += 1
                    self.assertEqual(stream.stored,len(expected))
                    self.assertEqual(stream.contiguous,contiguous)
                    self.assertEqual(stream.highest_end,max(expected,default=-1)+1)
                    self.assertEqual(b''.join(stream.inspector.chunks),data[:contiguous])
                    self.assertEqual(len(stream.buffer),64)
                    self.assertEqual(len(stream.present),64)
                stream.feed((first-3)%MODULUS,b'old'+data+b'ignored')
                self.assertEqual(b''.join(stream.inspector.chunks),data)

    def test_clipped_conflict_is_atomic_and_strict_mode_still_rejects_outside(self):
        for first in (0,1000):
            stream=Stream(first,64,RecordingInspector,False,True)
            stream.feed((first+63)%MODULUS,b'A')
            before=bytes(stream.buffer),bytes(stream.present),stream.stored,stream.highest_end
            with self.assertRaises(StreamError):
                stream.feed((first-1)%MODULUS,b'x'+b'A'*63+b'B'+b'outside')
            self.assertEqual(before,(bytes(stream.buffer),bytes(stream.present),stream.stored,stream.highest_end))
            self.assertEqual(stream.inspector.chunks,[])
            strict=Stream(first,64,RecordingInspector,False,False)
            with self.assertRaises(StreamError):strict.feed((first-1)%MODULUS,b'xA')


class OfflineCaptureIntegrityTests(unittest.TestCase):
    def analyze_bytes(self,data,events_only=True):
        output=io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'sample.pcap';path.write_bytes(data)
            with redirect_stdout(output):
                counts=analyze(path,json_output=True,events_only=events_only)
        return [json.loads(line) for line in output.getvalue().splitlines()],counts

    def test_original_length_preserved_in_every_classic_format(self):
        payload=frame(A,B,1000,9000,24,REQUEST)
        for endian in ('<','>'):
            for nano in (False,True):
                data=capture([(payload,len(payload)+8)],endian,nano)
                decoder=PcapStreamDecoder();live=decoder.feed(data);decoder.end()
                with tempfile.TemporaryDirectory() as directory:
                    path=Path(directory)/'sample.pcap';path.write_bytes(data)
                    records=list(read_pcap_records(path))
                    self.assertEqual(records,live)
                    self.assertTrue(records[0].truncated)
                    self.assertEqual(records[0].original_length,len(payload)+8)
                    with self.assertRaisesRegex(CaptureError,'Capture truncation'):
                        list(read_pcap(path))

    def test_truncation_drops_partial_stream_before_benign_retransmission(self):
        packets=[frame(A,B,999,0,2),frame(B,A,8999,1000,18),frame(A,B,1000,9000,24,REQUEST[:11])]
        bad=frame(A,B,1000,9000,24,b'X'+REQUEST[1:])
        records=[(p,len(p)) for p in packets]+[(bad[:10],len(bad))]
        good=frame(A,B,1000,9000,24,REQUEST);records.append((good,len(good)))
        for endian in ('<','>'):
            rows,counts=self.analyze_bytes(capture(records,endian))
            self.assertEqual(counts['truncated'],1)
            gap=next(row for row in rows if row.get('type')=='capture_gap')
            self.assertEqual(gap['active_connections'],1)
            self.assertEqual(gap['frame'],4)
            self.assertFalse(any(row.get('classification',{}).get('status')=='identified' for row in rows))
            self.assertFalse(any(row.get('type')=='stream_end' for row in rows))

    def test_truncation_retracts_all_active_labels_and_requires_new_handshake(self):
        packets=[frame(A,B,999,0,2),frame(B,A,8999,1000,18),frame(A,B,1000,9000,24,REQUEST),
                 frame(C,D,1999,0,2),frame(D,C,7999,2000,18),frame(C,D,2000,8000,24,REQUEST)]
        records=[(p,len(p)) for p in packets]+[(b'',60)]
        later=[frame(A,B,1000,9000,24,REQUEST),frame(C,D,2000,8000,24,REQUEST),
               frame(A,B,3999,0,2),frame(B,A,8999,4000,18),frame(A,B,4000,9000,24,REQUEST)]
        records += [(p,len(p)) for p in later]
        rows,counts=self.analyze_bytes(capture(records),False)
        gap=next(row for row in rows if row.get('type')=='capture_gap')
        self.assertEqual(gap['active_connections'],2)
        self.assertEqual(gap['scope'],'active_connections')
        self.assertEqual(counts['connections_discarded_after_gap'],2)
        identified=[row['frame'] for row in rows if row.get('classification') and row['classification']['status']=='identified']
        self.assertEqual(identified,[3,6,12])
        self.assertTrue(all('beginning not observed' in row['message'] for row in rows if row.get('frame') in (8,9)))

    def test_physically_cut_record_emits_global_gap_and_raises(self):
        packets=[frame(A,B,999,0,2),frame(B,A,8999,1000,18),frame(A,B,1000,9000,24,REQUEST)]
        for suffix in (b'\x00',struct.pack('<IIII',1700000010,0,60,60)+b'abc'):
            output=io.StringIO()
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'cut.pcap';path.write_bytes(pcap_bytes(packets)+suffix)
                with redirect_stdout(output),self.assertRaises(CaptureError):
                    analyze(path,json_output=True,events_only=True)
            rows=[json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(rows[-1]['type'],'capture_gap')
            self.assertEqual(rows[-1]['scope'],'all_observations_this_capture')
            self.assertFalse(any(row.get('type')=='stream_end' for row in rows))

    def test_offline_live_ipv4_flag_parity_tcp_udp_vlan(self):
        for original in (frame(A,B,1000,9000,24,REQUEST),udp_frame(A,B,b'opaque')):
            for field in (0,0x4000,0x8000,0xc000,0x2000,1,0xffff):
                changed=bytearray(original);changed[20:22]=field.to_bytes(2,'big')
                tagged=changed[:12]+b'\x81\x00\x00\x01\x08\x00'+changed[14:]
                for data in (bytes(changed),bytes(tagged)):
                    if field in (0,0x4000):
                        self.assertEqual(decode_packet(data),decode_frame(data))
                    else:
                        for decoder in (decode_packet,decode_frame):
                            with self.assertRaises(PacketError):decoder(data)

    def test_offline_never_classifies_reserved_flag_frame(self):
        packets=[frame(A,B,999,0,2),frame(B,A,8999,1000,18)]
        bad=bytearray(frame(A,B,1000,9000,24,REQUEST));bad[20:22]=b'\xc0\x00';packets.append(bytes(bad))
        rows,counts=self.analyze_bytes(pcap_bytes(packets))
        self.assertEqual(counts['skipped'],1)
        self.assertFalse(any(row.get('classification',{}).get('status')=='identified' for row in rows))


if __name__=='__main__':unittest.main()
