import tempfile
import unittest
from pathlib import Path
from analyze_pcap import Analyzer
from make_sample_pcap import A, B, REQUEST, frame, pcap_bytes, sample_frames
from packets import CaptureError, PacketError, decode_tcp, read_pcap


class PcapTests(unittest.TestCase):
    def read_bytes(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.pcap"
            path.write_bytes(data)
            return list(read_pcap(path))

    def test_formats_and_decode(self):
        for endian in ("<", ">"):
            for nano in (False, True):
                records = self.read_bytes(pcap_bytes(sample_frames(), endian, nano))
                self.assertEqual(len(records), 12)
                packet = decode_tcp(records[7][1])
                self.assertEqual(packet.source, A)
                self.assertEqual(packet.destination, B)
                self.assertEqual(packet.sequence, 1000)
                self.assertEqual(packet.payload, REQUEST[:11])

    def test_reject_bad_files(self):
        valid = pcap_bytes(sample_frames())
        for data in (b"", b"\x0a\x0d\x0d\x0a" + b"\x00" * 20, valid[:25], valid[:-1]):
            with self.assertRaises(CaptureError):
                self.read_bytes(data)
        invalid = bytearray(valid)
        invalid[20:24] = (999).to_bytes(4, "little")  # unknown link type
        with self.assertRaises(CaptureError):
            self.read_bytes(invalid)
        raw_ip = bytearray(valid)
        raw_ip[20:24] = (101).to_bytes(4, "little")  # supported since v0.31: frames decode by link type
        self.assertEqual(len(self.read_bytes(raw_ip)), 12)

    def test_reject_bad_packet_lengths_fragments_and_udp(self):
        original = frame(A, B, 1000, 9000, 24, REQUEST)
        for offset, value in ((14, 0x44), (20, 0x20), (23, 17), (46, 0x40)):
            data = bytearray(original)
            data[offset] = value
            with self.assertRaises(PacketError):
                decode_tcp(bytes(data))
        short = bytearray(frame(A, B, 1000, 9000, 16))
        short[46] = 0xf0
        with self.assertRaises(PacketError):
            decode_tcp(bytes(short))
        for size in (0, 13, 30, len(original) - 1):
            with self.assertRaises(PacketError):
                decode_tcp(original[:size])

    def test_vlan_and_header_options(self):
        original = frame(A, B, 1000, 9000, 24, REQUEST)
        vlan = original[:12] + b"\x81\x00\x00\x01\x08\x00" + original[14:]
        self.assertEqual(decode_tcp(vlan).payload, REQUEST)
        # Four bytes of IP options, then four of TCP options.
        packet = bytearray(original[:34] + b"\x01" * 4 + original[34:54] + b"\x01" * 4 + original[54:])
        packet[14] = 0x46
        packet[16:18] = (len(packet) - 14).to_bytes(2, "big")
        packet[50] = 0x60
        self.assertEqual(decode_tcp(bytes(packet)).payload, REQUEST)

    def test_full_pipeline(self):
        analyzer = Analyzer()
        events = [analyzer.process(i, decode_tcp(packet)) for i, packet in enumerate(sample_frames())]
        self.assertIn("pending=29", events[3])
        self.assertIn("SSH=MATCH", events[6])
        self.assertIn("HTTP=MATCH", events[7])
        self.assertEqual(events[8], "No new contiguous data")
        self.assertIn("CLOSED", events[-1])
        self.assertNotIn(analyzer.manager.key(A, B), analyzer.tracked)

    def ready(self):
        analyzer = Analyzer()
        for i, packet in enumerate(sample_frames()[:3]):
            analyzer.process(i, decode_tcp(packet))
        return analyzer

    def test_missing_handshake_invalid_ack_and_reset(self):
        analyzer = Analyzer()
        self.assertIn("beginning not observed", analyzer.process(0, decode_tcp(sample_frames()[7])))
        analyzer.process(1, decode_tcp(sample_frames()[0]))
        self.assertIn("INVALIDATED", analyzer.process(2, decode_tcp(frame(B, A, 8999, 2000, 18))))
        analyzer = self.ready()
        self.assertIn("RESET", analyzer.process(3, decode_tcp(frame(B, A, 9000, 1000, 4))))
        self.assertFalse(analyzer.tracked)

    def test_fin_waits_for_missing_data(self):
        analyzer = self.ready()
        analyzer.process(3, decode_tcp(frame(A, B, 1040, 9000, 17)))
        analyzer.process(4, decode_tcp(frame(B, A, 9000, 1041, 17)))
        self.assertTrue(analyzer.tracked)
        event = analyzer.process(5, decode_tcp(frame(A, B, 1000, 9000, 24, REQUEST)))
        self.assertIn("HTTP=MATCH", event)
        self.assertIn("CLOSED", event)

    def test_overlap_invalidates_previous_classification(self):
        analyzer = self.ready()
        analyzer.process(3, decode_tcp(frame(A, B, 1000, 9000, 24, REQUEST)))
        event = analyzer.process(4, decode_tcp(frame(A, B, 1000, 9000, 24, b"X")))
        self.assertIn("INVALIDATED", event)
        self.assertFalse(analyzer.tracked)

    def test_capture_timestamp_expiry(self):
        analyzer = self.ready()
        event = analyzer.process(100, decode_tcp(frame(A, B, 1000, 9000, 24, REQUEST)))
        self.assertIn("beginning not observed", event)


if __name__ == "__main__":
    unittest.main()
