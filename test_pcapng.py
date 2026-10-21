"""v0.31: pcapng framing for offline analysis and live --stdin replay."""
import contextlib
import io
import json
import random
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from capture_stream import LINK_TYPES, PcapStreamDecoder
from make_sample_pcap import A, B, REQUEST, _block, frame, pcap_bytes, pcapng_bytes, pcapng_option, sample_frames
from packets import CaptureError, read_pcap_records

FRAMES = sample_frames()


def decode(data, step=None):
    decoder = PcapStreamDecoder()
    records = []
    if step is None:
        records.extend(decoder.feed(data))
    else:
        for pos in range(0, len(data), step):
            records.extend(decoder.feed(data[pos:pos + step]))
    decoder.end()
    return decoder, records


class PcapngDecoderTests(unittest.TestCase):
    def test_equivalent_to_classic_in_both_endians_and_resolutions(self):
        classic = decode(pcap_bytes(FRAMES))[1]
        for endian in ("<", ">"):
            for tsresol in (None, 9, 0x80 | 10, 3):
                decoder, records = decode(pcapng_bytes(FRAMES, endian, tsresol))
                self.assertEqual(decoder.format, "pcapng")
                self.assertEqual([r.data for r in records], [r.data for r in classic])
                self.assertEqual([r.linktype for r in records], [1] * len(FRAMES))
                self.assertEqual([round(r.timestamp) for r in records], [round(r.timestamp) for r in classic])
                self.assertTrue(all(not r.truncated for r in records))
        self.assertEqual(decode(pcap_bytes(FRAMES))[0].format, "pcap")

    def test_every_split_point_and_bytewise_feeding(self):
        data = pcapng_bytes(FRAMES[:4], tsresol=6)
        whole = decode(data)[1]
        for step in (1, 3, 7, 64, 1000):
            self.assertEqual(decode(data, step)[1], whole)
        for cut in range(1, len(data)):
            decoder = PcapStreamDecoder()
            records = decoder.feed(data[:cut]) + decoder.feed(data[cut:])
            decoder.end()
            self.assertEqual(records, whole)
            self.assertFalse(decoder.buffer)

    def test_simple_packets_multiple_interfaces_sections_and_skipped_blocks(self):
        simple = decode(pcapng_bytes(FRAMES[:3], simple=True, snaplen=0))[1]
        self.assertEqual([r.data for r in simple], FRAMES[:3])
        self.assertEqual([r.timestamp for r in simple], [0.0, 0.0, 0.0])
        clipped = decode(pcapng_bytes([FRAMES[0]], simple=True, snaplen=40))[1][0]
        self.assertEqual((len(clipped.data), clipped.original_length, clipped.truncated), (40, len(FRAMES[0]), True))
        multi = decode(pcapng_bytes(FRAMES[:4], interfaces=3))[1]
        self.assertEqual(len(multi), 4)
        raw = pcapng_bytes([frame(A, B, 1000, 9000, 24, REQUEST)[14:]], linktype=101)
        self.assertEqual(decode(raw)[1][0].linktype, 101)
        extras = ((5, struct.pack("<IIIII", 0, 0, 0, 0, 0)), (4, struct.pack("<HH", 0, 0)), (0x40000BAD, b"custom data"), (12345, b"\x00" * 8))
        decoder, records = decode(pcapng_bytes(FRAMES[:2], extra_blocks=extras))
        self.assertEqual((len(records), decoder.blocks_skipped), (2, 4))
        two_sections = pcapng_bytes(FRAMES[:2]) + pcapng_bytes(FRAMES[2:4], ">", 9)
        decoder, records = decode(two_sections)
        self.assertEqual((len(records), decoder.sections), (4, 2))
        self.assertEqual([r.data for r in records], FRAMES[:4])
        empty = decode(pcapng_bytes([]))
        self.assertEqual(empty[1], [])

    def test_malformed_pcapng_is_rejected_and_bounded(self):
        good = pcapng_bytes(FRAMES[:2])
        shb_len = struct.unpack_from("<I", good, 4)[0]
        idb_start = shb_len
        idb_len = struct.unpack_from("<I", good, idb_start + 4)[0]
        epb_start = idb_start + idb_len
        def patched(offset, value):
            data = bytearray(good)
            data[offset:offset + len(value)] = value
            return bytes(data)
        bad = [
            patched(8, b"\x00\x00\x00\x00"),                              # byte-order magic
            patched(12, b"\x02\x00"),                                     # version
            patched(4, (shb_len + 2).to_bytes(4, "little")),              # not a multiple of 4
            patched(4, (8).to_bytes(4, "little")),                        # shorter than a block
            patched(shb_len - 4, (shb_len + 4).to_bytes(4, "little")),    # trailer mismatch
            patched(idb_start + 8, b"\xe7\x03"),                          # linktype 999
            patched(idb_start + 12, (2 ** 21).to_bytes(4, "little")),     # snaplen > 1 MiB
            patched(epb_start + 8, b"\x05\x00\x00\x00"),                  # undefined interface
            patched(epb_start + 20, (10 ** 6).to_bytes(4, "little")),     # captured > snaplen
            patched(epb_start + 24, b"\x01\x00\x00\x00"),                 # captured > original
            good[idb_start:],                                             # no section header first
            pcapng_bytes([FRAMES[0]], simple=True)[:shb_len] + good[epb_start:],  # packet without interface
        ]
        for data in bad:
            decoder = PcapStreamDecoder()
            with self.assertRaises(CaptureError, msg=data[:16].hex()):
                decoder.feed(data)
                decoder.end()
            self.assertFalse(decoder.buffer)
        oversized = _block("<", 6, bytes(20)).replace((32).to_bytes(4, "little"), (2 ** 21 + 12).to_bytes(4, "little"))
        decoder = PcapStreamDecoder()
        decoder.feed(good[:idb_start + idb_len])
        with self.assertRaises(CaptureError):
            decoder.feed(oversized[:16])
        bad_option = pcapng_bytes([], tsresol=0x80 | 60)
        with self.assertRaises(CaptureError):
            decode(bad_option)
        bad_option = pcapng_bytes([], tsresol=13)
        with self.assertRaises(CaptureError):
            decode(bad_option)
        truncated_option = _block("<", 0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + struct.pack("<HH", 2, 40) + b"x" * 4)
        with self.assertRaises(CaptureError):
            decode(truncated_option)
        boundaries, pos = set(), 0
        while pos < len(good):
            pos += struct.unpack_from("<I", good, pos + 4)[0]
            boundaries.add(pos)
        for cut in range(1, len(good)):
            decoder = PcapStreamDecoder()
            decoder.feed(good[:cut])
            if cut in boundaries:
                decoder.end()  # a capture that ends between blocks is complete
            else:
                with self.assertRaises(CaptureError):
                    decoder.end()
        rng = random.Random(31)
        for _ in range(300):
            data = bytearray(good)
            data[rng.randrange(len(data))] = rng.randrange(256)
            decoder = PcapStreamDecoder()
            try:
                decoder.feed(bytes(data))
                decoder.end()
            except CaptureError:
                self.assertTrue(decoder.failed or decoder.finished)
                self.assertTrue(decoder.finished or not decoder.buffer)  # a feed failure drops the buffer
            self.assertLessEqual(len(decoder.buffer), len(data))

    def test_offline_reader_and_cli_accept_pcapng(self):
        from analyze_pcap import analyze
        with tempfile.TemporaryDirectory() as directory:
            classic, ng = Path(directory) / "a.pcap", Path(directory) / "a.pcapng"
            classic.write_bytes(pcap_bytes(FRAMES))
            ng.write_bytes(pcapng_bytes(FRAMES, ">", 9))
            self.assertEqual([r.data for r in read_pcap_records(ng)], [r.data for r in read_pcap_records(classic)])
            outputs = []
            for path in (classic, ng):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    analyze(path, json_output=True, events_only=True, sessions=True)
                rows = [json.loads(line) for line in output.getvalue().splitlines()]
                outputs.append([(row.get("type"), row.get("app"), row.get("classification", {}).get("application_protocol")) for row in rows])
            self.assertEqual(outputs[0], outputs[1])
            raw = Path(directory) / "raw.pcapng"
            raw.write_bytes(pcapng_bytes([f[14:] for f in FRAMES], linktype=101))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                counts = analyze(raw, json_output=True, events_only=True)
            self.assertEqual(counts["tcp"] + counts["udp"], len(FRAMES))
            result = subprocess.run([sys.executable, "-B", "live_capture.py", "--stdin", "--duration", "0", "--json"],
                                    input=ng.read_bytes(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = json.loads(result.stdout.splitlines()[-1])
            self.assertEqual((summary["stop_reason"], summary["counts"]["packets"]), ("eof", len(FRAMES)))
            garbage = Path(directory) / "x.pcap"
            garbage.write_bytes(b"\x0a\x0d\x0d\x0a" + bytes(20))
            with self.assertRaises(CaptureError):
                list(read_pcap_records(garbage))
        self.assertIn(1, LINK_TYPES)
        self.assertEqual(pcapng_option("<", 0, b""), b"\x00\x00\x00\x00")


if __name__ == "__main__":
    unittest.main()
