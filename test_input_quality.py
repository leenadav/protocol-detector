"""D06: input normalization and quality contracts; rejected or suspect input never reads as fully inspected."""
import struct
import unittest

from protocol_adapters.analyze_pcap import Analyzer
from protocol_adapters.capture_stream import CaptureRecord
from protocol_adapters.link_packets import CHECKSUM_POLICIES, checksum_failures, decode_frame
from protocol_adapters.live_capture import CaptureMonitor
from protocol_adapters.make_sample_pcap import frame, udp_frame
from protocol_adapters.packets import PacketError
from protocol_adapters.protocol_fixtures import DNS
from protocol_adapters.quality import InputQuality

CLIENT, SERVER = ("192.0.2.10", 52000), ("198.51.100.20", 80)
REQUEST = b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"


def with_ip_flags(data, flags_offset):
    """Rewrite the IPv4 flags/fragment-offset field of a synthetic Ethernet frame (checksum left stale)."""
    out = bytearray(data)
    out[14 + 6:14 + 8] = struct.pack("!H", flags_offset)
    return bytes(out)


def corrupt_tcp_checksum(data):
    out = bytearray(data)
    out[14 + 20 + 16] ^= 0x55
    return bytes(out)


class DecoderContractTests(unittest.TestCase):
    def test_rejections_are_typed_and_name_the_flow_when_headers_allow(self):
        first_fragment = with_ip_flags(frame(CLIENT, SERVER, 1000, 9000, 24, REQUEST), 0x2000)      # MF, offset 0
        with self.assertRaises(PacketError) as caught:
            decode_frame(first_fragment)
        self.assertEqual((caught.exception.kind, caught.exception.endpoints), ("fragment", (CLIENT, SERVER)))
        later_fragment = with_ip_flags(frame(CLIENT, SERVER, 1000, 9000, 24, REQUEST), 0x0010)     # offset 128: no transport header
        with self.assertRaises(PacketError) as caught:
            decode_frame(later_fragment)
        self.assertEqual((caught.exception.kind, caught.exception.endpoints), ("fragment", None))
        udp = bytearray(udp_frame(CLIENT, ("198.51.100.20", 53), DNS))
        udp[14 + 20 + 4:14 + 20 + 6] = struct.pack("!H", 8 + len(DNS) + 9)                        # UDP length lies
        with self.assertRaises(PacketError) as caught:
            decode_frame(bytes(udp))
        self.assertEqual(caught.exception.kind, "length")
        self.assertEqual(caught.exception.endpoints, (CLIENT, ("198.51.100.20", 53)))
        ipv6 = bytes.fromhex("020000000002020000000001" + "86dd") + bytes(40)
        with self.assertRaises(PacketError) as caught:
            decode_frame(ipv6)
        self.assertEqual(caught.exception.kind, "network")
        with self.assertRaises(ValueError):
            PacketError("x", "bogus")

    def test_checksum_policies_account_for_offload(self):
        good = frame(CLIENT, SERVER, 1000, 9000, 24, REQUEST)
        bad = corrupt_tcp_checksum(good)
        self.assertEqual(decode_frame(bad).checksum_failures, ())                                   # ignore: never computed
        self.assertEqual(decode_frame(bad, checksums="audit").checksum_failures, ("tcp",))           # audit: reported, decoded
        self.assertEqual(decode_frame(good, checksums="audit").checksum_failures, ())
        with self.assertRaises(PacketError) as caught:
            decode_frame(bad, checksums="verify")                                                   # verify: skipped, flow named
        self.assertEqual((caught.exception.kind, caught.exception.endpoints), ("checksum", (CLIENT, SERVER)))
        self.assertEqual(decode_frame(good, checksums="verify").payload, REQUEST)
        udp_zero = bytearray(udp_frame(CLIENT, ("198.51.100.20", 53), DNS))
        udp_zero[14 + 20 + 6:14 + 20 + 8] = b"\x00\x00"                                              # UDP checksum absent
        self.assertEqual(decode_frame(bytes(udp_zero), checksums="verify").payload, DNS)
        self.assertEqual(CHECKSUM_POLICIES, ("ignore", "audit", "verify"))
        with self.assertRaises(ValueError):
            decode_frame(good, checksums="strict")
        ip = good[14:]
        self.assertEqual(checksum_failures(ip, 20, len(ip), 6, ip[20:]), [])


class FlowMarkingTests(unittest.TestCase):
    def test_fragmented_flow_never_appears_fully_inspected(self):
        records = []
        analyzer = Analyzer(on_session=records.append, idle_timeout=1000)
        for data in (frame(CLIENT, SERVER, 999, 0, 2), frame(SERVER, CLIENT, 8999, 1000, 18)):
            analyzer.process(0.0, decode_frame(data))
        quality = InputQuality("recorded")
        try:
            decode_frame(with_ip_flags(frame(CLIENT, SERVER, 1000, 9000, 24, REQUEST[:10]), 0x2000))
        except PacketError as error:
            self.assertTrue(analyzer.note_input(error.kind, quality.rejected(error)))
            quality.flows_marked += 1
        analyzer.process(0.2, decode_frame(frame(CLIENT, SERVER, 1000, 9000, 24, REQUEST)))      # the full segment arrives later
        analyzer.finish("eof")
        record = records[0]
        self.assertEqual(record["app"], "web-browsing")                                            # identified from the complete bytes
        self.assertEqual(record["input_quality"], {"fragment": 1})                                # but never silently "fully inspected"
        self.assertEqual(record["layers"]["capture_quality"], "degraded")
        self.assertEqual(quality.render()["rejected"], {"fragment": 1})
        self.assertEqual(quality.render()["flows_marked"], 1)
        self.assertFalse(analyzer.note_input("fragment", (("10.0.0.1", 1), ("10.0.0.2", 2))))    # unknown flow: nothing to mark

    def test_truncated_tcp_record_ends_the_connection_explicitly(self):
        records = []
        analyzer = Analyzer(on_session=records.append, idle_timeout=1000)
        for data in (frame(CLIENT, SERVER, 999, 0, 2), frame(SERVER, CLIENT, 8999, 1000, 18)):
            analyzer.process(0.0, decode_frame(data))
        self.assertTrue(analyzer.note_input("truncated", (CLIENT, SERVER)))
        self.assertEqual(records[0]["end_reason"], "Capture record truncated; stream bytes missing")
        self.assertEqual(records[0]["input_quality"], {"truncated": 1})
        self.assertNotEqual(records[0]["app"], "web-browsing")

    def test_policy_sees_degraded_capture_for_marked_flows(self):
        import json
        from protocol_engine.policy import Policy
        policy = Policy.from_json(json.dumps({"default": "alert", "rules": [
            {"name": "allow-intact-web", "action": "allow", "match": {"apps": ["web-browsing"], "capture_quality": ["intact"]}}]}))
        records = []
        analyzer = Analyzer(on_session=records.append, idle_timeout=1000, policy=policy)
        for data in (frame(CLIENT, SERVER, 999, 0, 2), frame(SERVER, CLIENT, 8999, 1000, 18), frame(CLIENT, SERVER, 1000, 9000, 24, REQUEST)):
            analyzer.process(0.0, decode_frame(data))
        analyzer.note_input("checksum", (CLIENT, SERVER))
        analyzer.finish("eof")
        self.assertEqual((records[0]["policy"]["action"], records[0]["policy"]["predicates"]["capture_quality"]), ("alert", "degraded"))


class LiveAdapterTests(unittest.TestCase):
    def test_monitor_counts_kinds_marks_flows_and_reports_the_contract(self):
        events = []
        monitor = CaptureMonitor(events.append, all_events=True, checksums="audit")
        packets = [frame(CLIENT, SERVER, 999, 0, 2), frame(SERVER, CLIENT, 8999, 1000, 18),
                   with_ip_flags(frame(CLIENT, SERVER, 1000, 9000, 24, REQUEST[:8]), 0x2000),
                   corrupt_tcp_checksum(frame(CLIENT, SERVER, 1000, 9000, 24, REQUEST)),
                   bytes.fromhex("020000000002020000000001" + "86dd") + bytes(40)]
        for index, data in enumerate(packets):
            monitor.accept(CaptureRecord(index, data, len(data), 1), float(index))
        summary = monitor.summary(1.0)
        self.assertEqual(summary["input_quality"]["rejected"], {"network": 1, "fragment": 1, "checksum": 1})
        self.assertEqual(summary["input_quality"]["adapter"], "host")
        self.assertEqual(summary["input_quality"]["checksums"], "audit")
        self.assertIn("ipv4-fragments", summary["input_quality"]["unsupported"])
        monitor.analyzer.finish("eof")
        session = [e for e in events if e.get("type") == "session"][0]
        self.assertEqual(session["input_quality"], {"fragment": 1, "checksum": 1})
        self.assertEqual(session["layers"]["capture_quality"], "degraded")
        self.assertEqual(session["app"], "web-browsing")                       # audit decodes the packet; verify would not
        verifying = CaptureMonitor(lambda e: None, checksums="verify")
        for index, data in enumerate(packets[:2] + packets[3:4]):
            verifying.accept(CaptureRecord(index, data, len(data), 1), float(index))
        self.assertEqual(verifying.counts["unsupported_or_malformed_packets"], 1)
        self.assertEqual(verifying.quality.counts["checksum"], 1)
        with self.assertRaises(ValueError):
            CaptureMonitor(lambda e: None, checksums="strict")


if __name__ == "__main__":
    unittest.main()
