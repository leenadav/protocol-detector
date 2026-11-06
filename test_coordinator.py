"""Stage 3 (A03/A04): SessionCoordinator owns lifecycle for every path; StreamDelta is the reassembler's output."""
import unittest

from protocol_adapters.capture_stream import PcapStreamDecoder
from protocol_adapters.coordinator import SessionCoordinator
from protocol_adapters.events import session_identity
from protocol_adapters.link_packets import decode_frame
from protocol_adapters.live_capture import CaptureMonitor
from protocol_adapters.make_sample_pcap import frame, pcap_bytes
from protocol_adapters.sessions import Stream, StreamDelta, StreamError

CLIENT, SERVER = ("192.0.2.10", 52000), ("198.51.100.20", 80)
REQUEST = b"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n"


def packets(frames):
    return [decode_frame(record.data, record.linktype) for record in PcapStreamDecoder().feed(pcap_bytes(frames))]


def no_fin_connection():
    return [frame(CLIENT, SERVER, 999, 0, 2), frame(SERVER, CLIENT, 4999, 1000, 18), frame(CLIENT, SERVER, 1000, 5000, 24, REQUEST)]


class StreamDeltaTests(unittest.TestCase):
    def test_each_contiguous_byte_exactly_once_in_order(self):
        stream = Stream(0, 64, compatibility=False)
        stream.feed(0, b"abc")
        stream.feed(6, b"ghi")                                     # beyond a gap: held back
        self.assertEqual(stream.deltas(), StreamDelta(0, b"abc"))
        self.assertIsNone(stream.deltas())                         # nothing new until the gap fills
        stream.feed(3, b"def")
        self.assertEqual(stream.deltas(), StreamDelta(3, b"defghi"))
        stream.feed(3, b"def")                                     # identical retransmission: no delta
        self.assertIsNone(stream.deltas())

    def test_conflicting_overlap_invalidates_before_admitting_bytes(self):
        stream = Stream(0, 64, compatibility=False)
        stream.feed(0, b"abc")
        self.assertEqual(stream.deltas(), StreamDelta(0, b"abc"))
        with self.assertRaises(StreamError):
            stream.feed(2, b"XYZ")                                 # conflicts at offset 2
        self.assertIsNone(stream.deltas())                         # the new bytes were never admitted


class CoordinatorTests(unittest.TestCase):
    def test_no_fin_connection_is_finalized_exactly_once_at_end(self):
        emitted = []
        coordinator = SessionCoordinator(emit=emitted.append, max_connections=8, byte_limit=16384)
        for index, packet in enumerate(packets(no_fin_connection())):
            coordinator.accept(packet, 10.0 + index)
        self.assertEqual(emitted, [])                              # nothing final yet: no FIN, not idle
        self.assertTrue(coordinator.end("stop"))
        sessions = [e for e in emitted if e.get("type") == "session"]
        self.assertEqual(len(sessions), 1)
        self.assertEqual((sessions[0]["session_id"], sessions[0]["generation"], sessions[0]["capture_id"]),
                         (session_identity("tcp", CLIENT, SERVER), 0, coordinator.capture_id))
        self.assertFalse(coordinator.end("stop again"))           # idempotent
        self.assertEqual(coordinator.counts["finalized"], 1)

    def test_idle_expiry_needs_a_tick_not_a_packet(self):
        emitted = []
        coordinator = SessionCoordinator(emit=emitted.append, max_connections=8, byte_limit=16384, idle_timeout=5)
        for index, packet in enumerate(packets(no_fin_connection())):
            coordinator.accept(packet, 100.0 + index)
        coordinator.tick(103.0)
        self.assertEqual([e for e in emitted if e.get("type") == "session"], [])
        coordinator.tick(200.0)                                    # injected time: no sleeping, no wall clock
        sessions = [e for e in emitted if e.get("type") == "session"]
        self.assertEqual(len(sessions), 1)
        self.assertIn("Idle", sessions[0]["end_reason"])
        coordinator.end("stop")
        self.assertEqual(len([e for e in emitted if e.get("type") == "session"]), 1)   # not finalized twice

    def test_tuple_reuse_starts_a_new_generation(self):
        emitted = []
        coordinator = SessionCoordinator(emit=emitted.append, max_connections=8, byte_limit=16384)
        first = no_fin_connection()
        second = [frame(CLIENT, SERVER, 50000, 0, 2), frame(SERVER, CLIENT, 70000, 50001, 18),
                  frame(CLIENT, SERVER, 50001, 70001, 24, b"SSH-2.0-OpenSSH_9.9\r\n")]
        for index, packet in enumerate(packets(first + second)):
            coordinator.accept(packet, 10.0 + index)
        coordinator.end("stop")
        sessions = [e for e in emitted if e.get("type") == "session"]
        self.assertEqual([s["generation"] for s in sessions], [0, 1])
        self.assertEqual(len({s["session_id"] for s in sessions}), 1)                  # same tuple, two generations
        self.assertEqual([s["app"] for s in sessions], ["web-browsing", "ssh"])
        self.assertEqual(coordinator.counts["generations"], 1)

    def test_gap_retracts_named_sessions_and_never_finalizes_them(self):
        emitted = []
        coordinator = SessionCoordinator(emit=emitted.append, max_connections=8, byte_limit=16384)
        for index, packet in enumerate(packets(no_fin_connection())):
            coordinator.accept(packet, 10.0 + index)
        coordinator.gap("Capture reported packet loss")
        gap = next(e for e in emitted if e.get("type") == "capture_gap")
        self.assertEqual(gap["session_ids"], [session_identity("tcp", CLIENT, SERVER)])
        coordinator.end("stop")
        self.assertEqual([e for e in emitted if e.get("type") == "session"], [])     # retracted, so no verdict is published

    def test_capture_monitor_and_coordinator_agree_on_the_sessions(self):
        plain, owned = [], []
        monitor = CaptureMonitor(plain.append, max_connections=8, byte_limit=16384)
        coordinator = SessionCoordinator(emit=owned.append, max_connections=8, byte_limit=16384)
        data = pcap_bytes(no_fin_connection())
        for index, record in enumerate(PcapStreamDecoder().feed(data)):
            monitor.accept(record, 10.0 + index)
            coordinator.accept(decode_frame(record.data, record.linktype), 10.0 + index)
        monitor.coordinator.end("stop")
        coordinator.end("stop")
        strip = lambda s: {k: v for k, v in s.items() if k not in ("capture_id", "end")}   # noqa: E731
        self.assertEqual([strip(s) for s in plain if s.get("type") == "session"],
                         [strip(s) for s in owned if s.get("type") == "session"])
        self.assertEqual(plain[-1]["session_id"], session_identity("tcp", CLIENT, SERVER))   # the monitor stamps identity too

    def test_deltas_come_from_the_one_owner(self):
        coordinator = SessionCoordinator(max_connections=8, byte_limit=16384)
        for index, packet in enumerate(packets(no_fin_connection())):
            coordinator.accept(packet, 10.0 + index)
        deltas = coordinator.deltas(CLIENT, SERVER)
        self.assertEqual(deltas[CLIENT], StreamDelta(0, REQUEST))
        self.assertIsNone(deltas.get(SERVER))
        self.assertEqual(coordinator.deltas(CLIENT, SERVER)[CLIENT], None)              # exactly once


if __name__ == "__main__":
    unittest.main()
