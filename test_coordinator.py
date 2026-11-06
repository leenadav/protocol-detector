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


SYN, FIN, ACK = 2, 1, 16


def tcp(source, destination, sequence, acknowledgement, flags, payload=b""):
    """One decoded TCP packet (Ethernet/IPv4 frame from the sample builder)."""
    return decode_frame(frame(source, destination, sequence, acknowledgement, flags, payload), 1)


class RetainedTierTests(unittest.TestCase):
    """Stage 4 (A03, A07): the retained reassembly tier a second consumer reads from the one owner."""

    def coordinator(self, **budget):
        from protocol_adapters.coordinator import RetentionBudget, SessionCoordinator
        options = dict(per_direction=4096, aggregate=16384, connections=4, pending=64)
        options.update(budget)
        return SessionCoordinator(retain=RetentionBudget(**options), max_connections=8, byte_limit=1024, compact=True)

    def handshake(self, coordinator, client, server=SERVER, now=0.0):
        coordinator.accept(tcp(client, server, 999, 0, SYN), now)
        coordinator.accept(tcp(server, client, 8999, 1000, SYN | ACK), now)

    def test_syn_flood_allocates_nothing_and_rejections_are_counted(self):
        coordinator = self.coordinator(connections=4)
        for port in range(50000, 50010):
            self.handshake(coordinator, ("192.0.2.1", port))
        self.assertEqual(len(coordinator.retained), 4)
        self.assertEqual(coordinator.counts["retained_rejected_connections"], 6)
        self.assertEqual(coordinator.retained_bytes(), 0)                 # lazy allocation: handshakes cost nothing
        opened = [item for item in coordinator.drain() if item[0] == "open"]
        self.assertEqual(len(opened), 4)

    def test_deltas_are_delivered_once_and_the_aggregate_budget_isolates_connections(self):
        coordinator = self.coordinator(per_direction=4096, aggregate=6000)
        a, b = ("192.0.2.1", 50001), ("192.0.2.1", 50002)
        self.handshake(coordinator, a)
        self.handshake(coordinator, b)
        coordinator.accept(tcp(a, SERVER, 1000, 9000, ACK, b"A" * 2000), 1.0)
        coordinator.accept(tcp(b, SERVER, 1000, 9000, ACK, b"B" * 500), 1.0)
        events = coordinator.drain()
        data = [(item[1], item[2], item[3].data) for item in events if item[0] == "data"]
        self.assertEqual([len(d) for _, _, d in data], [2000, 500])
        self.assertEqual(coordinator.drain(), [])                          # nothing is handed out twice
        # a would need 4000 more bytes of arrays: over the aggregate budget. Only a is rejected; b keeps going.
        coordinator.accept(tcp(a, SERVER, 3000, 9000, ACK, b"A" * 2000), 2.0)
        coordinator.accept(tcp(b, SERVER, 1500, 9000, ACK, b"B" * 500), 2.0)
        events = coordinator.drain()
        kinds = [(item[0], item[1]) for item in events]
        key_a, key_b = coordinator.analyzer.manager.key(a, SERVER), coordinator.analyzer.manager.key(b, SERVER)
        self.assertIn(("error", key_a), kinds)
        self.assertIn(("data", key_b), kinds)
        self.assertEqual(coordinator.counts["retained_rejected_bytes"], 2000)
        self.assertLessEqual(coordinator.retained_bytes(), 6000)

    def test_late_conflicting_overlap_after_both_fins_retracts(self):
        coordinator = self.coordinator()
        a = ("192.0.2.1", 50001)
        self.handshake(coordinator, a)
        coordinator.accept(tcp(a, SERVER, 1000, 9000, ACK, b"GET / HTTP/1.1\r\n\r\n"), 1.0)
        coordinator.accept(tcp(SERVER, a, 9000, 1018, ACK, b"HTTP/1.1 200 OK\r\n\r\n"), 1.0)
        coordinator.accept(tcp(a, SERVER, 1018, 9019, ACK | FIN), 1.1)
        coordinator.accept(tcp(SERVER, a, 9019, 1019, ACK | FIN), 1.1)
        kinds = [item[0] for item in coordinator.drain()]
        self.assertEqual(kinds, ["open", "data", "data", "fin"])
        self.assertEqual(len(coordinator.retained), 1)                     # retained past FIN for overlap checks
        coordinator.accept(tcp(a, SERVER, 1000, 9000, ACK, b"GET /x HTTP/1.1\r\n\r\n"), 1.2)
        events = coordinator.drain()
        self.assertEqual(events[0][0], "error")
        self.assertIn("Conflicting", events[0][2])
        coordinator.tick(100.0)                                             # idle: the owner releases it
        self.assertEqual([item[0] for item in coordinator.drain()], ["close"])
        self.assertFalse(coordinator.retained)

    def test_gap_and_end_close_retained_connections_and_name_them(self):
        emitted = []
        from protocol_adapters.coordinator import RetentionBudget, SessionCoordinator
        coordinator = SessionCoordinator(emit=emitted.append, retain=RetentionBudget(connections=4), max_connections=8,
                                         byte_limit=1024, compact=True)
        a = ("192.0.2.1", 50001)
        self.handshake(coordinator, a)
        coordinator.accept(tcp(a, SERVER, 1000, 9000, ACK, b"\x16\x03\x01\x00\x05hello"), 1.0)
        coordinator.drain()
        coordinator.gap("Capture truncation")
        gap = next(e for e in emitted if e.get("type") == "capture_gap")
        self.assertEqual(gap["session_ids"], [session_identity("tcp", a, SERVER)])
        kinds = [item[0] for item in coordinator.drain()]
        self.assertEqual(kinds, ["error", "close"])
        self.assertFalse(coordinator.retained)
        self.handshake(coordinator, a, now=2.0)
        coordinator.drain()
        self.assertTrue(coordinator.end("stop"))
        self.assertEqual([item[0] for item in coordinator.drain()], ["close"])
        self.assertFalse(coordinator.end("again"))

    def test_consumer_queue_is_bounded(self):
        from protocol_adapters.sessions import StreamError
        coordinator = self.coordinator(pending=16)
        a = ("192.0.2.1", 50001)
        self.handshake(coordinator, a)
        with self.assertRaises(StreamError):
            for index in range(40):
                coordinator.accept(tcp(a, SERVER, 1000 + index, 9000, ACK, b"x"), 1.0)
        self.assertEqual(coordinator.counts["pending_overflow"], 1)
