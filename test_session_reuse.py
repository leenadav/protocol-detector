"""Milestone B: generations come from one counter per capture (Lee, 2026-11-18). A flow on a tuple whose earlier
flow was published or retracted gets a later generation, never a suppressed duplicate; no (session_id,
generation) repeats; the coordinator holds a generation only for tuples with a tracked or retained flow."""
import unittest

from protocol_adapters import protocol_fixtures as fixtures
from protocol_adapters.capture_stream import PcapStreamDecoder
from protocol_adapters.coordinator import RetentionBudget, SessionCoordinator
from protocol_adapters.events import session_identity
from protocol_adapters.link_packets import decode_frame
from protocol_adapters.make_sample_pcap import frame, pcap_bytes, udp_frame

CLIENT, SERVER = ("192.0.2.10", 52000), ("198.51.100.20", 80)
DNS_CLIENT, DNS_SERVER = ("192.0.2.10", 53000), ("198.51.100.53", 53)
REQUEST = b"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
SYN, FIN, ACK = 2, 1, 16


def packets(frames):
    return [decode_frame(record.data, record.linktype) for record in PcapStreamDecoder().feed(pcap_bytes(frames))]


def closed_connection(base):
    """A complete HTTP exchange that ends with FIN from both sides, starting at sequence number `base`."""
    c, s = base, base + 100000
    return [frame(CLIENT, SERVER, c, 0, SYN), frame(SERVER, CLIENT, s, c + 1, SYN | ACK), frame(CLIENT, SERVER, c + 1, s + 1, 24, REQUEST),
            frame(CLIENT, SERVER, c + 1 + len(REQUEST), s + 1, FIN | ACK), frame(SERVER, CLIENT, s + 1, c + 2 + len(REQUEST), FIN | ACK),
            frame(CLIENT, SERVER, c + 2 + len(REQUEST), s + 2, ACK)]


def sessions(emitted):
    return [e for e in emitted if e.get("type") == "session"]


class SessionReuseTests(unittest.TestCase):
    def run_frames(self, frames, coordinator=None, idle=None):
        emitted = []
        coordinator = coordinator or SessionCoordinator(emit=emitted.append, max_connections=8, byte_limit=16384, idle_timeout=5)
        if coordinator.emit is None:
            coordinator.emit = emitted.append
        for index, packet in enumerate(packets(frames)):
            now = 10.0 + index * (idle or 1)
            coordinator.tick(now)
            coordinator.accept(packet, now)
        coordinator.end("stop")
        return coordinator, emitted

    def test_a_connection_after_the_tuple_closed_is_the_next_generation(self):
        coordinator, emitted = self.run_frames(closed_connection(1000) + closed_connection(500000) + closed_connection(900000))
        found = sessions(emitted)
        self.assertEqual([s["generation"] for s in found], [0, 1, 2])
        self.assertEqual({s["session_id"] for s in found}, {session_identity("tcp", CLIENT, SERVER)})
        self.assertEqual(coordinator.counts["duplicates_suppressed"], 0)
        self.assertEqual(coordinator._active, {})                       # nothing held once every flow is published

    def test_generations_are_unique_per_capture_and_the_table_stays_bounded(self):
        """Distinct tuples draw from the same counter: a tuple's first session need not be generation 0."""
        emitted = []
        coordinator = SessionCoordinator(emit=emitted.append, max_connections=8, byte_limit=16384)
        held = 0
        for index in range(3000):
            client = ("192.0.2.{}".format(1 + index % 200), 40000 + index // 200)
            frames = [frame(client, SERVER, 1000, 0, SYN), frame(SERVER, client, 9000, 1001, SYN | ACK),
                      frame(client, SERVER, 1001, 9001, 24, REQUEST), frame(client, SERVER, 1001 + len(REQUEST), 9001, FIN | ACK),
                      frame(SERVER, client, 9001, 1002 + len(REQUEST), FIN | ACK)]
            for packet in packets(frames):
                coordinator.accept(packet, 10.0 + index)
            held = max(held, len(coordinator._active))
        coordinator.end("stop")
        found = sessions(emitted)
        pairs = [(s["session_id"], s["generation"]) for s in found]
        self.assertEqual(len(found), 3000)
        self.assertEqual(len(set(pairs)), 3000)
        self.assertEqual(sorted(s["generation"] for s in found), list(range(3000)))
        self.assertLessEqual(held, 8)                                   # bounded by the flows in flight, not by the run
        self.assertEqual(coordinator._active, {})

    def test_a_udp_flow_after_the_earlier_one_expired_is_the_next_generation(self):
        datagrams = [udp_frame(DNS_CLIENT, DNS_SERVER, fixtures.DNS), udp_frame(DNS_CLIENT, DNS_SERVER, fixtures.DNS)]
        coordinator, emitted = self.run_frames(datagrams, idle=60)     # the first flow expires before the second
        found = [s for s in sessions(emitted) if s["transport"] == "udp"]
        self.assertEqual([s["generation"] for s in found], [0, 1])
        self.assertEqual(len({s["session_id"] for s in found}), 1)

    def test_a_connection_after_a_gap_retracted_the_tuple_is_the_next_generation(self):
        emitted = []
        coordinator = SessionCoordinator(emit=emitted.append, max_connections=8, byte_limit=16384)
        first = packets(closed_connection(1000))
        for index, packet in enumerate(first[:3]):
            coordinator.accept(packet, 10.0 + index)
        coordinator.gap("Capture reported packet loss")
        for index, packet in enumerate(packets(closed_connection(500000))):
            coordinator.accept(packet, 20.0 + index)
        coordinator.end("stop")
        self.assertEqual([s["generation"] for s in sessions(emitted)], [1])  # generation 0 was retracted

    def test_the_retained_tier_opens_a_reused_tuple_under_the_sessions_generation(self):
        emitted = []
        coordinator = SessionCoordinator(emit=emitted.append, retain=RetentionBudget(per_direction=4096, aggregate=16384, connections=4, pending=256),
                                         max_connections=8, byte_limit=1024, compact=True)
        for index, packet in enumerate(packets(closed_connection(1000) + closed_connection(500000))):
            coordinator.accept(packet, 10.0 + index)
            coordinator.drain()
        coordinator.end("stop")
        generations = [s["generation"] for s in sessions(emitted)]
        self.assertEqual(generations, [0, 1])
        state_generations = []
        coordinator2 = SessionCoordinator(retain=RetentionBudget(per_direction=4096, aggregate=16384, connections=4, pending=256),
                                          max_connections=8, byte_limit=1024, compact=True)
        for index, packet in enumerate(packets(closed_connection(1000) + closed_connection(500000))):
            coordinator2.accept(packet, 10.0 + index)
            for state in coordinator2.retained.values():
                if state["generation"] not in state_generations:
                    state_generations.append(state["generation"])
            coordinator2.drain()
        self.assertEqual(state_generations, generations)


if __name__ == "__main__":
    unittest.main()
