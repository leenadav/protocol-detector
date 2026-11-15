"""D01 (QUIC CRYPTO assembly isolation) and D02 (byte-compared overlaps) through helpers and the public packet path.

Detector-correctness regressions with protected synthetic Initials (RFC 9001 vectors re-sealed by the test
helper); no claim is made about a real-world exploit.
"""
import itertools
import unittest

from protocol_adapters.analyze_pcap import Analyzer
from protocol_adapters.link_packets import decode_frame
from protocol_adapters.make_sample_pcap import udp_frame
from protocol_engine import Config, DatagramInspector
from protocol_engine.quic import MAX_FRAGMENTS, V1, QuicAssembler, assemble
from test_quic import CLIENT_HELLO, DCID, crypto_frames, protect

SERVER = ("192.0.2.20", 443)
A, B = ("192.0.2.10", 51000), ("198.51.100.7", 51000)
CUT = 100


def fragments():
    """(offset, bytes) pieces of the published ClientHello split at CUT."""
    return [(0, CLIENT_HELLO[:CUT]), (CUT, CLIENT_HELLO[CUT:])]


def initial(piece_index, dcid=DCID, pieces=None, packet_number=2):
    pieces = pieces or crypto_frames(CLIENT_HELLO, (CUT,))
    return protect(V1, dcid, b"", pieces[piece_index], packet_number=packet_number)


class AssembleHelperTests(unittest.TestCase):
    def test_orderings_duplicates_and_gaps(self):
        first, second = fragments()
        for order in itertools.permutations([first, second, first]):       # exact duplicate in every position
            self.assertEqual(assemble(list(order)), ("complete", CLIENT_HELLO), order)
        self.assertEqual(assemble([second]), ("partial", None))            # gap before the end
        self.assertEqual(assemble([first]), ("partial", None))
        self.assertEqual(assemble([]), ("partial", None))
        self.assertEqual(assemble([(0, b"\x02\x00\x00\x01x")]), ("partial", None))   # not a ClientHello message

    def test_contradictory_overlaps_are_conflicts_in_every_order(self):
        first, second = fragments()
        flipped = (CUT - 10, bytes(b ^ 1 for b in CLIENT_HELLO[CUT - 10:CUT + 10]))   # partial overlap, changed bytes
        exact = (0, bytes([CLIENT_HELLO[0]]) + bytes(b ^ 0xff for b in CLIENT_HELLO[1:CUT]))  # exact-range overlap, changed
        for conflict in (flipped, exact):
            for order in itertools.permutations([first, second, conflict]):
                self.assertEqual(assemble(list(order)), ("conflict", None), (conflict[0], order))
        # The reviewer's reproduction: a complete message followed by a contradicting overlap.
        self.assertEqual(assemble([(0, b"\x01\x00\x00\x04abcd"), (4, b"XXXX")]), ("conflict", None))
        self.assertEqual(assemble([(0, b"\x01\x00\x00\x04abcd"), (4, b"abcd")]), ("complete", b"\x01\x00\x00\x04abcd"))
        # An overlap that agrees but a gap elsewhere: partial, not conflict.
        self.assertEqual(assemble([first, (CUT - 5, CLIENT_HELLO[CUT - 5:CUT + 5]), (CUT + 50, CLIENT_HELLO[CUT + 50:])]), ("partial", None))

    def test_assembler_scopes_lifetime_and_late_conflict(self):
        first, second = fragments()
        store = QuicAssembler(max_connections=2, idle_seconds=10)
        # Same DCID, two scopes: fragments never meet.
        self.assertEqual(store.add(DCID, [first], scope="A", version=V1, now=0.0), ("partial", None))
        self.assertEqual(store.add(DCID, [second], scope="B", version=V1, now=0.0), ("partial", None))
        self.assertEqual(store.add(DCID, [second], scope="A", version=V1, now=1.0), ("complete", CLIENT_HELLO))
        # A different version under the same scope and DCID is another connection.
        self.assertEqual(store.add(DCID, [first], scope="A", version=0x6b3343cf, now=1.0)[0], "partial")
        # Identical retransmission after completion stays complete; a contradiction poisons the connection.
        self.assertEqual(store.add(DCID, [first], scope="A", version=V1, now=2.0), ("complete", CLIENT_HELLO))
        bad = (CUT, bytes(b ^ 1 for b in CLIENT_HELLO[CUT:CUT + 8]))
        self.assertEqual(store.add(DCID, [bad], scope="A", version=V1, now=3.0), ("conflict", None))
        self.assertEqual(store.add(DCID, [first, second], scope="A", version=V1, now=4.0), ("conflict", None))   # stays withdrawn
        self.assertEqual(store.counts["conflicts"], 1)
        # Idle expiry ends the conflict marker; the next connection on that key starts clean.
        self.assertEqual(store.add(DCID, [first, second], scope="A", version=V1, now=20.0), ("complete", CLIENT_HELLO))
        # reset(scope) drops the flow's state; the other scope is untouched.
        store.reset("A")
        self.assertEqual(store.add(DCID, [first], scope="B", version=V1, now=20.0), ("partial", None))     # B's old piece expired
        self.assertEqual(store.add(DCID, [second], scope="B", version=V1, now=20.0), ("complete", CLIENT_HELLO))
        # Budget: more than MAX_FRAGMENTS distinct pieces is exhausted, explicitly.
        many = [(index, CLIENT_HELLO[index:index + 1]) for index in range(MAX_FRAGMENTS + 1)]
        self.assertEqual(store.add(b"\x01", many, scope="C", version=V1, now=20.0), ("exhausted", None))
        self.assertEqual(store.counts["exhausted"], 1)
        # LRU eviction bound holds.
        for index in range(5):
            store.add(bytes([index]), [first], scope="D", version=V1, now=21.0)
        self.assertLessEqual(len(store.entries), 2)


def analyzer_with_records():
    records, events = [], []
    analyzer = Analyzer(on_session=records.append, idle_timeout=30, max_udp_flows=16)
    return analyzer, records, events


def feed(analyzer, now, source, data):
    analyzer.process(now, decode_frame(udp_frame(source, SERVER, data), 1))
    return analyzer.last_classification


class PublicPathTests(unittest.TestCase):
    def test_same_dcid_on_unrelated_endpoints_never_combines(self):
        analyzer, records, _ = analyzer_with_records()
        first_from_a = feed(analyzer, 0.0, A, initial(0))
        second_from_b = feed(analyzer, 0.1, B, initial(1))
        for observation in (first_from_a, second_from_b):
            self.assertEqual((observation.status, observation.hostname), ("identified", None))
            self.assertEqual({e.field: e.value for e in observation.evidence}["crypto_assembly"], "partial")
        completed = feed(analyzer, 0.2, A, initial(1))                       # A's own second piece completes A
        self.assertEqual((completed.hostname, completed.offered_alpn), ("example.com", ("alpn",)))
        still_partial = feed(analyzer, 0.3, B, initial(1))                   # B still lacks its first piece
        self.assertIsNone(still_partial.hostname)
        analyzer.finish("eof")
        by_client = {tuple(r["client"]): r for r in records}
        self.assertEqual(by_client[A]["app"], "quic")
        self.assertIsNone(by_client[B].get("hostname"))

    def test_reordered_fragments_assemble_and_three_way_split(self):
        analyzer, records, _ = analyzer_with_records()
        self.assertIsNone(feed(analyzer, 0.0, A, initial(1)).hostname)
        self.assertEqual(feed(analyzer, 0.1, A, initial(0)).hostname, "example.com")
        pieces = crypto_frames(CLIENT_HELLO, (60, 180))
        self.assertIsNone(feed(analyzer, 1.0, B, initial(2, pieces=pieces)).hostname)
        self.assertIsNone(feed(analyzer, 1.1, B, initial(0, pieces=pieces)).hostname)
        self.assertEqual(feed(analyzer, 1.2, B, initial(1, pieces=pieces)).hostname, "example.com")

    def test_late_contradiction_withdraws_published_evidence(self):
        analyzer, records, _ = analyzer_with_records()
        complete = feed(analyzer, 0.0, A, initial(0, pieces=[b"\x06" + b"\x00" + bytes([0x40 | (len(CLIENT_HELLO) >> 8), len(CLIENT_HELLO) & 0xff]) + CLIENT_HELLO]))
        self.assertEqual(complete.hostname, "example.com")
        changed = bytearray(CLIENT_HELLO)
        changed[CUT + 3] ^= 0x55
        contradiction = feed(analyzer, 0.5, A, initial(1, pieces=crypto_frames(bytes(changed), (CUT,)), packet_number=3))
        self.assertEqual(contradiction.status, "invalidated")
        self.assertIsNone(contradiction.hostname)
        self.assertEqual({e.field: e.value for e in contradiction.evidence}["crypto_assembly"], "conflict")
        self.assertNotIn("ja4", {e.field for e in contradiction.evidence})
        again = feed(analyzer, 0.6, A, initial(0))                           # nothing revives the connection
        self.assertEqual(again.status, "invalidated")
        analyzer.finish("eof")
        record = records[0]
        self.assertEqual(record["engine_status"], "invalidated")
        self.assertEqual(record["app"], "not-applicable")
        self.assertIsNone(record.get("hostname"))
        self.assertNotIn("fingerprints", record)

    def test_invalidation_binds_every_later_datagram_of_the_connection(self):
        """Review round 2 (P1): a PING/ACK/PADDING-only Initial, an unopenable Initial or another family on the tuple
        never revives a connection a CRYPTO contradiction invalidated; the record stays invalidated."""
        from protocol_adapters.protocol_fixtures import DNS
        analyzer, records, _ = analyzer_with_records()
        feed(analyzer, 0.0, A, initial(0))
        feed(analyzer, 0.1, A, initial(1))
        changed = bytearray(CLIENT_HELLO)
        changed[CUT + 3] ^= 0x55
        self.assertEqual(feed(analyzer, 0.2, A, initial(1, pieces=crypto_frames(bytes(changed), (CUT,)))).status, "invalidated")
        ping = feed(analyzer, 0.3, A, protect(V1, DCID, b"", b"\x01"))                       # PING only, no CRYPTO
        self.assertEqual((ping.status, ping.hostname), ("invalidated", None))
        self.assertEqual({e.field: e.value for e in ping.evidence}["crypto_assembly"], "conflict")
        self.assertEqual(feed(analyzer, 0.4, A, protect(V1, DCID, b"", b"\x02\x00\x00\x00\x00")).status, "invalidated")   # ACK only
        self.assertEqual(feed(analyzer, 0.5, A, protect(V1, DCID, b"", b"\x00" * 8)).status, "invalidated")                  # PADDING only
        damaged = bytearray(initial(0))
        damaged[-1] ^= 0xff                                                                   # AEAD tag broken: cannot be opened
        self.assertEqual(feed(analyzer, 0.6, A, bytes(damaged)).status, "invalidated")
        other = feed(analyzer, 0.7, A, DNS)                                                   # another family on the same tuple
        self.assertEqual(other.status, "identified")                                          # reported as an event ...
        analyzer.finish("eof")
        record = records[0]
        self.assertEqual((record["engine_status"], record["app"]), ("invalidated", "not-applicable"))   # ... never as the verdict
        self.assertIsNone(record.get("hostname"))
        # A fresh flow on the tuple after the first ended starts clean.
        analyzer2, records2, _ = analyzer_with_records()
        feed(analyzer2, 0.0, A, initial(0))
        feed(analyzer2, 0.1, A, initial(1, pieces=crypto_frames(bytes(changed), (CUT,))))
        analyzer2.finish("eof")
        clean = feed(analyzer2, 1.0, A, protect(V1, DCID, b"", b"\x01"))
        self.assertEqual(clean.status, "identified")

    def test_assembler_conflict_marker_query(self):
        store = QuicAssembler()
        self.assertFalse(store.conflicted(DCID, "s", V1, 0.0))
        store.add(DCID, [(0, CLIENT_HELLO[:CUT])], "s", V1, 0.0)
        changed = bytearray(CLIENT_HELLO[:CUT])
        changed[3] ^= 0x55
        self.assertEqual(store.add(DCID, [(0, bytes(changed))], "s", V1, 0.1)[0], "conflict")
        self.assertTrue(store.conflicted(DCID, "s", V1, 0.2))
        self.assertFalse(store.conflicted(DCID, "other", V1, 0.2))                            # another scope is untouched
        self.assertTrue(store.conflicted(DCID, "s", V1, 50.0))                                # touched: still inside the idle window
        store.reset("s")
        self.assertFalse(store.conflicted(DCID, "s", V1, 50.1))                               # the host ended the flow

    def test_tuple_reuse_after_expiry_starts_clean(self):
        analyzer, records, _ = analyzer_with_records()
        self.assertEqual(feed(analyzer, 0.0, A, initial(0)).hostname, None)
        analyzer.expire(100.0)                                               # the flow and its CRYPTO state expire together
        self.assertEqual(len(records), 1)
        changed = bytearray(CLIENT_HELLO)
        changed[5] ^= 1
        pieces = crypto_frames(bytes(changed), (CUT,))
        self.assertIsNone(feed(analyzer, 100.0, A, initial(0, pieces=pieces)).hostname)
        later = feed(analyzer, 100.1, A, initial(1, pieces=pieces))
        self.assertNotEqual(later.status, "invalidated")                    # no stale fragments from the old flow

    def test_bare_inspector_keeps_one_namespace_and_rejects_nothing_silently(self):
        inspector = DatagramInspector(Config(), quic_assembler=QuicAssembler())
        self.assertIsNone(inspector.inspect(initial(0)).hostname)
        self.assertEqual(inspector.inspect(initial(1)).hostname, "example.com")
        inspector.quic_assembler.clear()
        self.assertIsNone(inspector.inspect(initial(1), scope=("x",)).hostname)
        self.assertIsNone(inspector.inspect(initial(0), scope=("y",)).hostname)   # scopes do not meet


if __name__ == "__main__":
    unittest.main()
