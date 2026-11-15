"""D10: stateful and metamorphic sequence relations over the Analyzer (tools/sequence_check.py)."""
import unittest

from protocol_adapters.protocol_fixtures import STREAM_CASES
from tools import sequence_check
from tools.sequence_check import Connection, Checker, drive, normalize, run

REQUEST = b"GET /sequence HTTP/1.1\r\nHost: seq.example\r\nUser-Agent: t\r\n\r\n"


class RelationTests(unittest.TestCase):
    def test_every_relation_holds_on_a_slice_of_the_corpus(self):
        checker = run(seed=7, iterations=2, limit=20)
        self.assertEqual(checker.violations, [])
        for relation in ("segmentation", "reordering", "conflict", "conflict-invalidated", "fin-first", "reuse", "expiry", "interleaving"):
            self.assertGreater(checker.counts[relation], 0, relation)

    def test_whole_corpus_once(self):
        checker = run(seed=20261107, iterations=1)
        self.assertEqual(checker.violations, [])
        self.assertEqual(checker.counts["reuse"], len(sequence_check.automatic_streams()))

    def test_checker_reports_a_broken_relation(self):
        checker = Checker(seed=1, iterations=1)
        checker.same("label", "segmentation", {"app": "a"}, {"app": "b"})
        self.assertEqual(len(checker.violations), 1)
        self.assertIn("segmentation", checker.violations[0])
        self.assertIn("seed 1", checker.violations[0])

    def test_drive_normalizes_timing_and_counts_away(self):
        connection = Connection(("192.0.2.10", 52000), ("198.51.100.20", 8000))
        one, _ = drive(connection.handshake() + connection.segments(REQUEST, []) + [connection.fin(REQUEST)])
        many, counters = drive(connection.handshake() + connection.segments(REQUEST, [3, 9, 10, 30]) + [connection.fin(REQUEST)])
        key = (connection.client, connection.server)
        self.assertEqual(one[key], many[key])
        self.assertEqual(one[key][0]["app"], "web-browsing")
        self.assertNotIn("start", one[key][0])
        self.assertEqual(counters["bytes.new"], len(REQUEST))
        self.assertEqual(set(normalize({"risks": ["b", "a"]})["risks"]), {"a", "b"})

    def test_conflicting_retransmission_invalidates_explicitly(self):
        connection = Connection(("192.0.2.10", 52000), ("198.51.100.20", 8000))
        segments = connection.segments(REQUEST, [10])
        changed = bytearray(REQUEST[:10])
        changed[4] ^= 0xff
        conflict = sequence_check.frame(connection.client, connection.server, connection.isn, connection.server_isn, 24, bytes(changed))
        keyed, _ = drive(connection.handshake() + [segments[0], conflict, segments[1], connection.fin(REQUEST)])
        record = keyed[(connection.client, connection.server)][-1]
        self.assertEqual(record["engine_status"], "invalidated")
        self.assertIsNone(record["client_protocol"])

    def test_automatic_corpus_covers_many_families(self):
        families = {label.split("/", 1)[0] for _, label in STREAM_CASES}
        covered = {label.split("/", 1)[0] for _, label in sequence_check.automatic_streams()}
        self.assertGreaterEqual(len(covered), 50)
        self.assertTrue(covered <= families)


if __name__ == "__main__":
    unittest.main()
