import unittest
from sessions import SessionManager, StreamError
from main import make_tls_example

A, B, C = ("192.0.2.1", 50000), ("192.0.2.2", 80), ("192.0.2.3", 443)
REQUEST = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.manager = SessionManager()
        self.manager.open_connection(A, B, 1000, 9000)

    def test_gap_then_reassembly(self):
        result = self.manager.feed(A, B, 1010, REQUEST[10:])
        self.assertEqual(result.contiguous_bytes, 0)
        self.assertEqual(result.pending_bytes, len(REQUEST) - 10)
        self.assertFalse(any(r.status == "MATCH" for r in result.results))
        result = self.manager.feed(A, B, 1000, REQUEST[:10])
        self.assertEqual(result.contiguous_bytes, len(REQUEST))
        self.assertEqual(result.pending_bytes, 0)
        self.assertEqual(result.results[0].status, "MATCH")

    def test_retransmission_and_consistent_overlap(self):
        self.manager.feed(A, B, 1000, REQUEST[:15])
        complete = self.manager.feed(A, B, 1010, REQUEST[10:])
        duplicate = self.manager.feed(A, B, 1000, REQUEST)
        self.assertEqual(complete, duplicate)

    def test_conflict_invalidates_stream(self):
        self.manager.feed(A, B, 1000, REQUEST)
        with self.assertRaises(StreamError):
            self.manager.feed(A, B, 1000, b"X")
        with self.assertRaises(StreamError):
            self.manager.feed(A, B, 1000, REQUEST)

    def test_directions_and_connections_are_separate(self):
        self.manager.open_connection(A, C, 2000, 7000)
        self.manager.feed(A, B, 1000, REQUEST[:10])
        ssh = self.manager.feed(A, C, 2000, b"SSH-2.0-Demo\r\n")
        self.assertEqual(ssh.results[1].status, "MATCH")
        response = b"HTTP/1.1 200 OK\r\n\r\n"
        reverse = self.manager.feed(B, A, 9000, response)
        self.assertEqual(reverse.results[0].status, "MATCH")
        forward = self.manager.feed(A, B, 1010, REQUEST[10:])
        self.assertEqual(forward.contiguous_bytes, len(REQUEST))
        self.assertEqual(len(self.manager.connections), 2)

    def test_sequence_wraparound(self):
        manager = SessionManager()
        manager.open_connection(A, B, 2 ** 32 - 5, 10)
        manager.feed(A, B, 0, REQUEST[5:])
        result = manager.feed(A, B, 2 ** 32 - 5, REQUEST[:5])
        self.assertEqual(result.results[0].status, "MATCH")

    def test_binary_tls_split_across_tcp_segments(self):
        hello = make_tls_example()
        for offset in range(len(hello) - 1, -1, -1):
            result = self.manager.feed(A, B, 1000 + offset, hello[offset:offset + 1])
        self.assertEqual(result.results[2].status, "MATCH")
        self.assertEqual(result.contiguous_bytes, len(hello))

    def test_limits(self):
        manager = SessionManager(byte_limit=16, max_connections=1)
        manager.open_connection(A, B, 1000, 9000)
        with self.assertRaises(StreamError):
            manager.open_connection(A, C, 2000, 7000)
        with self.assertRaises(StreamError):
            manager.feed(A, B, 1016, b"X")

    def test_expiry_and_reuse(self):
        now = [0]
        manager = SessionManager(idle_timeout=10, clock=lambda: now[0])
        manager.open_connection(A, B, 1000, 9000)
        now[0] = 10
        with self.assertRaises(StreamError):
            manager.feed(A, B, 1000, REQUEST)
        manager.open_connection(A, B, 2000, 8000)
        self.assertEqual(manager.feed(A, B, 2000, REQUEST).results[0].status, "MATCH")
        manager.close(B, A)
        self.assertEqual(len(manager.connections), 0)

    def test_requires_known_start_and_no_silent_replacement(self):
        with self.assertRaises(StreamError):
            self.manager.feed(A, C, 2000, b"SSH-2.0-Demo\r\n")
        with self.assertRaises(ValueError):
            self.manager.open_connection(B, A, 9000, 1000)


if __name__ == "__main__":
    unittest.main()
