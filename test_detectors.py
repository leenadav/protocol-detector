import random
import unittest

from detectors import MATCH, NEED_MORE, NO_MATCH, detect_all, detect_http, detect_ssh, detect_tls
from main import make_tls_example


class DetectorTests(unittest.TestCase):
    def test_http_request_and_response(self):
        for data in (b"DELETE / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                     b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"):
            self.assertEqual(detect_http(data).status, MATCH)

    def test_http_waits_for_headers(self):
        for data in (b"DELETE / HT", b"GET / HTTP/1.1\r\nHost: example.com\r\n"):
            self.assertEqual(detect_http(data).status, NEED_MORE)

    def test_http_malformed_headers(self):
        for header in (b"Broken", b"Host : example.com", b"Host: a\r\nHost: b", b"X: y"):
            self.assertEqual(detect_http(b"GET / HTTP/1.1\r\n" + header + b"\r\n\r\n").status, NO_MATCH)

    def test_ssh(self):
        self.assertEqual(detect_ssh(b"SSH-2.0-Demo_1.0\r\n").status, MATCH)
        self.assertEqual(detect_ssh(b"SSH-2.0-Demo").status, NEED_MORE)
        for data in (b"SSH-2.0-\r\n", b"SSH-9.0-Demo\r\n", b"SSH-2.0-" + b"a" * 250 + b"\r\n"):
            self.assertEqual(detect_ssh(data).status, NO_MATCH)

    def test_real_client_hello_and_every_truncated_prefix(self):
        hello = make_tls_example()
        self.assertEqual(detect_tls(hello).status, MATCH)
        for size in range(len(hello)):
            self.assertEqual(detect_tls(hello[:size]).status, NEED_MORE, size)

    def test_hello_across_tls_records(self):
        hello = make_tls_example()
        body = hello[5:]
        def record(payload):
            return b"\x16\x03\x03" + len(payload).to_bytes(2, "big") + payload
        self.assertEqual(detect_tls(record(body[:2]) + record(body[2:])).status, MATCH)

    def test_tls_bad_lengths(self):
        hello = bytearray(make_tls_example())
        hello[43] = 33  # ClientHello session ID exceeds maximum length.
        self.assertEqual(detect_tls(bytes(hello)).status, NO_MATCH)
        self.assertEqual(detect_tls(b"\x16\x03\x03\xff\xff").status, NO_MATCH)
        hello = bytearray(make_tls_example())
        hello[6:9] = (41).to_bytes(3, "big")  # Inner length contradicts fields.
        self.assertEqual(detect_tls(bytes(hello)).status, NO_MATCH)

    def test_embedded_protocol_names_do_not_match(self):
        results = detect_all(b"File mentions HTTP/1.1 and SSH-2.0\r\n\r\n")
        self.assertTrue(all(result.status == NO_MATCH for result in results))

    def test_random_inputs_do_not_crash(self):
        rng = random.Random(42)
        for _ in range(500):
            data = bytes(rng.randrange(256) for _ in range(rng.randrange(300)))
            self.assertEqual(len(detect_all(data)), 3)


if __name__ == "__main__":
    unittest.main()
