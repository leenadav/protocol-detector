import random
import ssl
import unittest
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from dataclasses import asdict

from protocol_engine import ApplicationRule, Config, Inspector, RuleIndex
from sessions import SessionManager, StreamError

HTTP = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
SSH = b"SSH-2.0-Demo_1.0\r\n"


def tls_example():
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2", "http/1.1"])
    client = context.wrap_bio(incoming, outgoing, server_hostname="example.com")
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


class EngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tls = tls_example()

    def inspect_chunks(self, data, chunks):
        inspector = Inspector()
        offset = 0
        for size in chunks:
            inspector.feed(data[offset:offset + size])
            offset += size
        inspector.feed(data[offset:])
        return inspector

    def test_every_split_point_preserves_classification(self):
        for data in (HTTP, SSH, self.tls):
            expected = self.inspect_chunks(data, []).observation
            self.assertEqual(expected.status, "identified")
            for split in range(len(data) + 1):
                inspector = self.inspect_chunks(data, [split])
                self.assertEqual(inspector.observation, expected, split)
                self.assertEqual(inspector.metrics.candidates_selected, 1)

    def test_single_bytes_inspected_once(self):
        for data in (HTTP, SSH, self.tls):
            inspector = self.inspect_chunks(data, [1] * len(data))
            self.assertEqual(inspector.observation.status, "identified")
            self.assertEqual(inspector.metrics.bytes_inspected, len(data))
            self.assertLessEqual(inspector.metrics.parser_calls, len(data) + 1)

    def test_tls_sni_alpn_are_not_inner_http(self):
        inspector = self.inspect_chunks(self.tls, [2, 3, 7])
        result = inspector.observation
        self.assertEqual(result.encryption, "tls")
        self.assertEqual(result.hostname, "example.com")
        self.assertEqual(result.offered_alpn, ("h2", "http/1.1"))
        self.assertIsNone(result.application_protocol)
        self.assertIsNone(result.application)

    def test_decrypted_refinement_retains_tls(self):
        rules = RuleIndex([ApplicationRule("example.com", "Example service", "http_host")])
        inspector = Inspector(rules=rules)
        outer_events = inspector.feed(self.tls)
        self.assertFalse(inspector.feed_decrypted(HTTP[:10]))
        events = inspector.feed_decrypted(HTTP[10:])
        self.assertEqual(events[-1].kind, "refined")
        self.assertGreater(events[-1].revision, outer_events[-1].revision)
        result = events[-1].observation
        self.assertEqual((result.encryption, result.application_protocol), ("tls", "http/1.1"))
        self.assertEqual(result.application, "Example service")
        self.assertTrue(any(e.source == "decrypted" for e in result.evidence))
        self.assertTrue(any(e.strength == "configured_mapping" for e in result.evidence))
        self.assertEqual(len(result.offered_alpn), 2)

    def test_outer_mapping_does_not_leak_to_different_inner_host(self):
        inspector = Inspector(rules=RuleIndex([ApplicationRule("example.com", "Example", "tls_sni")]))
        inspector.feed(self.tls)
        self.assertEqual(inspector.observation.application, "Example")
        inspector.feed_decrypted(HTTP.replace(b"example.com", b"other.example"))
        self.assertIsNone(inspector.observation.application)
        self.assertFalse(any(e.field == "application" for e in inspector.observation.evidence))

    def test_no_plaintext_api_without_tls(self):
        inspector = Inspector()
        with self.assertRaises(ValueError):
            inspector.feed_decrypted(HTTP)
        inspector.feed(HTTP)
        with self.assertRaises(ValueError):
            inspector.feed_decrypted(HTTP)

    def test_terminal_bypass_does_not_rerun_parsers(self):
        inspector = Inspector()
        inspector.feed(HTTP)
        calls = inspector.metrics.parser_calls
        inspected = inspector.metrics.bytes_inspected
        for _ in range(1000):
            self.assertEqual(inspector.feed(b"x" * 4096), ())
        self.assertEqual(inspector.metrics.parser_calls, calls)
        self.assertEqual(inspector.metrics.bytes_inspected, inspected)

    def test_budgets_are_not_protocol_mismatch(self):
        inspector = Inspector(Config(max_updates=2))
        for chunk in (b"G", b"E", b"T"):
            inspector.feed(chunk)
        self.assertEqual(inspector.observation.status, "budget_exhausted")
        inspector = Inspector(Config(max_bytes=64))
        inspector.feed(b"GET /" + b"a" * 100)
        self.assertEqual(inspector.metrics.bytes_inspected, 64)
        self.assertEqual(inspector.observation.status, "budget_exhausted")

    def test_line_header_and_tls_bounds(self):
        examples = [(Config(max_line=32), b"GET /" + b"a" * 40, "budget_exhausted"),
                    (Config(max_headers=1), HTTP[:-2] + b"X: y\r\n\r\n", "budget_exhausted"),
                    (Config(), b"\x16\x03\x03\xff\xff", "malformed"),
                    (Config(), b"\x16\x03\x03\x00\x04\x01\xff\xff\xff", "budget_exhausted")]
        for config, data, expected in examples:
            inspector = Inspector(config)
            inspector.feed(data)
            self.assertEqual(inspector.observation.status, expected)

    def test_http_ambiguity_and_version(self):
        for extra in (b"Host: other.com\r\n", b"Host : bad.com\r\n",
                      b"Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
                      b"Content-Length: 1\r\nContent-Length: 1\r\n"):
            inspector = Inspector()
            inspector.feed(HTTP[:-2] + extra + b"\r\n")
            self.assertEqual(inspector.observation.status, "malformed")
        inspector = Inspector()
        inspector.feed(b"GET /HTTP/1.1 HTTP/1.0\r\n\r\n")
        self.assertEqual(inspector.observation.application_protocol, "http/1.0")

    def test_exact_rule_index_and_duplicate_rejection(self):
        index = RuleIndex([ApplicationRule("EXAMPLE.com.", "Example", "tls_sni")])
        self.assertEqual(index.lookup("tls_sni", "example.com"), "Example")
        self.assertIsNone(index.lookup("tls_sni", "evil.example.com"))
        self.assertIsNone(index.lookup("http_host", "example.com"))
        with self.assertRaises(ValueError):
            RuleIndex([ApplicationRule("x.com", "A", "tls_sni"), ApplicationRule("X.com", "B", "tls_sni")])
        with self.assertRaises(ValueError):
            RuleIndex([ApplicationRule("*.example.com", "A", "tls_sni")])

    def test_unknown_eof_and_invalidation(self):
        inspector = Inspector()
        inspector.feed(b"\x00\x01garbage")
        self.assertEqual(inspector.observation.status, "unknown")
        self.assertEqual(inspector.metrics.candidates_selected, 0)
        inspector = Inspector()
        inspector.feed(b"GE")
        inspector.end()
        self.assertEqual(inspector.observation.status, "incomplete")
        inspector = Inspector()
        inspector.feed(self.tls)
        inspector.invalidate("Conflicting overlap")
        self.assertIsNone(inspector.observation.encryption)
        self.assertEqual(inspector.feed(self.tls), ())
        with self.assertRaises(ValueError):
            inspector.feed_decrypted(HTTP)

    def test_session_delivers_deltas_and_no_duplicate_work(self):
        manager = SessionManager()
        source, target = ("192.0.2.1", 1000), ("192.0.2.2", 443)
        manager.open_connection(source, target, 100, 200)
        stream = manager.connections[manager.key(source, target)]["directions"][source]
        manager.feed(source, target, 110, HTTP[10:])
        self.assertEqual(stream.inspector.metrics.bytes_received, 0)
        manager.feed(source, target, 100, HTTP[:10])
        before = asdict(stream.inspector.metrics)
        manager.feed(source, target, 100, HTTP)
        self.assertEqual(asdict(stream.inspector.metrics), before)
        self.assertEqual(before["bytes_received"], len(HTTP))
        with self.assertRaises(StreamError):
            manager.feed(source, target, 100, b"X")
        self.assertEqual(stream.inspector.observation.status, "invalidated")

    def test_fragmented_tls_records(self):
        body = self.tls[5:]
        def record(chunk):
            return b"\x16\x03\x03" + len(chunk).to_bytes(2, "big") + chunk
        fragmented = record(body[:2]) + record(body[2:20]) + record(body[20:])
        inspector = self.inspect_chunks(fragmented, [1] * len(fragmented))
        self.assertEqual(inspector.observation.status, "identified")
        self.assertEqual(inspector.observation.hostname, "example.com")

    def test_seeded_random_data_and_mutations_are_bounded(self):
        rng = random.Random(77)
        samples = [bytes(rng.randrange(256) for _ in range(rng.randrange(1024))) for _ in range(500)]
        for _ in range(200):
            data = bytearray(self.tls)
            data[rng.randrange(len(data))] = rng.randrange(256)
            samples.append(bytes(data))
        for data in samples:
            inspector = Inspector()
            for start in range(0, len(data), 7):
                inspector.feed(data[start:start + 7])
            inspector.end()
            self.assertLessEqual(inspector.metrics.candidates_selected, 1)
            self.assertLessEqual(inspector.metrics.bytes_inspected, len(data))


class IntegrationTests(unittest.TestCase):
    def test_tls_extension_boundaries_and_metadata_rejection(self):
        def hello(extension_data):
            body = (b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x00\x2f\x01\x00" +
                    len(extension_data).to_bytes(2, "big") + extension_data)
            handshake = b"\x01" + len(body).to_bytes(3, "big") + body
            return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake
        def extension(kind, data):
            return kind.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data
        malformed = [
            extension(0, b"\x00\x01\x00"),  # truncated name length
            extension(0, b"\x00\x00"),  # empty SNI
            extension(16, b"\x00\x00"),  # empty ALPN
            extension(16, b"\x00\x02\x05h"),  # ALPN item exceeds vector
            extension(1234, b"") * 2,  # duplicate extension
            b"\x00\x10\x00\x05hi",  # extension exceeds enclosing vector
        ]
        for payload in malformed:
            inspector = Inspector()
            inspector.feed(hello(payload))
            self.assertEqual(inspector.observation.status, "malformed")
            self.assertIsNone(inspector.observation.hostname)
        inspector = Inspector()
        inspector.feed(hello(extension(1234, b"opaque")))
        self.assertEqual(inspector.observation.status, "identified")
        self.assertIsNone(inspector.observation.application)

    def test_many_rules_do_not_increase_parser_work(self):
        rules = RuleIndex([ApplicationRule("host{}.example".format(i), "App {}".format(i), "http_host")
                           for i in range(30000)])
        request = HTTP.replace(b"example.com", b"host29999.example")
        baseline, indexed = Inspector(), Inspector(rules=rules)
        baseline.feed(request)
        indexed.feed(request)
        self.assertEqual(indexed.observation.application, "App 29999")
        self.assertEqual(baseline.metrics.parser_calls, indexed.metrics.parser_calls)
        self.assertEqual(indexed.metrics.candidates_selected, 1)

    def test_http_ip_literals_and_invalid_authorities(self):
        for host in (b"192.0.2.1:443", b"[2001:db8::1]:443"):
            inspector = Inspector()
            inspector.feed(HTTP.replace(b"example.com", host))
            self.assertEqual(inspector.observation.status, "identified")
            self.assertIsNone(inspector.observation.hostname)
        for host in (b"example.com..", b"example.com:999999999999", b"example.com:0"):
            inspector = Inspector()
            inspector.feed(HTTP.replace(b"example.com", host))
            self.assertEqual(inspector.observation.status, "malformed")

    def test_decrypted_eof_preserves_only_envelope_evidence(self):
        rules = RuleIndex([ApplicationRule("example.com", "Outer candidate", "tls_sni")])
        inspector = Inspector(rules=rules)
        inspector.feed(tls_example())
        inspector.feed_decrypted(b"GET / HT")
        events = inspector.end()
        self.assertEqual(events[-1].observation.status, "incomplete")
        self.assertEqual(inspector.observation.encryption, "tls")
        self.assertIsNone(inspector.observation.application)

    def test_json_pcap_events_are_change_only(self):
        from analyze_pcap import analyze
        output = io.StringIO()
        with redirect_stdout(output):
            analyze(Path(__file__).with_name("sample.pcap"), json_output=True, events_only=True)
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(rows), 5)
        self.assertEqual([row["frame"] for row in rows if "frame" in row], [7, 8, 10])
        self.assertEqual(rows[-2]["type"], "stream_end")
        self.assertEqual(rows[-2]["classification"]["status"], "incomplete")
        self.assertEqual(rows[0]["classification"]["application_protocol"], "ssh")

    def test_invalid_config_and_input(self):
        for kwargs in ({"max_bytes": -1}, {"max_updates": 0}, {"max_headers": True}):
            with self.assertRaises(ValueError):
                Config(**kwargs)
        with self.assertRaises(TypeError):
            Inspector().feed("not bytes")
        with self.assertRaises(TypeError):
            Inspector(config={})


if __name__ == "__main__":
    unittest.main()
