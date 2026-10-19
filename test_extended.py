import ipaddress
import json
import random
import subprocess
import sys
import unittest
from pathlib import Path
from protocol_engine import ApplicationRule, Config, Inspector, RuleIndex
from protocol_engine.extended import H2_PREFACE
from protocol_demo import HTTP2, SOCKS5, examples
from protocol_fixtures import DATAGRAM_CASES, HINTED_DATAGRAM_CASES
from proxy_demo import client_hello
from sessions import SessionManager


def h2(settings=b"", flags=0, stream=0, frame_type=4):
    return H2_PREFACE + len(settings).to_bytes(3, "big") + bytes([frame_type, flags]) + stream.to_bytes(4, "big") + settings


def setting(identifier, value):
    return identifier.to_bytes(2, "big") + value.to_bytes(4, "big")


class ExtendedTests(unittest.TestCase):
    def inspect(self, data, config=None):
        result = Inspector(config)
        result.feed(data)
        return result

    def test_every_split_point_and_single_byte_feeds(self):
        cases = [(HTTP2, "http/2"), (h2(setting(2, 0) + setting(5, 32768)), "http/2"),
                 (SOCKS5, "socks5"), (b"EHLO client.example.com\r\n", "smtp"),
                 (b"helo [IPv6:2001:db8::1]\r\n", "smtp")]
        for data, protocol in cases:
            expected = self.inspect(data).observation
            self.assertEqual(expected.application_protocol, protocol)
            for split in range(len(data) + 1):
                inspector = Inspector()
                inspector.feed(data[:split])
                inspector.feed(data[split:])
                self.assertEqual(inspector.observation, expected, (protocol, split))
            inspector = Inspector()
            for byte in data:
                inspector.feed(bytes([byte]))
            self.assertEqual(inspector.observation, expected)
            self.assertEqual(inspector.metrics.bytes_inspected, len(data))
            self.assertEqual(inspector.metrics.candidates_selected, 1)

    def test_no_match_before_complete_required_structure(self):
        for data in (HTTP2, SOCKS5, b"EHLO client.example.com\r\n"):
            for length in range(len(data)):
                inspector = self.inspect(data[:length])
                self.assertEqual(inspector.observation.status, "detecting", (data, length))
                inspector.end()
                self.assertEqual(inspector.observation.status, "incomplete")

    def test_h2_frame_constraints(self):
        for data in (h2(flags=1), h2(stream=1), h2(frame_type=0), h2(b"x"),
                     h2(setting(2, 2)), h2(setting(4, 0x80000000)), h2(setting(5, 10))):
            self.assertEqual(self.inspect(data).observation.status, "malformed")
        huge = H2_PREFACE + (16386).to_bytes(3, "big") + b"\x04\x00" + bytes(4)
        self.assertEqual(self.inspect(huge).observation.status, "malformed")

    def test_h2_reserved_bits_unknown_settings_and_repeated_settings(self):
        data = h2(setting(65000, 42) + setting(2, 0) + setting(2, 1), flags=128, stream=0x80000000)
        self.assertEqual(self.inspect(data).observation.application_protocol, "http/2")

    def test_h2_is_not_inferred_from_alpn_or_server_settings_alone(self):
        inspector = self.inspect(client_hello())
        self.assertIsNone(inspector.observation.application_protocol)
        inspector.feed_decrypted(HTTP2)
        self.assertEqual(inspector.observation.application_protocol, "http/2")
        self.assertEqual(inspector.observation.encryption, "tls")
        self.assertNotEqual(self.inspect(HTTP2[24:]).observation.status, "identified")

    def test_prefix_collisions_fall_back_to_actual_http_syntax(self):
        for method in (b"PRI", b"EHLO", b"HELO", b"SSH-", b"POST", b"PATCH"):
            data = method + b" / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            self.assertEqual(self.inspect(data).observation.application_protocol, "http/1.1", method)

    def test_socks_addresses_commands_and_no_target_application_mapping(self):
        for cmd in (1, 2, 3):
            for atyp, address in ((1, ipaddress.IPv4Address("192.0.2.1").packed),
                                  (4, ipaddress.IPv6Address("2001:db8::1").packed),
                                  (3, b"\x0bexample.com")):
                data = b"\x05\x02\x00\x02\x05" + bytes([cmd, 0, atyp]) + address + b"\x00\x00"
                result = self.inspect(data).observation
                self.assertEqual(result.application_protocol, "socks5")
                self.assertIsNone(result.hostname)
        inspector = Inspector(rules=RuleIndex([ApplicationRule("example.com", "Wrong inference", "http_host")]))
        inspector.feed(SOCKS5)
        self.assertIsNone(inspector.observation.application)
        self.assertTrue(any(e.field == "socks_target" and e.value == "example.com" for e in inspector.observation.evidence))

    def test_socks_invalid_or_unsupported(self):
        for data in (b"\x05\x00", b"\x05\x01\xff", b"\x05\x01\x00\x05\x04\x00\x01",
                     b"\x05\x01\x00\x05\x01\x01\x01", b"\x05\x01\x00\x05\x01\x00\x08",
                     b"\x05\x01\x00\x05\x01\x00\x03\x00"):
            self.assertEqual(self.inspect(data).observation.status, "malformed")
        self.assertEqual(self.inspect(b"\x05\x01\x02").observation.status, "unknown")

    def test_smtp_identities_and_ambiguous_server_greeting(self):
        for identity in (b"client.example.com", b"[192.0.2.1]", b"[IPv6:2001:db8::1]"):
            observation = self.inspect(b"EHLO " + identity + b"\r\n").observation
            self.assertEqual(observation.application_protocol, "smtp")
            self.assertIsNone(observation.hostname)  # client identity != server/application
        for line in (b"EHLO\r\n", b"EHLO /bad\r\n", b"EHLO client.example extra\r\n", b"HELO [999.1.1.1]\r\n"):
            self.assertEqual(self.inspect(line).observation.status, "malformed")
        for greeting in (b"220 mail.example SMTP ready\r\n", b"220 FTP ready\r\n", b"220-server ready\r\n"):
            self.assertEqual(self.inspect(greeting).observation.status, "unknown")

    def test_limits_terminal_bypass_and_reordering(self):
        self.assertEqual(self.inspect(h2(setting(1, 0) * 6), Config(max_bytes=64)).observation.status, "budget_exhausted")
        for data in (HTTP2, SOCKS5, b"EHLO client.example\r\n"):
            inspector = self.inspect(data)
            calls = inspector.metrics.parser_calls
            inspector.feed(b"later payload" * 1000)
            self.assertEqual(inspector.metrics.parser_calls, calls)
            manager = SessionManager()
            a, b = ("192.0.2.1", 50000), ("192.0.2.2", 9876)
            manager.open_connection(a, b, 100, 200)
            manager.feed(a, b, 107, data[7:])
            snapshot = manager.feed(a, b, 100, data[:7])
            self.assertEqual(snapshot.classification, self.inspect(data).observation)
            self.assertTrue(any(r.status == "MATCH" for r in snapshot.results))

    def test_seeded_mutation_and_fragmentation_never_crashes(self):
        rng = random.Random(1928)
        for base in (HTTP2, SOCKS5, b"EHLO client.example\r\n"):
            for _ in range(200):
                data = bytearray(base)
                data[rng.randrange(len(data))] = rng.randrange(256)
                inspector = Inspector()
                for offset in range(0, len(data), 3):
                    inspector.feed(bytes(data[offset:offset + 3]))
                inspector.end()
                self.assertLessEqual(inspector.metrics.bytes_inspected, len(data))
                self.assertLessEqual(inspector.metrics.candidates_selected, 1)

    def test_readable_and_json_demo(self):
        root = Path(__file__).parent
        output = subprocess.check_output([sys.executable, "-B", str(root / "protocol_demo.py")], text=True)
        self.assertIn("HTTP/2 -> IDENTIFIED | http/2", output)
        output = subprocess.check_output([sys.executable, "-B", str(root / "protocol_demo.py"), "--json"], text=True)
        rows = [json.loads(line) for line in output.splitlines()]
        from protocol_fixtures import HINTED_STREAM_CASES
        self.assertEqual(len(rows), len(examples()) + len(DATAGRAM_CASES) + len(HINTED_DATAGRAM_CASES) + len(HINTED_STREAM_CASES))
        self.assertEqual(rows[len(examples()) - 1]["observation"]["status"], "unknown")

    def test_packet_decoder_and_pcap_analyzer_path(self):
        from analyze_pcap import Analyzer
        from make_sample_pcap import A, B, frame
        from packets import decode_tcp
        for payload, name in ((HTTP2, "http/2"), (SOCKS5, "socks5"), (b"EHLO client.example\r\n", "smtp")):
            analyzer = Analyzer()
            packets = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18),
                       frame(A, B, 1007, 9000, 24, payload[7:]),
                       frame(A, B, 1000, 9000, 24, payload[:7])]
            for timestamp, packet in enumerate(packets):
                analyzer.process(timestamp, decode_tcp(packet))
            self.assertEqual(analyzer.last_classification.application_protocol, name)


if __name__ == "__main__":
    unittest.main()
