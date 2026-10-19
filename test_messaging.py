import random
import unittest
from protocol_engine import Config, Inspector
from protocol_engine.dispatch import LOOKAHEAD, select
from protocol_engine.messaging import RESPParser
from protocol_demo import AMQP_091, AMQP_10, HTTP2, MQTT, RESP, SOCKS5
from proxy_demo import client_hello
from sessions import SessionManager


def vector(value):
    return len(value).to_bytes(2, "big") + value


def remaining_length(value):
    result = bytearray()
    while True:
        byte, value = value % 128, value // 128
        result.append(byte | (128 if value else 0))
        if not value:
            return bytes(result)


def mqtt(flags=2, client=b"demo", tail=b"", level=4):
    body = vector(b"MQTT") + bytes([level, flags]) + b"\x00\x3c" + vector(client) + tail
    return b"\x10" + remaining_length(len(body)) + body


def resp(*args):
    return b"*%d\r\n" % len(args) + b"".join(b"$%d\r\n" % len(arg) + arg + b"\r\n" for arg in args)


CASES = ((MQTT, "mqtt/3.1.1"), (RESP, "resp"), (AMQP_091, "amqp/0-9-1"), (AMQP_10, "amqp/1.0"))


class MessagingTests(unittest.TestCase):
    def inspect(self, data, config=None):
        inspector = Inspector(config)
        inspector.feed(data)
        return inspector

    def test_all_splits_one_byte_and_exact_byte_accounting(self):
        for data, protocol in CASES:
            expected = self.inspect(data).observation
            self.assertEqual(expected.application_protocol, protocol)
            for split in range(len(data) + 1):
                inspector = Inspector()
                inspector.feed(data[:split])
                inspector.feed(data[split:])
                self.assertEqual(inspector.observation, expected, (protocol, split))
                self.assertEqual(inspector.metrics.bytes_inspected, len(data))
            inspector = Inspector()
            for byte in data:
                inspector.feed(bytes([byte]))
            self.assertEqual(inspector.observation, expected)
            self.assertEqual(inspector.metrics.bytes_inspected, len(data))
            self.assertEqual(inspector.metrics.candidates_selected, 1)

    def test_no_premature_identification(self):
        for data, _ in CASES:
            for end in range(len(data)):
                inspector = self.inspect(data[:end])
                self.assertEqual(inspector.observation.status, "detecting", (data, end))
                inspector.end()
                self.assertEqual(inspector.observation.status, "incomplete")

    def test_mqtt_optional_fields_binary_password_and_multibyte_length(self):
        tail = vector(b"sensors/temp") + vector(b"\xff\x00" * 90) + vector(b"user") + vector(b"\xff\x00secret")
        data = mqtt(flags=0xee, tail=tail)  # clean, will QoS1 + retain, user/password
        expected = self.inspect(data).observation
        self.assertEqual(expected.application_protocol, "mqtt/3.1.1")
        for step in (1, 2, 7, 128):
            inspector = Inspector()
            for pos in range(0, len(data), step):
                inspector.feed(data[pos:pos + step])
            self.assertEqual(inspector.observation, expected)
        self.assertNotIn("secret", repr(expected))
        self.assertNotIn("sensors", repr(expected))

    def test_mqtt_flags_and_field_validation(self):
        invalid = [mqtt(flags=f) for f in (1, 8, 0x20, 0x1c, 0x40)]
        invalid += [mqtt(flags=0, client=b""), mqtt(client=b"bad\x00id"),
                    mqtt(client=b"\xed\xa0\x80"), mqtt(client=b"\xc0\x80"),
                    mqtt(flags=6, tail=vector(b"bad/+") + vector(b"x")),
                    mqtt(flags=6, tail=vector(b"") + vector(b"x")),
                    mqtt(flags=0x82, tail=vector(b"\xff")),
                    mqtt(tail=b"unexpected"), mqtt(flags=0x82),
                    b"\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\xff\xff"]
        for data in invalid:
            self.assertEqual(self.inspect(data).observation.status, "malformed", data)
        self.assertEqual(self.inspect(mqtt(client=b"")).observation.status, "identified")
        self.assertEqual(self.inspect(mqtt(level=6, tail=b"\x00")).observation.status, "unknown")

    def test_mqtt_length_bound_and_no_allocation_from_advertised_size(self):
        for data in (b"\x10\xff\xff\xff\x7f", b"\x10\x80\x01"):
            self.assertEqual(self.inspect(data, Config(max_bytes=64)).observation.status, "budget_exhausted")
        for data in (b"\x10\xff\xff\xff\x80", b"\x10\x8c\x00", b"\x10\x0b"):
            self.assertEqual(self.inspect(data).observation.status, "malformed")

    def test_resp_binary_arguments_and_empty_argument(self):
        data = resp(b"MODULE.CMD", b"", b"\x00\xff\r\n$42\r\n", b"secret-password")
        inspector = Inspector()
        for byte in data:
            inspector.feed(bytes([byte]))
        self.assertEqual(inspector.observation.application_protocol, "resp")
        self.assertIsNone(inspector.observation.application)
        self.assertNotIn("secret-password", repr(inspector.observation))
        self.assertEqual(inspector.metrics.bytes_inspected, len(data))

    def test_resp_arguments_not_buffered(self):
        parser = RESPParser(Config())
        header = b"*2\r\n$3\r\nSET\r\n$10000\r\n"
        parser.feed(header)
        parser.feed(b"x" * 9999)
        self.assertEqual(parser.command, b"")
        self.assertEqual(parser.line, b"")
        self.assertEqual(parser.remaining_bytes, 1)
        self.assertFalse(parser.done)
        parser.feed(b"x\r\n")
        self.assertTrue(parser.done)

    def test_resp_invalid_and_unsupported_requests(self):
        for data in (b"*0\r\n", b"*1\r\n$-1\r\n", b"*1\r\n+PING\r\n",
                     b"*1\r\n$4\r\nPING\rX", b"*1\r\n$4\r\nPINGX\n",
                     b"*1\r\n$4\nPING\r\n", b"*1\r\n$+4\r\nPING\r\n"):
            self.assertEqual(self.inspect(data).observation.status, "malformed", data)
        for data in (resp(b""), resp(b"\x00secret"), resp(b"A" * 129)):
            self.assertEqual(self.inspect(data).observation.status, "unknown")
        for data in (b"+PONG\r\n", b"PING\r\n", b"*-1\r\n"):
            self.assertNotEqual(self.inspect(data).observation.status, "identified")

    def test_resp_budgets(self):
        for data in (b"*1025\r\n", b"*1\r\n$9999999999999999999\r\n", b"*1\r\n$" + b"9" * 24):
            self.assertEqual(self.inspect(data).observation.status, "budget_exhausted", data)
        self.assertEqual(self.inspect(resp(b"ECHO", b"x" * 100), Config(max_bytes=64)).observation.status, "budget_exhausted")

    def test_amqp_scope_and_unknown_version(self):
        for data in (AMQP_091, AMQP_10):
            result = self.inspect(data).observation
            self.assertEqual(result.scope, "protocol_header")
            self.assertIsNone(result.application)
        self.assertEqual(self.inspect(b"AMQP\x00\x09\x09\x09").observation.status, "unknown")

    def test_http_method_collisions_all_splits(self):
        for method in (b"AMQP", b"AMQP0", b"AM", b"*", b"*12", b"*" + b"1" * 40, b"PRI", b"POST"):
            data = method + b" / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            for split in range(len(data) + 1):
                inspector = Inspector()
                inspector.feed(data[:split])
                inspector.feed(data[split:])
                self.assertEqual(inspector.observation.application_protocol, "http/1.1", (method, split))

    def test_full_initial_messages_use_single_parser_call(self):
        for data in (HTTP2, SOCKS5, MQTT, RESP, AMQP_10, client_hello(),
                     b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", b"EHLO example.com\r\n"):
            inspector = self.inspect(data)
            self.assertEqual(inspector.observation.status, "identified")
            self.assertEqual(inspector.metrics.parser_calls, 1)

    def test_terminal_bypass_and_exact_first_message_boundary(self):
        for data, _ in CASES:
            inspector = self.inspect(data + b"uninspected next message" * 100)
            self.assertEqual(inspector.metrics.bytes_inspected, len(data))
            calls = inspector.metrics.parser_calls
            self.assertEqual(inspector.feed(b"more" * 10000), ())
            self.assertEqual(inspector.metrics.parser_calls, calls)

    def test_new_protocols_inside_decrypted_tls(self):
        for data, protocol in CASES:
            inspector = self.inspect(client_hello())
            inspector.feed_decrypted(data)
            self.assertEqual(inspector.observation.encryption, "tls")
            self.assertEqual(inspector.observation.application_protocol, protocol)
            self.assertTrue(any(e.field == "application_protocol" and e.source == "decrypted"
                                for e in inspector.observation.evidence))

    def test_reordering_and_legacy_adapter(self):
        for data, protocol in CASES:
            manager = SessionManager()
            a, b = ("192.0.2.1", 50123), ("192.0.2.2", 54321)
            manager.open_connection(a, b, 100, 200)
            manager.feed(a, b, 104, data[4:])
            snapshot = manager.feed(a, b, 100, data[:4])
            self.assertEqual(snapshot.classification.application_protocol, protocol)
            self.assertEqual(sum(r.status == "MATCH" for r in snapshot.results), 1)

    def test_packet_decode_analyzer_integration(self):
        from analyze_pcap import Analyzer
        from make_sample_pcap import A, B, frame
        from packets import decode_tcp
        for payload, name in CASES:
            analyzer = Analyzer()
            frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18),
                      frame(A, B, 1004, 9000, 24, payload[4:]),
                      frame(A, B, 1000, 9000, 24, payload[:4])]
            for timestamp, packet in enumerate(frames):
                analyzer.process(timestamp, decode_tcp(packet))
            self.assertEqual(analyzer.last_classification.application_protocol, name)

    def test_dispatch_is_bounded_for_all_first_bytes(self):
        for byte in range(256):
            self.assertIsNotNone(select(bytes([byte]) * LOOKAHEAD))
        for data in (b"P", b"AMQP", b"*123\r"):
            inspector = self.inspect(data)
            self.assertLessEqual(len(inspector._prefix), LOOKAHEAD)
            self.assertEqual(inspector.metrics.parser_calls, 0)

    def test_seeded_mutations_fragmentation_equivalence_and_bounds(self):
        rng = random.Random(9833)
        for base, _ in CASES:
            for _ in range(300):
                changed = bytearray(base)
                changed[rng.randrange(len(changed))] = rng.randrange(256)
                data = bytes(changed)
                whole = self.inspect(data)
                split = Inspector()
                step = rng.randrange(1, 8)
                for pos in range(0, len(data), step):
                    split.feed(data[pos:pos + step])
                whole.end()
                split.end()
                self.assertEqual(split.observation, whole.observation, data)
                self.assertLessEqual(split.metrics.bytes_inspected, len(data))
                self.assertLessEqual(split.metrics.candidates_selected, 1)


if __name__ == "__main__":
    unittest.main()
