"""D12: structured reasons for non-identifications and the minimized-example workflow."""
import json
import struct
import unittest

from protocol_adapters.analyze_pcap import Analyzer
from protocol_adapters.link_packets import decode_frame
from protocol_adapters.make_sample_pcap import frame, udp_frame
from protocol_engine import Config, DatagramInspector, Inspector
from protocol_engine.unknown import CODES, STAGES, explain
from tools import minimize_example, schema_check

CLIENT, SERVER = ("192.0.2.10", 52000), ("198.51.100.20", 8000)
BAD_HEADER = b"GET / HTTP/1.1\r\nHost: a.example\r\nBad Header\r\n\r\n"
NOISE = bytes(range(200, 256)) * 3


def tcp_session(payloads, server_payload=b"", **options):
    records = []
    an = Analyzer(on_session=records.append, idle_timeout=1000, **options)

    def feed(when, source, destination, seq, ack, flags, data=b""):
        an.process(when, decode_frame(frame(source, destination, seq, ack, flags, data), 1))
    feed(0.0, CLIENT, SERVER, 999, 0, 2)
    feed(0.1, SERVER, CLIENT, 8999, 1000, 18)
    feed(0.2, CLIENT, SERVER, 1000, 9000, 16)
    seq = 1000
    for payload in payloads:
        feed(0.3, CLIENT, SERVER, seq, 9000, 24, payload)
        seq += len(payload)
    if server_payload:
        feed(0.4, SERVER, CLIENT, 9000, seq, 24, server_payload)
    an.finish("eof")
    return records[0]


class VocabularyTests(unittest.TestCase):
    def test_codes_and_stages_are_closed(self):
        self.assertEqual(set(STAGES), set(CODES))
        self.assertEqual(set(STAGES.values()), {"dispatch", "profile", "budget", "lifecycle", "integrity"})

    def test_identification_has_no_structured_reason(self):
        inspector = Inspector()
        inspector.feed(b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
        self.assertIsNone(explain(inspector.observation, inspector=inspector))
        self.assertEqual(inspector.resolved_family, "http")

    def test_dispatch_profile_budget_and_lifecycle_codes(self):
        inspector = Inspector()
        inspector.feed(NOISE)
        self.assertEqual(explain(inspector.observation, inspector=inspector)["code"], "no-dispatch")
        self.assertIsNone(inspector.resolved_family)
        inspector = Inspector()
        inspector.feed(BAD_HEADER)
        item = explain(inspector.observation, inspector=inspector)
        self.assertEqual((item["code"], item["stage"], item["family"], item["detail"]), ("malformed", "profile", "http", "Invalid header name"))
        inspector = Inspector()
        inspector.feed(b"\x80\xf0" + bytes(22))                                     # memcached binary, opcode outside the profile
        item = explain(inspector.observation, inspector=inspector)
        self.assertEqual((item["code"], item["family"]), ("profile-unsupported", "memcached"))
        inspector = Inspector(protocol_hint="rfb")
        inspector.feed(b"RFB 009.009\n")                                             # hinted family, banner outside the profile
        item = explain(inspector.observation, inspector=inspector)
        self.assertEqual((item["code"], item["family"]), ("profile-unsupported", "rfb"))
        inspector = Inspector()
        inspector.feed(struct.pack("!II", 8, (3 << 16) | 2))                        # selected, then structurally wrong
        self.assertEqual(explain(inspector.observation, inspector=inspector)["family"], "postgresql")
        inspector = Inspector(Config(max_bytes=64))
        inspector.feed(b"GET /" + b"a" * 100)                                       # budget before the text route resolved a family
        item = explain(inspector.observation, inspector=inspector)
        self.assertEqual((item["code"], item["stage"], item["family"]), ("budget", "budget", None))
        inspector = Inspector(Config(max_bytes=64))
        inspector.feed(b"GET / HTTP/1.1\r\nX: " + b"a" * 100)                      # the route resolved to http, then the budget ended it
        item = explain(inspector.observation, inspector=inspector)
        self.assertEqual((item["code"], item["family"]), ("budget", "http"))
        inspector = Inspector()
        self.assertEqual(explain(inspector.observation, inspector=inspector)["code"], "no-payload")
        inspector.feed(b"GET / HTTP/1.1\r\n")
        inspector.end("Idle timeout before initial message completed")
        item = explain(inspector.observation, inspector=inspector)
        self.assertEqual((item["code"], item["detail"]), ("incomplete", "Idle timeout before initial message completed"))
        inspector = Inspector()
        inspector.feed(b"USER alice\r\n")
        item = explain(inspector.observation, inspector=inspector)
        self.assertEqual((item["code"], item["candidates"]), ("ambiguous", ["ftp", "pop3"]))
        inspector = Inspector()
        inspector.feed(b"GET / HTTP/1.1\r\n")
        inspector.invalidate("Conflicting overlapping bytes; classification invalidated")
        self.assertEqual(explain(inspector.observation, inspector=inspector)["code"], "invalidated")

    def test_datagram_codes(self):
        self.assertEqual(explain(DatagramInspector().inspect(bytes(range(1, 60))))["code"], "no-dispatch")
        inspector = Inspector()
        self.assertEqual(explain(Inspector().observation)["code"], "no-payload")   # no inspector: the initial observation
        del inspector


class RecordTests(unittest.TestCase):
    def test_session_records_carry_per_direction_reasons(self):
        record = tcp_session([BAD_HEADER])
        self.assertEqual(record["engine_status"], "malformed")
        self.assertEqual(record["unknown"]["client"]["code"], "malformed")
        self.assertEqual(record["unknown"]["client"]["family"], "http")
        self.assertEqual(record["unknown"]["server"]["code"], "no-payload")
        self.assertEqual(schema_check.validate(json.loads(json.dumps(record)), schema_check.load("session")), [])
        record = tcp_session([b"USER alice\r\n"])
        self.assertEqual(record["unknown"]["client"]["candidates"], ["ftp", "pop3"])
        record = tcp_session([b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"])
        self.assertNotIn("unknown", record)
        record = tcp_session([])
        self.assertEqual((record["app"], record["unknown"]["client"]["code"]), ("incomplete", "no-payload"))

    def test_no_handshake_and_midstream_are_session_level(self):
        records = []
        an = Analyzer(on_session=records.append, idle_timeout=1000)
        an.process(0.0, decode_frame(frame(CLIENT, SERVER, 999, 0, 2), 1))
        an.finish("eof")
        self.assertEqual(records[0]["unknown"]["session"]["code"], "no-handshake")
        self.assertEqual(schema_check.validate(json.loads(json.dumps(records[0])), schema_check.load("session")), [])
        records = []
        an = Analyzer(on_session=records.append, idle_timeout=1000, observation="midstream")
        an.process(0.0, decode_frame(frame(CLIENT, SERVER, 5000, 7000, 24, b"\x17\x03\x03\x00\x10" + bytes(16)), 1))
        an.finish("eof")
        self.assertEqual(records[0]["unknown"]["session"]["code"], "midstream")
        self.assertEqual(records[0]["unknown"]["client"]["code"], "no-dispatch")

    def test_udp_record(self):
        records = []
        an = Analyzer(on_session=records.append, idle_timeout=1000)
        an.process(0.0, decode_frame(udp_frame(CLIENT, ("198.51.100.1", 9999), bytes(range(1, 60))), 1))
        an.finish("eof")
        self.assertEqual(records[0]["unknown"], {"client": {"code": "no-dispatch", "stage": "dispatch", "family": None,
                                                            "detail": "No supported datagram structure selected"}})
        self.assertEqual(schema_check.validate(json.loads(json.dumps(records[0])), schema_check.load("session")), [])


class MinimizerTests(unittest.TestCase):
    def test_minimized_example_keeps_the_signature(self):
        minimized, steps, target = minimize_example.minimize(BAD_HEADER)
        self.assertLess(len(minimized), len(BAD_HEADER))
        self.assertEqual(target[:3], ("malformed", "malformed", "http"))
        self.assertEqual(target[4], "Invalid header name")
        self.assertEqual(minimize_example.signature(*minimize_example.outcome(minimized)), target)
        loose, _, loose_target = minimize_example.minimize(BAD_HEADER, strict=False)
        self.assertLessEqual(len(loose), len(minimized))                 # dropping the sentence can only shrink further
        self.assertEqual(loose_target[:3], target[:3])
        noise, steps, target = minimize_example.minimize(NOISE)
        self.assertEqual((len(noise), target[1]), (1, "no-dispatch"))

    def test_report_and_cli(self):
        out = minimize_example.report(BAD_HEADER, "tcp", None, True)
        self.assertEqual(out["structured"]["code"], "malformed")
        self.assertIn("Inspector().feed(bytes.fromhex(", out["minimized"]["reproduce"])
        self.assertEqual(out["minimized"]["signature"]["detail"], "Invalid header name")
        identified = minimize_example.report(b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n", "tcp", None, False)
        self.assertIsNone(identified["structured"])
        self.assertEqual(identified["identification"]["protocol"], "http/1.1")
        self.assertEqual(minimize_example.main(["--hex", BAD_HEADER.hex(), "--minimize", "--json"]), 0)
        self.assertEqual(minimize_example.main(["--hex", bytes(range(1, 60)).hex(), "--udp"]), 0)
        with self.assertRaises(SystemExit):
            minimize_example.main(["--hex", "zz"])
        with self.assertRaises(SystemExit):
            minimize_example.main(["--hex", "00", "--hint", "nope"])

    def test_minimizer_is_bounded(self):
        minimized, steps, _ = minimize_example.minimize(NOISE * 50, max_steps=40)
        self.assertLessEqual(steps, 41)
        self.assertLess(len(minimized), len(NOISE) * 50)


if __name__ == "__main__":
    unittest.main()
