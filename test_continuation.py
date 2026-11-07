"""D07: optional budgeted continuation after an HTTP/1 or TLS identification (one vertical slice)."""
import json
import unittest

from protocol_adapters.analyze_pcap import Analyzer
from protocol_adapters.link_packets import decode_frame
from protocol_adapters.make_sample_pcap import frame
from protocol_adapters.protocol_fixtures import (LEAF_CERTIFICATE, TLS_SERVER12, TLS_SERVER13, certificate_message, client_hello_with,
                                                 tls_record)
from protocol_engine import Config, Inspector
from protocol_engine.continuation import continuation_summary
from tools import schema_check

CLIENT, SERVER = ("192.0.2.10", 52000), ("198.51.100.20", 80)
GET = b"GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n"
POST = b"POST /b HTTP/1.1\r\nHost: b.example\r\nContent-Length: 5\r\n\r\nhello"
CONNECT = b"CONNECT x.example:443 HTTP/1.1\r\nHost: x.example:443\r\n\r\n"
OK_EMPTY = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
CHUNKED = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n3;ext=1\r\nabc\r\n0\r\nX-Trailer: 1\r\n\r\n"
NOT_FOUND = b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno"
CLOSE_DELIMITED = b"HTTP/1.0 200 OK\r\n\r\nbody until close"
APP_DATA = b"\x17\x03\x03\x00\x10" + bytes(16)
CCS = b"\x14\x03\x03\x00\x01\x01"
ALERT = b"\x15\x03\x03\x00\x02\x01\x00"


def client_hello(name):
    entry = b"\x00" + len(name).to_bytes(2, "big") + name.encode("ascii")
    return client_hello_with([(0, len(entry).to_bytes(2, "big") + entry)])


def run(chunks, end=True, **options):
    inspector = Inspector(Config(**options))
    events = []
    for chunk in chunks:
        events.extend(inspector.feed(chunk))
    if end:
        events.extend(inspector.end("fin"))
    return inspector, events


def fields(observation):
    return {e.field: e.value for e in observation.evidence if e.source.endswith(":continuation")}


class DefaultPathTests(unittest.TestCase):
    def test_default_configuration_stops_at_the_first_message(self):
        inspector, events = run([GET, POST, CONNECT])
        self.assertEqual([e.kind for e in events], ["updated"])
        self.assertEqual(fields(inspector.observation), {})
        self.assertEqual(inspector.metrics.bytes_inspected, len(GET))   # later bytes are never parsed
        self.assertEqual(Config().continuation, 0)

    def test_limits_are_validated(self):
        with self.assertRaises(ValueError):
            Config(continuation=-1)
        with self.assertRaises(ValueError):
            Config(continuation=2 ** 21)
        with self.assertRaises(ValueError):
            Config(max_transactions=0)
        with self.assertRaises(ValueError):
            Config(continuation=True)


class HttpContinuationTests(unittest.TestCase):
    def test_later_requests_add_counts_without_changing_identity(self):
        inspector, events = run([GET, POST, POST[:7], POST[7:]], continuation=4096)
        self.assertEqual([e.kind for e in events], ["updated", "refined"])
        first, refined = events[0].observation, events[1].observation
        self.assertEqual((first.hostname, first.application_protocol), ("a.example", "http/1.1"))
        self.assertEqual((refined.hostname, refined.application_protocol, refined.status), ("a.example", "http/1.1", "identified"))
        self.assertEqual(fields(refined), {"http_messages": "3", "http_methods": "POST", "http_host_variation": "observed"})
        kept = [(e.field, e.value) for e in refined.evidence if not e.source.endswith(":continuation")]
        self.assertEqual(kept, [(e.field, e.value) for e in first.evidence])      # identification evidence preserved verbatim
        self.assertEqual(inspector.metrics.bytes_inspected, len(GET) + 2 * len(POST))

    def test_budget_ends_the_continuation_and_charges_nothing_beyond_it(self):
        inspector, events = run([GET, POST, POST], continuation=10)
        self.assertEqual(fields(events[-1].observation), {"http_messages": "1", "continuation": "budget"})
        self.assertEqual(inspector.metrics.bytes_inspected, len(GET) + 10)
        self.assertEqual(events[-1].kind, "refined")

    def test_message_cap(self):
        inspector, events = run([GET] + [POST] * 5, continuation=65536, max_transactions=3)
        self.assertEqual(fields(events[-1].observation), {"http_messages": "3", "http_methods": "POST",
                                                          "http_host_variation": "observed", "continuation": "messages"})

    def test_bodies_are_skipped_by_declared_framing(self):
        inspector, events = run([CHUNKED[:20], CHUNKED[20:] + NOT_FOUND + OK_EMPTY, CLOSE_DELIMITED], continuation=4096)
        summary = fields(events[-1].observation)
        self.assertEqual(summary, {"http_messages": "4", "http_status_classes": "4xx,2xx", "continuation": "close-delimited"})
        self.assertEqual(events[-1].observation.evidence[0].value, "http/1.1")   # the identification stays the first message
        # Bytes after a close-delimited body are never parsed as messages.
        self.assertNotIn("GET", summary.get("http_methods", ""))

    def test_large_declared_body_consumes_budget_then_ends(self):
        big = b"POST /u HTTP/1.1\r\nHost: a.example\r\nContent-Length: 1000000\r\n\r\n"
        inspector, events = run([GET, big, bytes(300), bytes(300)], continuation=400)
        self.assertEqual(fields(events[-1].observation)["continuation"], "budget")
        self.assertEqual(inspector.metrics.bytes_inspected, len(GET) + 400)

    def test_framing_error_keeps_the_identification(self):
        inspector, events = run([GET, b"\x16\x03\x01garbage\r\n\r\n", POST], continuation=4096)
        last = events[-1].observation
        self.assertEqual((last.status, last.hostname), ("identified", "a.example"))
        self.assertEqual(fields(last), {"http_messages": "1", "continuation": "framing"})
        self.assertEqual(inspector.metrics.bytes_inspected, len(GET) + len(b"\x16\x03\x01garbage\r\n\r\n"))

    def test_header_budget_inside_a_later_message_ends_the_continuation(self):
        many = b"GET /h HTTP/1.1\r\nHost: a.example\r\n" + b"X: 1\r\n" * 200 + b"\r\n"
        inspector, events = run([GET, many], continuation=65536, max_headers=16)
        self.assertEqual(fields(events[-1].observation)["continuation"], "framing")
        self.assertEqual(events[-1].observation.status, "identified")

    def test_later_connect_shifts_with_outer_evidence_preserved(self):
        hello = client_hello("inner.example")
        inspector, events = run([GET, CONNECT + hello[:20], hello[20:]], continuation=4096)
        self.assertEqual([e.kind for e in events], ["updated", "updated", "shifted"])
        carrier = events[1].observation                 # republished carrier identification at the boundary
        self.assertEqual((carrier.hostname, carrier.application_protocol), ("a.example", "http/1.1"))
        self.assertEqual(fields(carrier), {"http_messages": "2", "http_methods": "CONNECT", "http_host_variation": "observed",
                                           "continuation": "shift"})
        shifted = events[-1].observation                # the tunnel payload was inspected as a fresh phase (v0.28 semantics)
        values = {e.field: e.value for e in shifted.evidence}
        self.assertEqual((shifted.encryption, shifted.hostname), ("tls", "inner.example"))
        self.assertEqual((values["shift"], values["shift_from"]), ("http-connect", "http/1.1"))
        # Same merged shape as a first-message CONNECT: the continuation changes nothing after the boundary.
        plain, plain_events = run([CONNECT, hello])
        self.assertEqual(plain_events[-1].observation.evidence, shifted.evidence)

    def test_stream_end_during_continuation_publishes_what_was_framed(self):
        inspector, events = run([GET, POST, b"GET /partial HTTP/1.1\r\n"], continuation=4096)
        self.assertEqual(events[-1].kind, "refined")
        self.assertEqual(fields(events[-1].observation), {"http_messages": "2", "http_methods": "POST", "http_host_variation": "observed"})

    def test_first_message_with_a_shift_never_starts_a_continuation(self):
        inspector, events = run([CONNECT, client_hello("t.example")], continuation=4096)
        self.assertEqual(events[-1].kind, "shifted")
        self.assertNotIn("http_messages", {e.field for e in events[-1].observation.evidence})

    def test_response_direction_counts_status_classes(self):
        inspector, events = run([OK_EMPTY, NOT_FOUND, OK_EMPTY], continuation=4096)
        self.assertEqual(fields(events[-1].observation), {"http_messages": "3", "http_status_classes": "4xx,2xx"})


class TlsContinuationTests(unittest.TestCase):
    def test_records_after_the_client_hello_are_counted_not_read(self):
        hello = client_hello("a.example")
        inspector, events = run([hello, CCS + APP_DATA[:7], APP_DATA[7:] + APP_DATA, ALERT], continuation=4096)
        last = events[-1].observation
        self.assertEqual((last.encryption, last.hostname, last.status), ("tls", "a.example", "identified"))
        self.assertEqual(fields(last), {"tls_records": "ccs=1,alert=1,application_data=2",
                                        "tls_application_data": "observed", "tls_alert": "observed"})
        self.assertEqual(events[-1].kind, "refined")

    def test_bad_record_header_ends_with_framing(self):
        inspector, events = run([client_hello("a.example"), b"\x99\x03\x03\x00\x01x" + APP_DATA], continuation=4096)
        self.assertEqual(fields(events[-1].observation), {"continuation": "framing"})
        self.assertEqual(events[-1].observation.hostname, "a.example")

    def test_budget_bounds_record_framing(self):
        inspector, events = run([client_hello("a.example"), APP_DATA * 10], continuation=50)
        summary = fields(events[-1].observation)
        self.assertEqual(summary["continuation"], "budget")
        self.assertEqual(summary["tls_records"], "application_data=3")       # 50 bytes frame two full records and a third header
        self.assertEqual(inspector.metrics.bytes_inspected, len(client_hello("a.example")) + 50)

    def test_server_hello_13_then_protected_records(self):
        inspector, events = run([TLS_SERVER13, CCS, APP_DATA, APP_DATA], continuation=4096)
        self.assertEqual(fields(events[-1].observation), {"tls_records": "ccs=1,application_data=2", "tls_application_data": "observed"})

    def test_certificate_watch_chains_into_record_framing(self):
        flight = TLS_SERVER12 + tls_record(certificate_message(LEAF_CERTIFICATE))
        inspector, events = run([flight, tls_record(b"\x0e\x00\x00\x00"), CCS, APP_DATA], continuation=4096, certificates=True)
        values = {e.field: e.value for e in events[-1].observation.evidence}
        self.assertIn("tls_certificate_key", values)                      # the certificate evidence is kept
        self.assertEqual(values["tls_records"], "handshake=1,ccs=1,application_data=1")
        without, _ = run([flight, tls_record(b"\x0e\x00\x00\x00"), CCS, APP_DATA], certificates=True)
        self.assertNotIn("tls_records", {e.field for e in without.observation.evidence})


class AnalyzerTests(unittest.TestCase):
    def analyzer(self, **options):
        records = []
        return Analyzer(on_session=records.append, idle_timeout=1000, **options), records

    def feed(self, an, when, source, destination, seq, ack, flags, payload=b""):
        return an.process(when, decode_frame(frame(source, destination, seq, ack, flags, payload), 1))

    def connection(self, an, client_messages, server_messages=()):
        self.feed(an, 0.0, CLIENT, SERVER, 999, 0, 2)
        self.feed(an, 0.1, SERVER, CLIENT, 8999, 1000, 18)
        self.feed(an, 0.2, CLIENT, SERVER, 1000, 9000, 16)
        seq, when = 1000, 0.3
        for message in client_messages:
            self.feed(an, when, CLIENT, SERVER, seq, 9000, 24, message)
            seq += len(message)
            when += 0.1
        sseq = 9000
        for message in server_messages:
            self.feed(an, when, SERVER, CLIENT, sseq, seq, 24, message)
            sseq += len(message)
            when += 0.1
        an.finish("eof")

    def test_session_record_carries_a_per_direction_summary(self):
        an, records = self.analyzer(continuation=4096)
        self.connection(an, [GET, POST, POST], [OK_EMPTY, NOT_FOUND])
        record = records[0]
        self.assertEqual((record["app"], record["client_protocol"], record["server_protocol"]), ("web-browsing", "http/1.1", "http/1.1"))
        self.assertEqual(record["continuation"], {"client": {"http_messages": 3, "http_methods": "POST", "http_host_variation": "observed"},
                                                  "server": {"http_messages": 2, "http_status_classes": "4xx"}})   # the first 200 is http_status
        self.assertEqual(record["decision"]["stable_seconds"], 0.3)        # later messages do not move the decision
        self.assertEqual(schema_check.validate(json.loads(json.dumps(record)), schema_check.load("session")), [])

    def test_default_analyzer_has_no_summary(self):
        an, records = self.analyzer()
        self.connection(an, [GET, POST], [OK_EMPTY])
        self.assertNotIn("continuation", records[0])
        self.assertEqual(schema_check.validate(json.loads(json.dumps(records[0])), schema_check.load("session")), [])

    def test_summary_helper(self):
        inspector, _ = run([GET, POST], continuation=4096)
        self.assertEqual(continuation_summary(inspector.observation, None),
                         {"client": {"http_messages": 2, "http_methods": "POST", "http_host_variation": "observed"}})
        self.assertEqual(continuation_summary(None, None), {})


if __name__ == "__main__":
    unittest.main()
