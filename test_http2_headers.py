"""HTTP/2 after the initial SETTINGS: frame preamble, HEADERS/CONTINUATION, HPACK-decoded evidence, budgets."""
import json
import random
import unittest

from analyze_pcap import Analyzer
from make_sample_pcap import A, B, frame
from packets import decode_packet
from protocol_engine import ApplicationRule, Config, Inspector, RuleIndex
from protocol_engine.appid import classify
from protocol_engine.extended import content_type_class
from protocol_engine.signatures import SignatureSet
from protocol_fixtures import (H2_GRPC, H2_PREFACE, H2_REQUEST, H2_RESPONSE, H2_SERVER_SETTINGS, H2_SETTINGS, H2_WINDOW_UPDATE,
                               H2C_101, HPACK_REQUEST, h2_frame, hpack_literal)

PREAMBLE = H2_PREFACE + H2_SETTINGS
REQUEST_FIELDS = {"http2_message": "request", "http2_method": "GET", "http2_scheme": "http", "hostname": "www.example.com"}


def block(*fields):
    """Header block of raw literals; (name, value) pairs, pseudo-headers first as given."""
    return b"".join(hpack_literal(name, value) for name, value in fields)


def request(*fields):
    return block((b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/"), (b":authority", b"www.example.com")) + block(*fields)


def values(observation):
    return {e.field: e.value for e in observation.evidence}


def inspect(data, config=None, hint=None, **kwargs):
    inspector = Inspector(config, protocol_hint=hint, **kwargs)
    events = inspector.feed(data)
    return inspector, events


class RequestHeadersTests(unittest.TestCase):
    def test_fixture_identifies_at_settings_then_refines_with_the_headers_block(self):
        inspector, events = inspect(H2_REQUEST)
        self.assertEqual([e.kind for e in events], ["updated", "refined"])
        first = events[0].observation
        self.assertEqual((first.status, first.application_protocol, first.scope, first.hostname), ("identified", "http/2", "initial_message", None))
        self.assertIn("no HEADERS frame decoded yet", first.reason)
        final = inspector.observation
        self.assertEqual((final.status, final.application_protocol, final.scope, final.hostname), ("identified", "http/2", "request_headers", "www.example.com"))
        fields = values(final)
        for field, value in REQUEST_FIELDS.items():
            self.assertEqual(fields[field], value, field)
        self.assertEqual({e.field: e.strength for e in final.evidence}["hostname"], "asserted")
        self.assertEqual({e.field: e.source for e in final.evidence}["hostname"], "wire:http_host")
        self.assertNotIn("http2_content_type", fields)
        self.assertIn("HPACK decoded", final.reason)
        self.assertEqual(inspector.metrics.bytes_inspected, len(H2_REQUEST))
        self.assertEqual(inspector.metrics.candidates_selected, 1)
        self.assertTrue(inspector._terminal)
        self.assertEqual(classify(final).app, "web-browsing")

    def test_every_split_point_and_single_byte_feeds_agree(self):
        for data, hint in ((H2_REQUEST, None), (H2_GRPC, None), (H2_RESPONSE, "http2-server")):
            expected = inspect(data, hint=hint)[0].observation
            self.assertEqual(expected.status, "identified")
            for split in range(len(data) + 1):
                inspector = Inspector(protocol_hint=hint)
                inspector.feed(data[:split])
                inspector.feed(data[split:])
                self.assertEqual(inspector.observation, expected, split)
                self.assertEqual(inspector.metrics.bytes_inspected, len(data))
            inspector = Inspector(protocol_hint=hint)
            for byte in data:
                inspector.feed(bytes([byte]))
            self.assertEqual(inspector.observation, expected)

    def test_truncated_headers_keep_the_settings_identification(self):
        for end in range(len(PREAMBLE), len(H2_REQUEST)):
            inspector, _ = inspect(H2_REQUEST[:end])
            self.assertEqual((inspector.observation.status, inspector.observation.scope), ("identified", "initial_message"), end)
            self.assertIsNone(inspector.observation.hostname)
            inspector.end()
            self.assertEqual((inspector.observation.status, inspector.observation.scope), ("identified", "initial_message"), end)
            self.assertTrue(inspector._terminal)

    def test_grpc_is_post_plus_grpc_content_type_over_validated_http2(self):
        inspector, _ = inspect(H2_GRPC)
        fields = values(inspector.observation)
        self.assertEqual((fields["http2_method"], fields["http2_scheme"], fields["http2_content_type"]), ("POST", "https", "grpc"))
        self.assertEqual({e.field: e.strength for e in inspector.observation.evidence}["http2_content_type"], "asserted")
        self.assertEqual(inspector.observation.hostname, "grpc.example")
        verdict = classify(inspector.observation)
        self.assertEqual((verdict.app, verdict.category, verdict.implicitly_uses), ("grpc", "business-systems", ("web-browsing",)))
        text = repr(inspector.observation)
        for secret in ("Greeter", "SayHello", "application/grpc", "trailers"):
            self.assertNotIn(secret, text)
        # GET with a grpc content-type is not a gRPC request; grpc-web content maps the same way.
        data = PREAMBLE + h2_frame(1, request((b"content-type", b"application/grpc")), flags=0x04, stream=1)
        self.assertEqual(classify(inspect(data)[0].observation).app, "web-browsing")
        data = PREAMBLE + h2_frame(1, block((b":method", b"POST"), (b":scheme", b"https"), (b":path", b"/svc"),
                                            (b"content-type", b"application/grpc-web+proto")), flags=0x04, stream=1)
        observation = inspect(data)[0].observation
        self.assertEqual((values(observation)["http2_content_type"], classify(observation).app), ("grpc-web", "grpc"))

    def test_content_type_classes(self):
        cases = (("application/grpc", "grpc"), ("application/grpc+proto", "grpc"), ("Application/GRPC; charset=x", "grpc"),
                 ("application/grpc-web-text", "grpc-web"), ("application/json", "json"), ("application/problem+json", "json"),
                 ("text/xml", "xml"), ("application/soap+xml", "soap"), ("application/rss+xml", "xml"), ("application/x-www-form-urlencoded", "form"),
                 ("multipart/form-data; boundary=abc", "multipart"), ("application/x-protobuf", "protobuf"),
                 ("application/octet-stream", "binary"), ("text/html; charset=utf-8", "text"), ("image/png", "other"), ("", "other"))
        for value, expected in cases:
            self.assertEqual(content_type_class(value.encode()), expected, value)

    def test_connect_and_extended_connect(self):
        data = PREAMBLE + h2_frame(1, block((b":method", b"CONNECT"), (b":authority", b"proxy.example:443")), flags=0x04, stream=1)
        observation = inspect(data)[0].observation
        self.assertEqual((values(observation)["http2_method"], observation.hostname, classify(observation).app), ("CONNECT", "proxy.example", "http-proxy"))
        self.assertNotIn("http2_scheme", values(observation))
        websocket = block((b":method", b"CONNECT"), (b":protocol", b"websocket"), (b":scheme", b"https"), (b":path", b"/chat"), (b":authority", b"ws.example"))
        observation = inspect(PREAMBLE + h2_frame(1, websocket, flags=0x04, stream=1))[0].observation
        self.assertEqual((values(observation)["http2_protocol"], classify(observation).app), ("websocket", "websocket"))
        other = block((b":method", b"CONNECT"), (b":protocol", b"webtransport"), (b":scheme", b"https"), (b":path", b"/"), (b":authority", b"ws.example"))
        self.assertEqual(values(inspect(PREAMBLE + h2_frame(1, other, flags=0x04, stream=1))[0].observation)["http2_protocol"], "other")
        # CONNECT with :scheme, :protocol without CONNECT, extension methods.
        grpc_bad_authority = block((b":method", b"POST"), (b":scheme", b"https"), (b":path", b"/svc"), (b":authority", b"[not-an-ip]:999999"),
                                   (b"content-type", b"application/grpc"))
        observation = inspect(PREAMBLE + h2_frame(1, grpc_bad_authority, flags=0x04, stream=1))[0].observation
        self.assertEqual((observation.scope, observation.hostname, classify(observation).app), ("initial_message", None, "web-browsing"))
        self.assertNotIn("http2_content_type", values(observation))
        for bad in (block((b":method", b"CONNECT"), (b":scheme", b"https"), (b":authority", b"a.example")),
                    block((b":method", b"GET"), (b":protocol", b"websocket"), (b":scheme", b"https"), (b":path", b"/"), (b":authority", b"a.example")),
                    block((b":method", b"CONNECT"))):
            observation = inspect(PREAMBLE + h2_frame(1, bad, flags=0x04, stream=1))[0].observation
            self.assertEqual((observation.status, observation.scope), ("identified", "initial_message"))
            self.assertNotIn("http2_method", values(observation))
        extension = block((b":method", b"BREW"), (b":scheme", b"https"), (b":path", b"/"), (b":authority", b"a.example"))
        self.assertEqual(values(inspect(PREAMBLE + h2_frame(1, extension, flags=0x04, stream=1))[0].observation)["http2_method"], "extension")
        webdav = block((b":method", b"PROPFIND"), (b":scheme", b"https"), (b":path", b"/dav/"), (b":authority", b"a.example"))
        observation = inspect(PREAMBLE + h2_frame(1, webdav, flags=0x04, stream=1))[0].observation
        self.assertEqual((values(observation)["http2_method"], classify(observation).app), ("PROPFIND", "webdav"))

    def test_authority_forms(self):
        cases = ((b"www.example.com:8443", "www.example.com"), (b"WWW.Example.COM.", "www.example.com"), (b"192.0.2.1", None),
                 (b"192.0.2.1:8080", None), (b"[2001:db8::1]", None), (b"[2001:db8::1]:443", None), (b"xn--bcher-kva.example", "xn--bcher-kva.example"))
        for authority, expected in cases:
            data = PREAMBLE + h2_frame(1, block((b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/"), (b":authority", authority)), flags=0x04, stream=1)
            observation = inspect(data)[0].observation
            self.assertEqual((observation.hostname, values(observation).get("http2_method")), (expected, "GET"), authority)
        for authority in (b"user@www.example.com", b"www.example.com:", b"www.example.com:99999", b"www.example.com:4a3", b"", b"b\xfccher.example",
                          b"[2001:db8::1", b"[2001:db8::1]x", b"-bad-.example", b"a..b",
                          # review round 1: bracket contents must be an IPv6 literal and the port obeys the same rules
                          b"[not-an-ip]:999999", b"[not-an-ip]", b"[2001:db8::1]:999999", b"[2001:db8::1]:0", b"[2001:db8::1]:", b"[]", b"www.example.com:0"):
            data = PREAMBLE + h2_frame(1, block((b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/"), (b":authority", authority)), flags=0x04, stream=1)
            observation = inspect(data)[0].observation
            self.assertEqual((observation.status, observation.hostname), ("identified", None), authority)
            self.assertNotIn("http2_method", values(observation), authority)
        # Without :authority there is no hostname; a configured mapping on the authority host names an application.
        data = PREAMBLE + h2_frame(1, block((b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/")), flags=0x04, stream=1)
        self.assertIsNone(inspect(data)[0].observation.hostname)
        rules = RuleIndex((ApplicationRule("www.example.com", "example-portal", "http_host"),))
        observation = inspect(H2_REQUEST, rules=rules)[0].observation
        self.assertEqual(observation.application, "example-portal")
        self.assertEqual({e.field: e.source for e in observation.evidence}["application"], "http_host:exact_rule")
        self.assertEqual(classify(observation).app, "example-portal")

    def test_preamble_frames_before_headers(self):
        ack = h2_frame(4, b"", flags=0x01)
        ping = h2_frame(6, bytes(8))
        priority = h2_frame(2, b"\x00\x00\x00\x00\x10", stream=3)
        headers = h2_frame(1, HPACK_REQUEST, flags=0x05, stream=1)
        for preamble in (ack, ping, priority, H2_WINDOW_UPDATE, H2_SETTINGS, ack + ping + priority + H2_WINDOW_UPDATE + H2_SETTINGS + ack):
            observation = inspect(PREAMBLE + preamble + headers)[0].observation
            self.assertEqual(observation.hostname, "www.example.com", preamble)
        # Nine frames before HEADERS exceed the budget; the identification stands without header evidence.
        observation = inspect(PREAMBLE + ping * 9 + headers)[0].observation
        self.assertEqual((observation.status, observation.scope, observation.hostname), ("identified", "initial_message", None))
        self.assertEqual(inspect(PREAMBLE + ping * 8 + headers)[0].observation.hostname, "www.example.com")
        # Frames outside the profile end the watch quietly: DATA, RST_STREAM, PUSH_PROMISE, GOAWAY, unknown types.
        for kind in (0, 3, 5, 7, 10, 255):
            inspector, _ = inspect(PREAMBLE + h2_frame(kind, bytes(4), stream=1) + headers)
            self.assertEqual((inspector.observation.status, inspector.observation.hostname), ("identified", None), kind)
            self.assertTrue(inspector._terminal)
        # Malformed preamble frames also leave the identification as it was.
        for bad in (h2_frame(4, b"", flags=0x01, stream=1), h2_frame(4, b"\x00", flags=0x01), h2_frame(4, b"\x00\x02\x00\x00\x00\x05"),
                    h2_frame(8, bytes(4)), h2_frame(8, bytes(3)), h2_frame(2, bytes(5)), h2_frame(2, b"\x00\x00\x00\x03\x10", stream=3),
                    h2_frame(6, bytes(7)), h2_frame(6, bytes(8), stream=1)):
            observation = inspect(PREAMBLE + bad + headers)[0].observation
            self.assertEqual((observation.status, observation.scope), ("identified", "initial_message"), bad)

    def test_continuation_padding_and_priority(self):
        fragments = (HPACK_REQUEST[:4], HPACK_REQUEST[4:9], HPACK_REQUEST[9:])
        data = PREAMBLE + h2_frame(1, fragments[0], flags=0x01, stream=1) + h2_frame(9, fragments[1], stream=1) + h2_frame(9, fragments[2], flags=0x04, stream=1)
        self.assertEqual(values(inspect(data)[0].observation)["hostname"], "www.example.com")
        padded = h2_frame(1, b"\x03" + HPACK_REQUEST + bytes(3), flags=0x0c, stream=1)
        prioritised = h2_frame(1, b"\x80\x00\x00\x03\x20" + HPACK_REQUEST, flags=0x24, stream=1)
        both = h2_frame(1, b"\x02\x00\x00\x00\x03\x10" + HPACK_REQUEST + bytes(2), flags=0x2c, stream=1)
        for headers in (padded, prioritised, both):
            self.assertEqual(inspect(PREAMBLE + headers)[0].observation.hostname, "www.example.com")
        for bad in (h2_frame(1, b"\x20" + HPACK_REQUEST, flags=0x0c, stream=1),                      # padding beyond the frame
                    h2_frame(1, b"", flags=0x0c, stream=1),                                           # padded without pad length
                    h2_frame(1, b"\x00\x00\x00\x01\x10" + HPACK_REQUEST, flags=0x24, stream=1),       # depends on itself
                    h2_frame(1, b"\x00\x00", flags=0x24, stream=1),                                   # truncated priority
                    h2_frame(1, HPACK_REQUEST, flags=0x05, stream=2),                                 # server-initiated stream
                    h2_frame(1, HPACK_REQUEST, flags=0x05, stream=0),
                    h2_frame(1, HPACK_REQUEST, flags=0x45, stream=1),                                 # unknown flag
                    h2_frame(1, fragments[0], flags=0x01, stream=1) + H2_WINDOW_UPDATE,               # interrupted block
                    h2_frame(1, fragments[0], flags=0x01, stream=1) + h2_frame(9, fragments[1] + fragments[2], flags=0x04, stream=3),
                    h2_frame(1, fragments[0], flags=0x01, stream=1) + h2_frame(9, b"", stream=1) * 8,
                    h2_frame(9, HPACK_REQUEST, flags=0x04, stream=1)):                                # CONTINUATION without HEADERS
            observation = inspect(PREAMBLE + bad)[0].observation
            self.assertEqual((observation.status, observation.scope, observation.hostname), ("identified", "initial_message", None), bad)
        data = PREAMBLE + h2_frame(1, fragments[0], flags=0x01, stream=1) + h2_frame(9, b"", stream=1) * 6 + h2_frame(9, fragments[1] + fragments[2], flags=0x04, stream=1)
        self.assertEqual(inspect(data)[0].observation.hostname, "www.example.com")

    def test_header_list_validation(self):
        bad_blocks = (
            request((b"Content-Type", b"text/html")),                               # uppercase name
            block((b":method", b"GET"), (b"x", b"y"), (b":scheme", b"https"), (b":path", b"/")),   # pseudo after regular
            block((b":method", b"GET"), (b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/")),
            block((b":status", b"200"), (b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/")),
            block((b":unknown", b"1"), (b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/")),
            block((b":scheme", b"https"), (b":path", b"/")),                                       # missing method
            block((b":method", b"GET"), (b":path", b"/")),                                         # missing scheme
            block((b":method", b"GET"), (b":scheme", b"https"), (b":path", b"")),                 # empty path
            block((b":method", b"G ET"), (b":scheme", b"https"), (b":path", b"/")),
            block((b":method", b"X" * 33), (b":scheme", b"https"), (b":path", b"/")),
            request((b"connection", b"keep-alive")), request((b"transfer-encoding", b"chunked")), request((b"upgrade", b"h2c")),
            request((b"te", b"gzip")), request((b"x-a", b"line\r\nbreak")), request((b"x-a", b"nul\x00")),
            request((b"x-a", b" padded")), request((b"x-a", b"padded\t")), request((b"", b"empty-name")),
            request((b"x a", b"space-in-name")),
            b"\x82\x86\x84\xbe",                                                                   # dynamic index without a table
        )
        for bad in bad_blocks:
            observation = inspect(PREAMBLE + h2_frame(1, bad, flags=0x04, stream=1))[0].observation
            self.assertEqual((observation.status, observation.scope, observation.hostname), ("identified", "initial_message", None), bad)
        good = request((b"te", b"trailers"), (b"x-empty", b""), (b"user-agent", b"demo/1.0"), (b"content-type", b"application/json"))
        observation = inspect(PREAMBLE + h2_frame(1, good, flags=0x04, stream=1))[0].observation
        self.assertEqual(values(observation)["http2_content_type"], "json")
        self.assertNotIn("demo/1.0", repr(observation))

    def test_budgets_bound_the_continuation(self):
        inspector, _ = inspect(H2_REQUEST, Config(max_bytes=64))
        self.assertEqual((inspector.observation.status, inspector.observation.scope), ("identified", "initial_message"))
        self.assertLessEqual(inspector.metrics.bytes_inspected, 64)
        self.assertEqual(inspect(H2_REQUEST, Config(max_bytes=len(H2_REQUEST)))[0].observation.hostname, "www.example.com")
        inspector, _ = inspect(H2_REQUEST, Config(max_bytes=len(H2_REQUEST) - 1))
        self.assertEqual((inspector.observation.status, inspector.observation.hostname), ("identified", None))
        self.assertLessEqual(inspector.metrics.bytes_inspected, len(H2_REQUEST) - 1)
        self.assertEqual(inspect(H2_REQUEST, Config(max_headers=4))[0].observation.hostname, "www.example.com")
        self.assertIsNone(inspect(H2_REQUEST, Config(max_headers=3))[0].observation.hostname)
        long_value = request((b"x-long", b"v" * 300))
        self.assertEqual(inspect(PREAMBLE + h2_frame(1, long_value, flags=0x04, stream=1), Config(max_line=299))[0].observation.hostname, None)
        self.assertEqual(inspect(PREAMBLE + h2_frame(1, long_value, flags=0x04, stream=1), Config(max_line=300))[0].observation.hostname, "www.example.com")
        huge = h2_frame(1, bytes(16385), flags=0x04, stream=1)
        inspector, _ = inspect(PREAMBLE + huge)
        self.assertEqual((inspector.observation.status, inspector.observation.scope), ("identified", "initial_message"))
        self.assertTrue(inspector._terminal)
        inspector = Inspector()
        inspector.feed(PREAMBLE + huge[:9])
        self.assertTrue(inspector._terminal)   # the frame header alone exceeds the header block budget
        self.assertEqual(inspector.metrics.bytes_inspected, len(PREAMBLE) + 9)
        many = request(*((("x-%03d" % i).encode(), b"v") for i in range(130)))
        inspector, _ = inspect(PREAMBLE + h2_frame(1, many, flags=0x04, stream=1), Config(max_headers=4096))
        self.assertIsNone(inspector.observation.hostname)

    def test_fingerprints_and_signature_contexts(self):
        observation = inspect(H2_REQUEST, Config(fingerprints=True))[0].observation
        derived = {e.field: e.value for e in observation.evidence if e.strength == "derived"}
        self.assertEqual(derived, {"h2_settings": "3:100;4:65536", "h2_pseudo_order": "m,s,p,a"})
        observation = inspect(H2_RESPONSE, Config(fingerprints=True), hint="http2-server")[0].observation
        self.assertEqual([e for e in observation.evidence if e.strength == "derived"], [])
        signatures = SignatureSet([
            {"name": "example-h2", "category": "general-internet", "subcategory": "internet-utility", "technology": "browser-based", "risk": 2,
             "conditions": [{"context": "http2-req-method", "operator": "equal-to", "value": "GET"},
                            {"context": "http2-req-host-header", "pattern": "www\\.example\\.com"},
                            {"context": "http2-req-uri-path", "operator": "equal-to", "value": "/"}]},
            {"name": "demo-agent", "category": "general-internet", "subcategory": "internet-utility", "technology": "browser-based", "risk": 2,
             "conditions": [{"context": "http2-req-user-agent-header", "pattern": "demo-agent/"},
                            {"context": "http2-req-headers", "pattern": "x-demo: yes\r\n"}]},
            {"name": "h2-redirect", "category": "general-internet", "subcategory": "internet-utility", "technology": "browser-based", "risk": 1,
             "conditions": [{"context": "http2-rsp-status", "operator": "equal-to", "value": 302}]},
        ])
        config = Config(retain_contexts=True)
        observation = inspect(H2_REQUEST, config, signatures=signatures)[0].observation
        self.assertEqual(observation.application, "example-h2")
        self.assertEqual({e.field: e.source for e in observation.evidence}["application"], "signature:http2")
        self.assertEqual(classify(observation, signatures=signatures).app, "example-h2")
        agent = block((b":method", b"POST"), (b":scheme", b"https"), (b":path", b"/api"), (b"user-agent", b"demo-agent/2"), (b"x-demo", b"yes"))
        observation = inspect(PREAMBLE + h2_frame(1, agent, flags=0x04, stream=1), config, signatures=signatures)[0].observation
        self.assertEqual(observation.application, "demo-agent")
        observation = inspect(H2_RESPONSE, config, hint="http2-server", signatures=signatures)[0].observation
        self.assertEqual((observation.application, {e.field: e.source for e in observation.evidence}["application"]), ("h2-redirect", "signature:http2-server"))
        self.assertIsNone(inspect(H2_GRPC, config, signatures=signatures)[0].observation.application)

    def test_seeded_mutations_are_bounded_and_never_leak_header_values(self):
        rng = random.Random(5050)
        for _ in range(1500):
            data = bytearray(H2_GRPC)
            for _ in range(rng.randrange(1, 4)):
                position = rng.randrange(len(PREAMBLE), len(data))
                data[position] = rng.randrange(256)
            inspector = Inspector()
            inspector.feed(bytes(data))
            inspector.end()
            observation = inspector.observation
            self.assertEqual(observation.status, "identified")
            self.assertLessEqual(inspector.metrics.bytes_inspected, len(data))
            self.assertTrue(inspector._terminal)
            text = repr(observation)
            for secret in ("Greeter", "application/", "trailers"):
                self.assertNotIn(secret, text)


class ResponseHeadersTests(unittest.TestCase):
    def test_response_status_and_no_value_leakage(self):
        inspector, events = inspect(H2_RESPONSE, hint="http2-server")
        self.assertEqual([e.kind for e in events], ["updated", "refined"])
        observation = inspector.observation
        fields = values(observation)
        self.assertEqual((fields["http2_message"], fields["http2_status"], observation.scope, observation.hostname), ("response", "302", "response_headers", None))
        for secret in ("private", "www.example.com", "Oct 2013"):
            self.assertNotIn(secret, repr(observation))
        self.assertEqual(classify(observation).app, "web-browsing")
        response = block((b":status", b"200"), (b"content-type", b"application/grpc+proto"))
        observation = inspect(H2_SERVER_SETTINGS + h2_frame(1, response, flags=0x04, stream=1), hint="http2-server")[0].observation
        self.assertEqual((values(observation)["http2_status"], values(observation)["http2_content_type"]), ("200", "grpc"))
        self.assertEqual(classify(observation).app, "web-browsing")   # the server side alone never names gRPC

    def test_response_pseudo_header_rules(self):
        for bad in (block((b":status", b"99")), block((b":status", b"600")), block((b":status", b"20")), block((b":status", b"2000")),
                    block((b":status", b"abc")), block((b"server", b"x")), block((b":status", b"200"), (b":method", b"GET")),
                    block((b":status", b"200"), (b":status", b"200")), HPACK_REQUEST):
            observation = inspect(H2_SERVER_SETTINGS + h2_frame(1, bad, flags=0x04, stream=1), hint="http2-server")[0].observation
            self.assertEqual((observation.status, observation.scope), ("identified", "initial_message"), bad)
            self.assertNotIn("http2_status", values(observation))
        for status in (b"100", b"204", b"404", b"599"):
            observation = inspect(H2_SERVER_SETTINGS + h2_frame(1, block((b":status", status)), flags=0x04, stream=1), hint="http2-server")[0].observation
            self.assertEqual(values(observation)["http2_status"], status.decode())

    def test_h2c_upgrade_phase_keeps_reading_for_the_response_headers(self):
        inspector, events = inspect(H2C_101 + H2_RESPONSE)
        self.assertEqual([e.kind for e in events], ["updated", "shifted"])
        inspector_by_frame = Inspector()
        kinds = [e.kind for part in (H2C_101, H2_SERVER_SETTINGS, H2_RESPONSE[len(H2_SERVER_SETTINGS):]) for e in inspector_by_frame.feed(part)]
        self.assertEqual(kinds, ["updated", "shifted", "shifted"])
        self.assertEqual(inspector_by_frame.observation, inspector.observation)
        observation = inspector.observation
        fields = values(observation)
        self.assertEqual((observation.application_protocol, fields["shift"], fields["http2_status"]), ("http/2", "h2c-upgrade", "302"))
        self.assertTrue(inspector._terminal)
        self.assertEqual(inspector.metrics.bytes_inspected, len(H2C_101) + len(H2_RESPONSE))
        inspector, _ = inspect(H2C_101 + H2_SERVER_SETTINGS)
        self.assertFalse(inspector._terminal)
        inspector.end()
        self.assertTrue(inspector._terminal)
        self.assertEqual(inspector.observation.application_protocol, "http/2")


class OfflineTests(unittest.TestCase):
    def test_session_record_names_grpc_and_the_authority_host(self):
        records = []
        analyzer = Analyzer(on_session=records.append, include_hostnames=True)
        response = H2_RESPONSE
        frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, 1000, 9000, 24, H2_GRPC),
                  frame(B, A, 9000, 1000 + len(H2_GRPC), 24, response),
                  frame(A, B, 1000 + len(H2_GRPC), 9000 + len(response), 17), frame(B, A, 9000 + len(response), 1001 + len(H2_GRPC), 17)]
        for index, data in enumerate(frames):
            analyzer.process(index, decode_packet(data))
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual((record["app"], record["client_protocol"], record["server_protocol"], record["hostname"]), ("grpc", "http/2", "http/2", "grpc.example"))
        self.assertNotIn("Greeter", json.dumps(record))
        self.assertEqual(analyzer.counts["http2_servers_expected"], 1)

    def test_server_expectation_needs_the_client_preface_and_still_validates(self):
        records = []
        analyzer = Analyzer(on_session=records.append)
        bad_settings = b"\x00\x00\x0b\x04\x00\x00\x00\x00\x00" + bytes(11)       # length not a multiple of six
        frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, 1000, 9000, 24, H2_REQUEST),
                  frame(B, A, 9000, 1000 + len(H2_REQUEST), 24, bad_settings),
                  frame(A, B, 1000 + len(H2_REQUEST), 9000 + len(bad_settings), 17), frame(B, A, 9000 + len(bad_settings), 1001 + len(H2_REQUEST), 17)]
        for index, data in enumerate(frames):
            analyzer.process(index, decode_packet(data))
        record = records[0]
        self.assertEqual((record["app"], record["client_protocol"], record["server_protocol"]), ("web-browsing", "http/2", None))
        self.assertEqual(analyzer.counts["http2_servers_expected"], 1)
        # A server that spoke first is never given the expectation; an HTTP/1.1 client does not create one.
        records.clear()
        analyzer = Analyzer(on_session=records.append)
        frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(B, A, 9000, 1000, 24, H2_RESPONSE),
                  frame(A, B, 1000, 9000 + len(H2_RESPONSE), 24, H2_REQUEST),
                  frame(A, B, 1000 + len(H2_REQUEST), 9000 + len(H2_RESPONSE), 17), frame(B, A, 9000 + len(H2_RESPONSE), 1001 + len(H2_REQUEST), 17)]
        for index, data in enumerate(frames):
            analyzer.process(index, decode_packet(data))
        self.assertEqual((records[0]["client_protocol"], records[0]["server_protocol"]), ("http/2", None))
        self.assertEqual(analyzer.counts["http2_servers_expected"], 0)
        inspector = Inspector()
        self.assertTrue(inspector.expect("http2-server", "test"))
        self.assertFalse(inspector.expect("http2-server", "test"))
        with self.assertRaises(ValueError):
            Inspector().expect("not-a-parser", "test")
        inspector.feed(H2_RESPONSE)
        self.assertEqual(values(inspector.observation)["candidate_hint"], "http2-server")
        self.assertEqual({e.field: e.source for e in inspector.observation.evidence}["candidate_hint"], "peer:test")
        self.assertFalse(Inspector().expect("http2-server", "test") and False)
        started = Inspector()
        started.feed(b"G")
        self.assertFalse(started.expect("http2-server", "test"))


if __name__ == "__main__":
    unittest.main()
