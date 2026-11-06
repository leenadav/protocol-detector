"""Custom application signatures: compilation safety, contexts, evaluation, integration."""
import io
import json
import re
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from analyze_pcap import Analyzer, analyze
from capture_stream import CaptureRecord
from live_capture import CaptureMonitor
from make_sample_pcap import A, B, REQUEST, frame, pcap_bytes, udp_frame
from packets import decode_packet
from protocol_engine import Config, DatagramInspector, Inspector, SignatureError, SignatureSet
from protocol_engine.appid import classify, session_verdict
from protocol_engine.signatures import CONTEXTS, MAX_CONDITIONS, compile_pattern
from protocol_fixtures import DATAGRAM_CASES, DNS, STREAM_CASES
from proxy_demo import client_hello

CONFIG = Config(retain_contexts=True)
EXAMPLE = Path(__file__).with_name("signatures-example.json")


def sigs(*items):
    return SignatureSet(list(items))


def cond(context, pattern=None, **extra):
    data = {"context": context}
    if pattern is not None:
        data["pattern"] = pattern
    data.update(extra)
    return data


def inspect(data, signatures, config=CONFIG, **kwargs):
    inspector = Inspector(config, signatures=signatures, **kwargs)
    inspector.feed(data)
    return inspector


class CompileTests(unittest.TestCase):
    def test_anchor_requirements_and_unsafe_constructs(self):
        self.assertEqual(compile_pattern("^GET /admin/", "raw")[1], b"GET /admin/")
        self.assertEqual(compile_pattern("abc", "text")[1], b"abc")
        for pattern in ("abc", "(a|b)cdefgh", "a.{0,9}b", "[a-z]{7}"):
            with self.assertRaises(SignatureError):
                compile_pattern(pattern, "raw")
        for pattern in ("(a+)+bcdefgh", "(abcdefgh)\\1", "(?=abcdefgh)", "(?<!abcdefgh)x", "x{5000}abcdefgh"):
            with self.assertRaises(SignatureError):
                compile_pattern(pattern, "raw")
        with self.assertRaises(SignatureError):
            compile_pattern("abcdefg(", "raw")
        with self.assertRaises(SignatureError):
            compile_pattern("x" * 600, "raw")
        with self.assertRaises(SignatureError):
            compile_pattern("אbcdefgh", "raw")  # not Latin-1
        self.assertEqual(compile_pattern("(ab)*cdefghij+", "raw")[1], b"cdefghi")
        compiled, anchor = compile_pattern("AGENT-HELLO", "raw", case_insensitive=True)
        self.assertEqual(anchor, b"agent-hello")
        self.assertTrue(compiled.search(b"xx agent-hello yy"))

    def test_signature_document_validation(self):
        with self.assertRaises(SignatureError):
            sigs({"name": "x", "conditions": [cond("no-such-context", "abcdefgh")]})
        with self.assertRaises(SignatureError):
            sigs({"name": "x", "conditions": [cond("http-req-host-header", "abcdefgh", operator="less-than")]})
        with self.assertRaises(SignatureError):
            sigs({"name": "x", "conditions": [cond("http-req-content-length", operator="pattern-match", pattern="abcdefgh")]})
        with self.assertRaises(SignatureError):
            sigs({"name": "x", "conditions": [cond("http-req-content-length", operator="equal-to", value="7")]})
        with self.assertRaises(SignatureError):
            sigs({"name": "x", "conditions": [cond("ssl-req-client-hello-ext-type", operator="greater-than", value=1)]})
        with self.assertRaises(SignatureError):
            sigs({"name": "x", "conditions": [cond("http-req-host-header", "abcdefgh", negate=True)]})  # no positive condition
        with self.assertRaises(SignatureError):
            sigs({"name": "x", "risk": 9, "conditions": [cond("http-req-host-header", "abcdefgh")]})
        with self.assertRaises(SignatureError):
            sigs({"name": "x", "category": "nope", "conditions": [cond("http-req-host-header", "abcdefgh")]})
        with self.assertRaises(SignatureError):
            sigs({"name": "x", "scope": "session", "conditions": [cond("http-req-host-header", "abcdefgh")]})
        with self.assertRaises(SignatureError):
            sigs({"name": "x", "conditions": {"and": [], }})
        with self.assertRaises(SignatureError):
            sigs({"name": "x", "conditions": {"and": [cond("http-req-host-header", "abcdefgh")], "or": []}})
        nested = cond("http-req-host-header", "abcdefgh")
        for _ in range(5):
            nested = {"or": [nested]}
        with self.assertRaises(SignatureError):
            sigs({"name": "x", "conditions": nested})
        with self.assertRaises(SignatureError):
            sigs({"name": "x", "conditions": [cond("http-req-host-header", "abcdefgh")] * (MAX_CONDITIONS + 1)})
        with self.assertRaises(SignatureError):
            sigs({"name": "dup", "conditions": [cond("http-req-host-header", "abcdefgh")]},
                 {"name": "dup", "conditions": [cond("http-req-host-header", "abcdefgh")]})
        with self.assertRaises(SignatureError):
            SignatureSet.from_json("{not json")
        with self.assertRaises(SignatureError):
            SignatureSet.from_json('{"version": 2, "signatures": []}')
        empty = SignatureSet.from_json("[]")
        self.assertEqual(len(empty), 0)
        example = SignatureSet.from_path(EXAMPLE)
        self.assertEqual(len(example), 6)
        self.assertIn("corp-intranet", example)
        self.assertIsNotNone(example.get("udp-beacon"))
        self.assertIsNone(example.get("missing"))
        for context, (kind, family) in CONTEXTS.items():
            self.assertIn(kind, ("text", "raw", "integer", "set"), context)

    def test_inspectors_require_context_retention_for_signatures(self):
        signatures = sigs({"name": "x", "conditions": [cond("http-req-host-header", "abcdefgh")]})
        with self.assertRaises(ValueError):
            Inspector(Config(), signatures=signatures)
        with self.assertRaises(ValueError):
            DatagramInspector(Config(), signatures)
        with self.assertRaises(TypeError):
            Inspector(CONFIG, signatures=[])
        Inspector(Config(), signatures=SignatureSet())  # empty set needs no retention
        with self.assertRaises(ValueError):
            Config(retain_contexts=1)
        with self.assertRaises(ValueError):
            Config(signature_bytes=8)


class ContextTests(unittest.TestCase):
    def test_contexts_are_only_retained_when_configured(self):
        for data, _ in STREAM_CASES + ((REQUEST, "http/1.1"), (client_hello(), "tls")):
            plain = Inspector(); plain.feed(data)
            self.assertIn(getattr(plain._parser, "contexts", None), (None,))  # parser released or no contexts
            kept = Inspector(CONFIG)
            kept.feed(data)
            self.assertEqual(kept.observation.status, "identified")
        parser_http = Inspector(CONFIG)
        parser_http.feed(b"GET /path/x?secret=1 HTTP/1.1\r\nHost: Example.COM\r\nUser-Agent: Agent/1.0\r\nX: y\r\n\r\n")
        self.assertEqual(parser_http.observation.status, "identified")
        from protocol_engine.parsers import LineParser  # noqa: F401 - documents the retention site
        probe = Inspector(CONFIG)
        probe.feed(b"GET /path/x?secret=1 HTTP/1.1\r\nHost: Example.COM\r\nUser-Agent: Agent/1.0\r\n")
        contexts = probe._parser.contexts
        self.assertEqual(contexts["http-req-method"], b"GET")
        self.assertEqual(contexts["http-req-uri-path"], b"/path/x")
        self.assertEqual(contexts["http-req-version"], b"HTTP/1.1")
        self.assertEqual(contexts["http-req-user-agent-header"], b"Agent/1.0")
        self.assertIn(b"user-agent: Agent/1.0\r\n", bytes(contexts["http-req-headers"]))
        probe.feed(b"\r\n")
        self.assertEqual(probe.observation.hostname, "example.com")
        self.assertNotIn("secret", repr(probe.observation))

    def test_header_block_is_bounded(self):
        probe = Inspector(Config(retain_contexts=True, max_headers=4096))
        probe.feed(b"GET / HTTP/1.1\r\nHost: example.com\r\n" + b"".join(b"X-%d: %s\r\n" % (i, b"v" * 200) for i in range(40)))
        self.assertLessEqual(len(probe._parser.contexts["http-req-headers"]), 4096)

    def test_tls_contexts_and_structured_hello(self):
        probe = Inspector(CONFIG)
        probe.feed(client_hello())
        self.assertEqual(probe.observation.status, "identified")
        hello_inspector = Inspector(CONFIG)
        data = client_hello()
        hello_inspector.feed(data[:-1])
        parser = hello_inspector._parser
        hello_inspector.feed(data[-1:])
        self.assertEqual(parser.contexts["ssl-req-chello-sni"], b"example.com")
        self.assertEqual(parser.contexts["ssl-req-alpn"], b"h2,http/1.1")
        self.assertIn(0, parser.contexts["ssl-req-client-hello-ext-type"])
        self.assertIn(16, parser.contexts["ssl-req-client-hello-ext-type"])
        self.assertEqual(parser.contexts["ssl-req-version"], 0x0303)
        self.assertTrue(parser.hello.ciphers)
        self.assertIn(43, parser.hello.extensions)  # supported_versions from the local TLS library
        self.assertTrue(parser.hello.signature_algorithms)
        self.assertTrue(parser.hello.groups)
        self.assertEqual(parser.contexts["ssl-req-client-hello"], parser.hello.body)
        unretained = Inspector()
        unretained.feed(data[:-1])
        self.assertIsNone(unretained._parser.contexts)


class EvaluationTests(unittest.TestCase):
    def test_http_tls_ssh_dns_contexts_match_and_precede_rule_index(self):
        from protocol_engine import ApplicationRule, RuleIndex
        signatures = SignatureSet.from_path(EXAMPLE)
        rules = RuleIndex([ApplicationRule("intranet.example.com", "Mapped", "http_host")])
        result = inspect(REQUEST.replace(b"example.com", b"intranet.example.com"), signatures, rules=rules).observation
        self.assertEqual((result.status, result.application, result.application_protocol), ("identified", "corp-intranet", "http/1.1"))
        self.assertTrue(any(e.field == "application" and e.strength == "configured_signature" for e in result.evidence))
        connect = inspect(b"CONNECT intranet.example.com:443 HTTP/1.1\r\nHost: intranet.example.com\r\n\r\n", signatures, rules=rules).observation
        self.assertEqual(connect.application, "Mapped")  # negated method condition: fall back to the exact-host rule
        self.assertIsNone(inspect(REQUEST, signatures).observation.application)
        tls = inspect(client_hello(), SignatureSet([{"name": "h2-example", "conditions": [
            cond("ssl-req-chello-sni", operator="equal-to", value="example.com"),
            cond("ssl-req-alpn", "^h2,http/1\\.1$"), cond("ssl-req-version", operator="equal-to", value=0x0303),
            cond("ssl-req-client-hello-ext-type", operator="equal-to", value=16)]}])).observation
        self.assertEqual((tls.application, tls.encryption), ("h2-example", "tls"))
        ssh = inspect(b"SSH-2.0-DeployBot_4.1\r\n", signatures).observation
        self.assertEqual(ssh.application, "automation-ssh-client")
        self.assertIsNone(inspect(b"SSH-2.0-OpenSSH_9\r\n", signatures).observation.application)
        dns_tcp = inspect(len(DNS).to_bytes(2, "big") + DNS, SignatureSet([{"name": "zone", "conditions": [
            cond("dns-req-query-name", operator="equal-to", value="www.example.com"),
            cond("dns-req-query-type", operator="equal-to", value=1)]}])).observation
        self.assertEqual(dns_tcp.application, "zone")
        udp = DatagramInspector(CONFIG, signatures)
        self.assertEqual(udp.inspect(DNS.replace(b"\x07example", b"\x04corp\x07example")[:0] + DNS).application, None)
        corp = bytes.fromhex("123401000001000000000000") + b"\x03www\x04corp\x07example\x03com\x00\x00\x01\x00\x01"
        self.assertEqual(udp.inspect(corp).application, "corp-dns-zone")
        self.assertEqual(udp.inspect(corp).application_protocol, "dns")

    def test_unknown_payload_signatures_stream(self):
        signatures = SignatureSet.from_path(EXAMPLE)
        inspector = Inspector(CONFIG, signatures=signatures)
        self.assertEqual(inspector.feed(b"\x01\x02AG"), ())
        events = inspector.feed(b"ENT-HB\x00binary tail")
        self.assertEqual(events[-1].observation.application, "legacy-agent-protocol")
        self.assertEqual(events[-1].observation.scope, "signature_match")
        self.assertIsNone(events[-1].observation.application_protocol)
        self.assertEqual(inspector.feed(b"more" * 100), ())  # terminal
        lower = inspect(b"\x7fagent-hello/12 ok", signatures)
        self.assertEqual(lower.observation.application, "legacy-agent-protocol")
        waiting = inspect(b"\x7fnothing here yet", signatures)
        self.assertEqual(waiting.observation.status, "detecting")
        waiting.end()
        self.assertEqual(waiting.observation.status, "unknown")
        full = inspect(b"\x7f" + b"z" * 3000, signatures)
        self.assertEqual((full.observation.status, full.metrics.bytes_inspected), ("unknown", 2000))
        prefix_eof = inspect(b"\x01\x02AGENT-HB\x00", signatures)
        prefix_eof.end()  # dispatch for first byte 0x01 waits for eight bytes; EOF still evaluates the prefix
        self.assertEqual(prefix_eof.observation.application, "legacy-agent-protocol")
        short = inspect(b"\x01\x02", signatures)
        short.end()
        self.assertEqual(short.observation.status, "incomplete")
        without = Inspector(CONFIG, signatures=SignatureSet([{"name": "http-only", "conditions": [cond("http-req-host-header", "abcdefgh")]}]))
        without.feed(b"\x7fnothing")
        self.assertEqual(without.observation.status, "unknown")  # no unknown-tcp signatures: immediate outcome as before
        small = Inspector(Config(retain_contexts=True, signature_bytes=16), signatures=signatures)
        small.feed(b"\x7f" + b"q" * 100)
        self.assertEqual((small.observation.status, small.metrics.bytes_inspected), ("unknown", 16))
        hinted = Inspector(CONFIG, signatures=signatures, protocol_hint="dns")
        hinted.feed(b"\x7fagent-hello/1 x")
        self.assertNotEqual(hinted.observation.application, "legacy-agent-protocol")  # hints keep strict validation

    def test_unknown_payload_signatures_datagram(self):
        signatures = SignatureSet.from_path(EXAMPLE)
        udp = DatagramInspector(CONFIG, signatures)
        beacon = udp.inspect(b"\xfa\x01BEACONv1" + bytes(20))
        self.assertEqual((beacon.status, beacon.application, beacon.scope), ("identified", "udp-beacon", "signature_match"))
        self.assertEqual(udp.inspect(b"\xfa\x01BEACONv1" + bytes(200)).status, "unknown")  # length condition fails
        self.assertEqual(udp.inspect(b"\xff" * 30).status, "unknown")
        self.assertEqual(udp.inspect(b"\xfa\x01BEACONv1" + bytes(20), "dns").status, "unknown")  # hint restricts to DNS
        for data, protocol in DATAGRAM_CASES:
            result = udp.inspect(data)
            self.assertEqual(result.status, "identified", protocol)
            self.assertIsNone(result.application)

    def test_negate_or_groups_and_absent_contexts(self):
        signatures = SignatureSet([{"name": "either", "conditions": {"or": [
            cond("http-req-user-agent-header", "^curl/[0-9]"),
            {"and": [cond("http-req-uri-path", "^/api/v1/"), cond("http-req-method", operator="equal-to", value="DELETE", negate=True)]}]}}])
        self.assertEqual(inspect(b"GET / HTTP/1.1\r\nHost: a.example\r\nUser-Agent: curl/8.0\r\n\r\n", signatures).observation.application, "either")
        self.assertEqual(inspect(b"POST /api/v1/x HTTP/1.1\r\nHost: a.example\r\n\r\n", signatures).observation.application, "either")
        self.assertIsNone(inspect(b"DELETE /api/v1/x HTTP/1.1\r\nHost: a.example\r\n\r\n", signatures).observation.application)
        self.assertIsNone(inspect(b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n", signatures).observation.application)
        absent = SignatureSet([{"name": "no-ua", "conditions": [cond("http-req-host-header", "a.example"),
                                                                 cond("http-req-user-agent-header", "Mozilla/", negate=True)]}])
        # Absent context never matches, even negated; the signature needs the UA header to exist.
        self.assertIsNone(inspect(b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n", absent).observation.application)
        self.assertEqual(inspect(b"GET / HTTP/1.1\r\nHost: a.example\r\nUser-Agent: curl\r\n\r\n", absent).observation.application, "no-ua")

    def test_signature_evaluation_is_bounded_and_prefiltered(self):
        many = SignatureSet([{"name": "s%d" % i, "conditions": [cond("unknown-req-tcp-payload", "needle-%07d" % i)]} for i in range(2000)])
        data = b"\x7f" + b"hay" * 600
        start = time.perf_counter()
        for _ in range(20):
            inspect(data, many)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 5.0)
        hit = inspect(b"\x7f" + b"x" * 100 + b"needle-0001999" + b"y" * 100, many)
        self.assertEqual(hit.observation.application, "s1999")
        pathological = SignatureSet([{"name": "p", "conditions": [cond("unknown-req-tcp-payload", "abcdefgh[a-z]*z")]}])
        start = time.perf_counter()
        inspect(b"\x7fabcdefgh" + b"a" * 1990, pathological)
        self.assertLess(time.perf_counter() - start, 1.0)

    def test_signatures_work_inside_decrypted_plaintext(self):
        signatures = SignatureSet.from_path(EXAMPLE)
        inspector = Inspector(CONFIG, signatures=signatures)
        inspector.feed(client_hello())
        inspector.feed_decrypted(REQUEST.replace(b"example.com", b"intranet.example.com"))
        self.assertEqual((inspector.observation.application, inspector.observation.encryption), ("corp-intranet", "tls"))


class IntegrationTests(unittest.TestCase):
    def test_verdicts_use_signature_metadata_and_carriers(self):
        signatures = SignatureSet.from_path(EXAMPLE)
        http = inspect(REQUEST.replace(b"example.com", b"intranet.example.com"), signatures).observation
        verdict = classify(http, "tcp", 80, signatures=signatures)
        self.assertEqual((verdict.app, verdict.category, verdict.subcategory, verdict.risk, verdict.base_app, verdict.implicitly_uses),
                         ("corp-intranet", "business-systems", "general-business", 2, "web-browsing", ("web-browsing",)))
        self.assertEqual(verdict.port_usage, "standard")
        unknown = inspect(b"\x7fagent-hello/3 ping", signatures).observation
        verdict = classify(unknown, "tcp", 4444, signatures=signatures)
        self.assertEqual((verdict.app, verdict.base_app, verdict.risk, verdict.characteristics, verdict.port_usage),
                         ("legacy-agent-protocol", "unknown-tcp", 4, ("evasive",), "unknown"))
        self.assertTrue(verdict.identified)
        beacon = DatagramInspector(CONFIG, signatures).inspect(b"\xfa\x01BEACONv1" + bytes(8))
        self.assertEqual(classify(beacon, "udp", 9, signatures=signatures).base_app, "unknown-udp")
        without_metadata = classify(unknown, "tcp", 4444)  # no signature set: inherits the carrier
        self.assertEqual((without_metadata.app, without_metadata.category, without_metadata.risk), ("legacy-agent-protocol", "custom", 5))
        merged = session_verdict(unknown, None, "tcp", 1, 10, 0, signatures=signatures)
        self.assertEqual(merged.app, "legacy-agent-protocol")

    def test_analyzer_and_cli_accept_signature_files(self):
        signatures = SignatureSet.from_path(EXAMPLE)
        records = []
        analyzer = Analyzer(on_session=records.append, signatures=signatures)
        self.assertTrue(analyzer.inspection_config.retain_contexts)
        frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, 1000, 9000, 24, b"\x01\x02AGENT-HB\x00data"),
                  udp_frame(A, ("192.0.2.20", 9999), b"\xfa\x01BEACONv1" + bytes(4))]
        for index, data in enumerate(frames):
            analyzer.process(index, decode_packet(data))
        analyzer.finish()
        self.assertEqual(sorted(record["app"] for record in records), ["legacy-agent-protocol", "udp-beacon"])
        with self.assertRaises(TypeError):
            Analyzer(signatures={"not": "a set"})
        self.assertFalse(Analyzer(signatures=SignatureSet()).inspection_config.retain_contexts)
        events = []
        monitor = CaptureMonitor(events.append, signatures=signatures)
        for index, data in enumerate(frames):
            monitor.accept(CaptureRecord(index, data, len(data), 1), index)
        apps = [event["app"] for event in events if event["type"] == "classification"]
        self.assertEqual(apps, ["legacy-agent-protocol", "udp-beacon"])
        self.assertNotIn("AGENT", json.dumps(events))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custom.pcap"
            path.write_bytes(pcap_bytes(frames))
            output = io.StringIO()
            with redirect_stdout(output):
                analyze(path, json_output=True, events_only=True, sessions=True, signatures=signatures)
            rows = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(sorted(row["app"] for row in rows if row.get("type") == "session"), ["legacy-agent-protocol", "udp-beacon"])
            self.assertEqual([row["app"] for row in rows if "frame" in row], ["legacy-agent-protocol", "udp-beacon"])
            self.assertNotIn("AGENT-HB", output.getvalue())
            bad = Path(directory) / "bad.json"
            bad.write_text('[{"name": "x", "conditions": [{"context": "unknown-req-tcp-payload", "pattern": "(a+)+bcdefgh"}]}]')
            with self.assertRaises(SignatureError):
                SignatureSet.from_path(bad)
            with self.assertRaises(SignatureError):
                SignatureSet.from_json(json.dumps([{"name": "big", "conditions": [cond("unknown-req-tcp-payload", "a" * 513)]}]))

    def test_retention_does_not_change_classification_of_fixtures(self):
        for data, protocol in STREAM_CASES:
            plain, kept = Inspector(), Inspector(CONFIG)
            plain.feed(data); kept.feed(data)
            self.assertEqual(plain.observation, kept.observation, protocol)
        for data, protocol in DATAGRAM_CASES:
            self.assertEqual(DatagramInspector().inspect(data), DatagramInspector(CONFIG).inspect(data), protocol)
        self.assertTrue(re.fullmatch(r"[a-z0-9-]+", "corp-intranet"))


if __name__ == "__main__":
    unittest.main()
