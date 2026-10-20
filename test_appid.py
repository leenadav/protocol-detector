"""App-ID style verdicts: catalog integrity, direction/session merging, session records."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from analyze_pcap import Analyzer, analyze
from capture_stream import CaptureRecord
from live_capture import CaptureMonitor
from make_sample_pcap import A, B, REQUEST, frame, pcap_bytes, udp_frame
from packets import decode_packet
from protocol_engine import ApplicationRule, DatagramInspector, Inspector, Observation, RuleIndex, supported_protocols
from protocol_engine.applications import ALIASES, APPLICATIONS, CATEGORIES, OUTCOMES, application_name, lookup
from protocol_engine.appid import Verdict, classify, session_verdict, verdict_fields
from protocol_fixtures import DATAGRAM_CASES, DNS, HINTED_DATAGRAM_CASES, HINTED_STREAM_CASES, STREAM_CASES
from proxy_demo import client_hello

SSH = b"SSH-2.0-demo\r\n"


def observe(data, **kwargs):
    inspector = Inspector(**kwargs)
    inspector.feed(data)
    return inspector.observation


class CatalogTests(unittest.TestCase):
    def test_every_engine_family_has_a_catalog_application(self):
        for entry in supported_protocols():
            name = application_name(entry.family)
            self.assertIsNotNone(name, entry.family)
            self.assertIn(name, APPLICATIONS)
        for data, protocol in STREAM_CASES + DATAGRAM_CASES:
            self.assertIsNotNone(application_name(protocol), protocol)
        for data, protocol, hint in HINTED_STREAM_CASES + HINTED_DATAGRAM_CASES:
            self.assertIsNotNone(application_name(protocol), protocol)
        self.assertEqual(application_name(encryption="tls"), "ssl")
        self.assertIsNone(application_name("not-a-protocol"))
        self.assertIsNone(application_name(None))

    def test_catalog_attributes_are_valid_and_cross_references_resolve(self):
        for app in APPLICATIONS.values():
            self.assertIn(app.subcategory, CATEGORIES[app.category], app.name)
            self.assertTrue(1 <= app.risk <= 5)
            for reference in app.implicitly_uses + app.depends_on:
                self.assertIn(reference, APPLICATIONS)
            self.assertTrue(app.description)
        self.assertEqual(set(OUTCOMES) <= set(APPLICATIONS), True)
        self.assertIs(lookup("redis"), APPLICATIONS["resp"])
        self.assertIs(lookup("ms-ds-smbv2"), APPLICATIONS["smb"])
        self.assertIsNone(lookup("missing"))
        self.assertFalse(set(ALIASES) & set(APPLICATIONS))
        with self.assertRaises(AttributeError):
            APPLICATIONS["ssh"].risk = 1  # frozen

    def test_port_matching_including_ranges_and_dynamic(self):
        self.assertTrue(APPLICATIONS["vnc"].uses_port("tcp", 5909))
        self.assertFalse(APPLICATIONS["vnc"].uses_port("tcp", 5910))
        self.assertFalse(APPLICATIONS["vnc"].uses_port("udp", 5900))
        self.assertTrue(APPLICATIONS["bittorrent"].uses_port("udp", 1))
        self.assertTrue(APPLICATIONS["web-browsing"].uses_port("tcp", 443))  # secure port
        self.assertFalse(APPLICATIONS["unknown-tcp"].uses_port("tcp", 80))


class VerdictTests(unittest.TestCase):
    def test_identified_directions_map_to_catalog_names_and_ports(self):
        http = observe(REQUEST)
        verdict = classify(http, "tcp", 80)
        self.assertEqual((verdict.app, verdict.port_usage, verdict.risk, verdict.category), ("web-browsing", "standard", 4, "general-internet"))
        self.assertTrue(verdict.identified)
        self.assertEqual(classify(http, "tcp", 8443).port_usage, "nonstandard")
        self.assertEqual(classify(http, "tcp", None).port_usage, "unknown")
        tls = classify(observe(client_hello()), "tcp", 443)
        self.assertEqual((tls.app, tls.encryption, tls.client_protocol), ("ssl", "tls", "tls"))
        for data, protocol in STREAM_CASES:
            self.assertTrue(classify(observe(data)).identified, protocol)
        for data, protocol in DATAGRAM_CASES:
            self.assertTrue(classify(DatagramInspector().inspect(data), "udp", 53).identified, protocol)

    def test_configured_mapping_becomes_custom_application_over_its_container(self):
        rules = RuleIndex([ApplicationRule("example.com", "Example Service", "tls_sni")])
        verdict = classify(observe(client_hello(), rules=rules), "tcp", 443)
        self.assertEqual((verdict.app, verdict.base_app, verdict.implicitly_uses), ("Example Service", "ssl", ("ssl",)))
        self.assertEqual((verdict.category, verdict.subcategory, verdict.risk), ("custom", "configured-mapping", 4))
        self.assertEqual(verdict.port_usage, "standard")

    def test_outcomes_for_unknown_malformed_budget_incomplete_invalidated(self):
        unknown = observe(b"\x00\x01garbage")
        self.assertEqual(classify(unknown, "tcp").app, "unknown-tcp")
        self.assertEqual(classify(unknown, "udp").app, "unknown-udp")
        malformed = observe(REQUEST[:-2] + b"Host : bad\r\n\r\n")
        self.assertEqual(malformed.status, "malformed")
        self.assertEqual(classify(malformed).app, "unknown-tcp")
        self.assertEqual(classify(DatagramInspector().inspect(b"x" * 70000)).app, "unknown-udp")
        inspector = Inspector(); inspector.feed(b"GE"); inspector.end()
        self.assertEqual(classify(inspector.observation, payload_bytes=2).app, "insufficient-data")
        self.assertEqual(classify(inspector.observation, payload_bytes=0).app, "incomplete")
        self.assertEqual(classify(inspector.observation).app, "insufficient-data")
        inspector = Inspector(); inspector.feed(b"GE"); inspector.invalidate("lost integrity")
        verdict = classify(inspector.observation)
        self.assertEqual((verdict.app, verdict.status, verdict.port_usage), ("not-applicable", "invalidated", "unknown"))
        self.assertFalse(verdict.identified)
        with self.assertRaises(TypeError):
            classify("not an observation")
        with self.assertRaises(ValueError):
            classify(unknown, "icmp")

    def test_session_merge_prefers_identification_and_records_disagreement(self):
        http, ssh, tls = observe(REQUEST), observe(SSH), observe(client_hello())
        incomplete = Observation(status="incomplete", reason="EOF")
        self.assertEqual(session_verdict(http, http, "tcp", 80).app, "web-browsing")
        self.assertEqual(session_verdict(incomplete, ssh, "tcp", 22).app, "ssh")
        self.assertEqual(session_verdict(None, ssh, "tcp", 22).client_protocol, None)
        disagreement = session_verdict(http, ssh, "tcp", 22)
        self.assertEqual(disagreement.app, "web-browsing")
        self.assertIn("Server direction identified as ssh", disagreement.reasons)
        self.assertEqual(disagreement.server_protocol, "ssh")
        invalidated = Observation(status="invalidated", reason="conflict")
        kept = session_verdict(tls, invalidated, "tcp", 443)
        self.assertEqual(kept.app, "ssl")
        self.assertTrue(any("invalidated" in reason for reason in kept.reasons))
        self.assertEqual(session_verdict(None, None, handshake_complete=False).app, "incomplete")
        self.assertEqual(session_verdict(incomplete, incomplete, client_bytes=0, server_bytes=0).app, "incomplete")
        self.assertEqual(session_verdict(incomplete, incomplete, client_bytes=3, server_bytes=0).app, "insufficient-data")
        self.assertEqual(session_verdict(Observation(status="unknown", reason="x"), incomplete, client_bytes=5).app, "unknown-tcp")
        self.assertEqual(session_verdict(invalidated, incomplete, client_bytes=5).app, "not-applicable")
        self.assertEqual(session_verdict(incomplete, None, "udp", 53, 10).app, "insufficient-data")

    def test_verdict_fields_are_json_and_payload_free(self):
        rules = RuleIndex([ApplicationRule("example.com", "Example", "http_host")])
        fields = verdict_fields(classify(observe(REQUEST, rules=rules), "tcp", 80))
        json.dumps(fields)
        self.assertEqual(fields["app"], "Example")
        self.assertNotIn("example.com", json.dumps(fields))
        self.assertEqual(fields["engine_status"], "identified")
        self.assertIsInstance(classify(observe(REQUEST)), Verdict)


class SessionLedgerTests(unittest.TestCase):
    def analyzer(self, **kwargs):
        records = []
        analyzer = Analyzer(on_session=records.append, **kwargs)
        return analyzer, records

    def run_frames(self, analyzer, frames):
        for index, data in enumerate(frames):
            analyzer.process(index, decode_packet(data))

    def test_tcp_session_record_after_both_fins(self):
        analyzer, records = self.analyzer()
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        self.run_frames(analyzer, [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, 1000, 9000, 24, REQUEST),
                                   frame(B, A, 9000, 1000 + len(REQUEST), 24, response),
                                   frame(A, B, 1000 + len(REQUEST), 9000 + len(response), 17),
                                   frame(B, A, 9000 + len(response), 1001 + len(REQUEST), 17)])
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual((record["type"], record["transport"], record["client"], record["server"]), ("session", "tcp", A, B))
        self.assertEqual((record["app"], record["port_usage"], record["client_protocol"], record["server_protocol"]),
                         ("web-browsing", "standard", "http/1.1", "http/1.1"))
        self.assertEqual((record["client_bytes"], record["server_bytes"], record["packets"]), (len(REQUEST), len(response), 6))
        self.assertEqual(record["end_reason"], "Both TCP directions closed with FIN")
        self.assertNotIn("hostname", record)
        self.assertNotIn("example.com", json.dumps(record))
        self.assertFalse(analyzer.tracked)
        analyzer.finish()
        self.assertEqual(len(records), 1)

    def test_handshake_only_and_syn_only_sessions(self):
        analyzer, records = self.analyzer()
        self.run_frames(analyzer, [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18)])
        self.run_frames(analyzer, [frame(("192.0.2.5", 7), B, 1, 0, 2)])
        analyzer.finish("Capture ended")
        self.assertEqual(sorted(record["app"] for record in records), ["incomplete", "incomplete"])
        statuses = {tuple(record["client"]): record["engine_status"] for record in records}
        self.assertEqual(statuses[A], "incomplete")
        self.assertEqual(statuses[("192.0.2.5", 7)], "no_handshake")
        self.assertTrue(all(record["end_reason"] == "Capture ended" for record in records))

    def test_insufficient_data_unknown_and_rejection_sessions(self):
        analyzer, records = self.analyzer()
        self.run_frames(analyzer, [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, 1000, 9000, 24, b"GET ")])
        analyzer.expire(1000)
        self.assertEqual((records[-1]["app"], records[-1]["client_bytes"]), ("insufficient-data", 4))
        self.assertIn("Idle timeout", records[-1]["end_reason"])
        self.run_frames(analyzer, [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, 1000, 9000, 24, b"\x00\x01garbage")])
        self.run_frames(analyzer, [frame(A, B, 1000 + 9, 9000, 4)])  # RST
        self.assertEqual(records[-1]["app"], "unknown-tcp")
        self.assertIn("RST", records[-1]["end_reason"])
        self.run_frames(analyzer, [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, 1000, 9000, 25, REQUEST),
                                   frame(A, B, 1000 + len(REQUEST), 9000, 24, b"X")])
        # Control rejection retracts the directional classification, so the session cannot keep the application.
        self.assertEqual((records[-1]["app"], records[-1]["engine_status"]), ("not-applicable", "invalidated"))
        self.assertIn("data beyond observed FIN", records[-1]["reasons"][0])

    def test_udp_flows_aggregate_and_are_bounded(self):
        analyzer, records = self.analyzer(max_udp_flows=1)
        self.run_frames(analyzer, [udp_frame(A, B, DNS), udp_frame(B, A, DNS), udp_frame(("192.0.2.9", 1), B, DNS)])
        self.assertEqual(analyzer.counts["udp_flow_limit"], 1)
        self.assertEqual(len(analyzer.udp_flows), 1)
        analyzer.expire(1000)
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual((record["transport"], record["app"], record["packets"], record["client"], record["server"]), ("udp", "dns", 2, A, B))
        self.assertEqual((record["client_bytes"], record["server_bytes"], record["port_usage"]), (len(DNS), len(DNS), "nonstandard"))
        analyzer, records = self.analyzer()
        self.run_frames(analyzer, [udp_frame(A, ("192.0.2.20", 53), b"\xff" * 20), udp_frame(A, ("192.0.2.20", 53), DNS)])
        analyzer.finish()
        self.assertEqual((records[0]["app"], records[0]["port_usage"]), ("dns", "standard"))  # first identification wins
        with self.assertRaises(ValueError):
            Analyzer(max_udp_flows=-1)
        with self.assertRaises(TypeError):
            Analyzer(on_session=1)

    def test_hostnames_are_opt_in(self):
        for include in (False, True):
            analyzer, records = self.analyzer(include_hostnames=include)
            self.run_frames(analyzer, [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, 1000, 9000, 24, REQUEST)])
            analyzer.finish()
            self.assertEqual("hostname" in records[0], include)
            if include:
                self.assertEqual(records[0]["hostname"], "example.com")

    def test_live_monitor_emits_sessions_apps_and_summary(self):
        events = []
        monitor = CaptureMonitor(events.append)
        frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, 1000, 9000, 24, REQUEST), udp_frame(A, B, DNS)]
        for index, data in enumerate(frames):
            monitor.accept(CaptureRecord(index, data, len(data), 1), index)
        classifications = [event for event in events if event["type"] == "classification"]
        self.assertEqual([event["app"] for event in classifications], ["web-browsing", "dns"])
        monitor.analyzer.finish()
        sessions = [event for event in events if event["type"] == "session"]
        self.assertEqual(sorted(event["app"] for event in sessions), ["dns", "web-browsing"])
        summary = monitor.summary(1, True)
        self.assertEqual(summary["apps"], {"web-browsing": 1, "dns": 1})
        self.assertEqual(summary["counts"]["sessions"], 2)
        self.assertEqual(summary["active_udp_flows"], 0)
        self.assertNotIn("example.com", json.dumps(events))

    def test_offline_json_sessions_and_app_fields(self):
        frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, 1000, 9000, 24, REQUEST), udp_frame(A, B, DNS)]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sessions.pcap"
            path.write_bytes(pcap_bytes(frames))
            for json_output in (True, False):
                output = io.StringIO()
                with redirect_stdout(output):
                    counts = analyze(path, json_output=json_output, events_only=True, sessions=True)
                self.assertEqual(counts["sessions"], 2)
                text = output.getvalue()
                if json_output:
                    rows = [json.loads(line) for line in text.splitlines()]
                    sessions = [row for row in rows if row.get("type") == "session"]
                    # Frame rows keep the full Observation (including asserted Host); session verdicts do not.
                    self.assertNotIn("example.com", json.dumps(sessions))
                    self.assertEqual({row["app"] for row in sessions}, {"web-browsing", "dns"})
                    self.assertEqual([row["app"] for row in rows if "frame" in row], ["web-browsing", "dns"])
                    self.assertEqual(rows[-1]["summary"]["sessions"], 2)
                else:
                    self.assertEqual(text.count("SESSION "), 2)
                    self.assertIn("sessions: 2", text)
            output = io.StringIO()
            with redirect_stdout(output):
                analyze(path, json_output=True, events_only=True)
            self.assertFalse(any(json.loads(line).get("type") == "session" for line in output.getvalue().splitlines()))


if __name__ == "__main__":
    unittest.main()
