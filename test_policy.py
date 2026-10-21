"""v0.30: policy evaluation over session verdicts and the unified CLI."""
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from protocol_engine import Inspector
from protocol_engine.appid import Verdict, session_verdict
from protocol_engine.applications import APPLICATIONS
from protocol_engine.policy import ACTIONS, MAX_RULES, Decision, Policy, PolicyError
from protocol_fixtures import CONNECT_REQUEST, MODBUS, RDP, TELNET
from proxy_demo import client_hello


def verdict_for(data, port, transport="tcp", hint=None):
    inspector = Inspector(protocol_hint=hint)
    inspector.feed(data)
    return session_verdict(inspector.observation, None, transport, port, len(data), 0, True, None)


def synthetic(app, port_usage="standard", risks=(), encryption=None, shifted_from=None):
    entry = APPLICATIONS[app]
    return Verdict(entry.name, entry.category, entry.subcategory, entry.technology, entry.risk, entry.characteristics, None,
                   entry.implicitly_uses, port_usage, "identified", None, None, encryption, (), shifted_from, tuple(risks))


class LoadingTests(unittest.TestCase):
    def test_example_policy_loads_and_lints_clean(self):
        policy = Policy.from_path("policy-example.json")
        self.assertEqual((len(policy), policy.default, policy.lint()), (7, "alert", ()))

    def test_validation_errors(self):
        bad = [
            '[]', '{"version": 2}', '{"default": "drop"}', '{"extra": 1}', '{"rules": {}}',
            '{"rules": [{"action": "allow", "match": {"apps": ["no-such-app"]}}]}',
            '{"rules": [{"action": "allow", "match": {"categories": ["nope"]}}]}',
            '{"rules": [{"action": "allow", "match": {"risks": ["made-up"]}}]}',
            '{"rules": [{"action": "allow", "match": {"server_ports": ["tcp/0"]}}]}',
            '{"rules": [{"action": "allow", "match": {"server_ports": ["sctp/1"]}}]}',
            '{"rules": [{"action": "allow", "match": {"server_ports": ["tcp/5-3"]}}]}',
            '{"rules": [{"action": "allow", "match": {"risk_min": 6}}]}',
            '{"rules": [{"action": "allow", "match": {"risk_min": 4, "risk_max": 2}}]}',
            '{"rules": [{"action": "allow", "match": {"apps": []}}]}',
            '{"rules": [{"action": "allow", "match": {"port_usage": ["weird"]}}]}',
            '{"rules": [{"action": "allow", "match": {"unknown": 1}}]}',
            '{"rules": [{"action": "allow", "bogus": 1}]}',
            '{"rules": [{"action": "allow", "application_default": "yes"}]}',
            '{"rules": [{"name": "a", "action": "allow"}, {"name": "a", "action": "deny"}]}',
            '{"rules": [{"name": "", "action": "allow"}]}',
            '{"rules": "x"}', 'not json',
        ]
        for text in bad:
            with self.assertRaises(PolicyError, msg=text):
                Policy.from_json(text)
        with self.assertRaises(PolicyError):
            Policy([{"action": "allow"}] * (MAX_RULES + 1))
        with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as handle:
            handle.write(b"[" + b" " * (4 * 1024 * 1024) + b"]")
        try:
            with self.assertRaises(PolicyError):
                Policy.from_path(handle.name)
        finally:
            Path(handle.name).unlink()
        self.assertEqual(len(Policy.from_json('{"rules": []}')), 0)
        self.assertEqual(Policy.from_json('{"rules": [{"action": "deny", "match": {"apps": ["msrpc", "postgres"]}}]}').rules[0].apps,
                         frozenset(("dce-rpc", "postgresql")))  # aliases resolve to catalog names


class EvaluationTests(unittest.TestCase):
    def test_first_match_wins_and_default_applies(self):
        policy = Policy.from_json(json.dumps({"default": "deny", "rules": [
            {"name": "a", "action": "alert", "match": {"apps": ["telnet"]}},
            {"name": "b", "action": "allow", "match": {"categories": ["networking"]}},
        ]}))
        telnet = verdict_for(TELNET, 23)
        self.assertEqual(policy.evaluate(telnet, "tcp", 23), Decision("alert", "a", ("rule 'a' matched telnet",)))
        self.assertEqual(policy.evaluate(verdict_for(RDP, 3389), "tcp", 3389).rule, "b")
        modbus = policy.evaluate(verdict_for(MODBUS, 502), "tcp", 502)
        self.assertEqual((modbus.action, modbus.rule), ("deny", None))
        self.assertEqual(Policy.from_json('{"rules": []}').evaluate(telnet).action, "allow")
        with self.assertRaises(TypeError):
            policy.evaluate("telnet")

    def test_every_condition_kind(self):
        def decide(match, verdict, transport="tcp", port=None, application_default=False):
            rule = {"name": "r", "action": "deny", "match": match, "application_default": application_default}
            return Policy([rule]).evaluate(verdict, transport, port).action
        ssl = synthetic("ssl", encryption="tls")
        self.assertEqual(decide({"encryption": ["tls"]}, ssl), "deny")
        self.assertEqual(decide({"encryption": ["none"]}, ssl), "allow")
        self.assertEqual(decide({"encryption": ["none"]}, synthetic("web-browsing")), "deny")
        self.assertEqual(decide({"subcategories": ["encrypted-tunnel"]}, ssl), "deny")
        self.assertEqual(decide({"technologies": ["peer-to-peer"]}, ssl), "allow")
        self.assertEqual(decide({"risk_min": 4}, ssl), "deny")
        self.assertEqual(decide({"risk_max": 3}, ssl), "allow")
        self.assertEqual(decide({"characteristics": ["tunnels-other-applications", "excessive-bandwidth"]}, ssl), "deny")
        self.assertEqual(decide({"characteristics": ["excessive-bandwidth"]}, ssl), "allow")
        self.assertEqual(decide({"risks": ["tls-missing-sni"]}, ssl), "allow")
        self.assertEqual(decide({"risks": ["tls-missing-sni"]}, synthetic("ssl", risks=("tls-missing-sni",))), "deny")
        self.assertEqual(decide({"transports": ["udp"]}, ssl, "tcp"), "allow")
        self.assertEqual(decide({"transports": ["udp"]}, ssl, "udp"), "deny")
        self.assertEqual(decide({"server_ports": ["tcp/443", "tcp/8000-8100"]}, ssl, "tcp", 8080), "deny")
        self.assertEqual(decide({"server_ports": ["tcp/443", "tcp/8000-8100"]}, ssl, "tcp", 8443), "allow")
        self.assertEqual(decide({"server_ports": ["tcp/443"]}, ssl, "udp", 443), "allow")
        self.assertEqual(decide({"server_ports": ["tcp/443"]}, ssl, "tcp", None), "allow")
        self.assertEqual(decide({"server_ports": ["udp/dynamic"]}, ssl, "udp", 40000), "deny")
        self.assertEqual(decide({"shifted_from": ["http-proxy"]}, ssl), "allow")
        self.assertEqual(decide({"shifted_from": ["http-proxy"]}, synthetic("ssl", shifted_from="http-proxy")), "deny")
        self.assertEqual(decide({"port_usage": ["nonstandard"]}, synthetic("ssl", "nonstandard")), "deny")
        self.assertEqual(decide({"apps": ["unknown-tcp"]}, Verdict("unknown-tcp", "unknown", "session-outcome", "unknown", 1, (), None, (), "unknown", "unknown", None, None, None, ())), "deny")
        # application-default: an allow rule matches only on standard (or unknown) ports.
        self.assertEqual(decide({"apps": ["ssl"]}, synthetic("ssl", "nonstandard"), application_default=True), "allow")
        self.assertEqual(decide({"apps": ["ssl"]}, synthetic("ssl", "standard"), application_default=True), "deny")
        self.assertEqual(decide({"apps": ["ssl"]}, synthetic("ssl", "unknown"), application_default=True), "deny")

    def test_application_default_explains_the_fallthrough(self):
        policy = Policy.from_json(json.dumps({"default": "deny", "rules": [
            {"name": "web", "action": "allow", "application_default": True, "match": {"apps": ["web-browsing"]}}]}))
        standard = policy.evaluate(verdict_for(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", 80), "tcp", 80)
        self.assertEqual((standard.action, standard.rule, standard.reasons[1]), ("allow", "web", "application-default: port usage standard"))
        moved = policy.evaluate(verdict_for(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", 8081), "tcp", 8081)
        self.assertEqual((moved.action, moved.rule), ("deny", None))
        self.assertIn("would allow web-browsing on its application-default ports only", moved.reasons[1])
        tunnel = verdict_for(CONNECT_REQUEST + client_hello(), 3128)
        self.assertEqual((tunnel.app, tunnel.shifted_from, tunnel.port_usage), ("ssl", "http-proxy", "standard"))
        proxy_policy = Policy.from_json(json.dumps({"rules": [{"name": "no-tunnels", "action": "deny", "match": {"shifted_from": ["http-proxy"]}}]}))
        self.assertEqual(proxy_policy.evaluate(tunnel, "tcp", 3128).rule, "no-tunnels")

    def test_dependency_and_lint_warnings(self):
        policy = Policy.from_json(json.dumps({"default": "deny", "rules": [
            {"name": "ws", "action": "allow", "match": {"apps": ["websocket"]}},
            {"name": "never", "action": "allow", "application_default": True, "match": {"port_usage": ["nonstandard"]}},
            {"name": "odd", "action": "deny", "match": {"apps": ["unknown-tcp"], "risk_min": 3}},
        ]}))
        warnings = policy.lint()
        self.assertEqual(len(warnings), 3, warnings)
        self.assertIn("rule 'ws' allows websocket which implicitly uses web-browsing, denied by the policy default", warnings)
        self.assertTrue(any("never matches" in w and "'never'" in w for w in warnings))
        self.assertTrue(any("'odd'" in w for w in warnings))
        allowed = Policy.from_json(json.dumps({"default": "deny", "rules": [
            {"name": "web", "action": "allow", "match": {"apps": ["websocket", "web-browsing"]}}]}))
        self.assertEqual(allowed.dependency_warnings(), ())
        self.assertEqual(ACTIONS, ("allow", "deny", "alert"))


class PipelineTests(unittest.TestCase):
    def test_offline_records_and_live_summary_carry_decisions(self):
        from analyze_pcap import Analyzer, analyze, readable_session
        from live_capture import CaptureMonitor
        from capture_stream import CaptureRecord
        from make_sample_pcap import A, B, frame, pcap_bytes
        policy = Policy.from_path("policy-example.json")
        frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, 1000, 9000, 24, TELNET)]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "telnet.pcap"
            path.write_bytes(pcap_bytes(frames))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                analyze(path, json_output=True, events_only=True, sessions=True, policy=policy)
        session = [json.loads(line) for line in output.getvalue().splitlines() if '"type": "session"' in line][0]
        # The synthetic server port is 8080: telnet there is remote access on a nonstandard port (rule 1).
        self.assertEqual(session["policy"], {"action": "deny", "rule": "deny-remote-access", "reasons": ["rule 'deny-remote-access' matched telnet"]})
        self.assertIn("policy=deny(deny-remote-access)", readable_session(session))
        with self.assertRaises(TypeError):
            Analyzer(policy="policy-example.json")
        events = []
        monitor = CaptureMonitor(events.append, policy=policy)
        for index, data in enumerate(frames):
            record = CaptureRecord(index, data, len(data), 1)
            monitor.accept(record, record.timestamp)
        classification = [e for e in events if e["type"] == "classification"][0]
        self.assertEqual(classification["policy"], "deny")
        monitor._session(session)
        self.assertEqual(monitor.summary(1.0, final=True)["policy"], {"deny": 1})
        without = CaptureMonitor(events.append)
        for index, data in enumerate(frames):
            record = CaptureRecord(index, data, len(data), 1)
            without.accept(record, record.timestamp)
        self.assertIsNone([e for e in events if e["type"] == "classification"][-1]["policy"])

    def test_protodetect_cli(self):
        def run(*args):
            return subprocess.run([sys.executable, "-B", "protodetect.py", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, text=True)
        version = run("version")
        self.assertEqual((version.returncode, version.stdout.startswith("protocol-detector ")), (0, True))
        self.assertEqual(run("policy", "lint", "policy-example.json").returncode, 0)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump({"default": "deny", "rules": [{"name": "ws", "action": "allow", "match": {"apps": ["websocket"]}}]}, handle)
        try:
            lenient, strict = run("policy", "lint", handle.name), run("policy", "lint", handle.name, "--strict")
            self.assertEqual((lenient.returncode, strict.returncode), (0, 1))
            self.assertIn("warning: rule 'ws' allows websocket", strict.stdout)
            handle_path = Path(handle.name)
            handle_path.write_text('{"default": "drop"}')
            self.assertEqual(run("policy", "lint", handle.name).returncode, 1)
        finally:
            Path(handle.name).unlink()
        tested = run("policy", "test", "policy-example.json", "--app", "rdp", "--port", "9000")
        self.assertEqual(json.loads(tested.stdout)["decision"]["rule"], "deny-remote-access")
        tested = run("policy", "test", "policy-example.json", "--app", "unknown-udp", "--transport", "udp", "--risk", "unknown-high-entropy-payload")
        self.assertEqual(json.loads(tested.stdout)["decision"]["action"], "alert")
        self.assertEqual(run("policy", "test", "policy-example.json", "--app", "nothing").returncode, 1)
        risks = run("risks", "--json")
        self.assertEqual(risks.returncode, 0)
        self.assertEqual({json.loads(line)["risk"] for line in risks.stdout.splitlines()} >= {"nonstandard-port", "obsolete-protocol"}, True)
        self.assertEqual(run("signatures", "lint", "signatures-example.json").returncode, 0)
        analyzed = run("analyze", "sample-expanded.pcap", "--policy", "policy-example.json", "--json", "--events-only")
        self.assertEqual(analyzed.returncode, 0)
        sessions = [json.loads(line) for line in analyzed.stdout.splitlines() if '"type": "session"' in line]
        self.assertTrue(sessions and all("policy" in row for row in sessions))
        self.assertEqual(run("protocols").returncode, 0)
        self.assertEqual(run().returncode, 2)


if __name__ == "__main__":
    unittest.main()
