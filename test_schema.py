"""v0.34: every JSON line the tools emit conforms to the published schemas."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
import schema_check  # noqa: E402
from make_sample_pcap import A, B, frame, pcap_bytes  # noqa: E402
from protocol_fixtures import CONNECT_REQUEST, CONNECT_RESPONSE, TLS_SERVER13  # noqa: E402
from proxy_demo import client_hello  # noqa: E402

SAMPLE = Path("sample-expanded.pcap")


def run_json(*args, stdin=None):
    result = subprocess.run([sys.executable, "-B", *args], input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    return result.returncode, result.stdout.decode("utf-8").splitlines()


class ValidatorTests(unittest.TestCase):
    def test_keywords(self):
        schema = {"type": "object", "additionalProperties": False, "required": ["a"],
                  "properties": {"a": {"type": "integer", "minimum": 1}, "b": {"type": ["string", "null"]}, "c": {"enum": ["x", "y"]},
                                 "d": {"type": "array", "items": {"type": "string"}, "maxItems": 2},
                                 "e": {"type": "array", "items": [{"type": "string"}, {"type": "integer"}], "minItems": 2},
                                 "f": {"oneOf": [{"const": 1}, {"type": "string"}]}, "g": {"$ref": "#/$defs/thing"}},
                  "$defs": {"thing": {"type": "object", "additionalProperties": {"type": "integer"}}}}
        self.assertEqual(schema_check.validate({"a": 1, "b": None, "c": "x", "d": ["q"], "e": ["h", 2], "f": "s", "g": {"k": 3}}, schema), [])
        bad = {"a": True, "b": 3, "c": "z", "d": ["1", "2", "3"], "e": ["h"], "f": 2, "g": {"k": "v"}, "extra": 0}
        problems = schema_check.validate(bad, schema)
        for fragment in ("$.a: expected integer", "$.b: expected string/null", "$.c: 'z' not in enum", "$.d: more than 2 items",
                         "$.e: fewer than 2 items", "$.f: no oneOf branch", "$.g.k: expected integer", "unexpected property 'extra'"):
            self.assertTrue(any(fragment in problem for problem in problems), (fragment, problems))
        self.assertEqual(schema_check.validate({}, schema), ["$: missing required property 'a'"])
        self.assertEqual(schema_check.validate(1.5, {"type": "number", "maximum": 1}), ["$: 1.5 above maximum 1"])
        self.assertEqual(schema_check.validate("x", {"oneOf": [{"type": "string"}, {"const": "x"}]}), ["$: 2 oneOf branches matched"])
        with self.assertRaises(ValueError):
            schema_check.validate(1, {"$ref": "http://elsewhere/x"})
        self.assertEqual(schema_check.names(), ["live-event", "offline-row", "session"])
        for name in schema_check.names():
            schema = schema_check.load(name)
            self.assertEqual(schema["$schema"], "http://json-schema.org/draft-07/schema#")
            self.assertTrue(schema["title"] and schema["description"])


class OutputConformanceTests(unittest.TestCase):
    def check(self, name, lines, minimum=1):
        count, errors = schema_check.validate_lines(lines, name)
        self.assertEqual(errors, [], errors[:5])
        self.assertGreaterEqual(count, minimum)
        return [json.loads(line) for line in lines if line.strip()]

    def test_offline_rows_under_every_option(self):
        for options in ((), ("--events-only",), ("--sessions",), ("--events-only", "--sessions", "--hostnames", "--fingerprints", "--certificates"),
                        ("--sessions", "--policy", "policy-example.json", "--heuristics")):
            code, lines = run_json("analyze_pcap.py", str(SAMPLE), "--json", *options)
            self.assertEqual(code, 0, options)
            rows = self.check("offline-row", lines, 10)
            if "--sessions" in options or "--policy" in options:
                sessions = [row for row in rows if row.get("type") == "session"]
                self.check("session", [json.dumps(row) for row in sessions], 10)
                if "--policy" in options:
                    self.assertTrue(all("policy" in row for row in sessions))
            self.assertEqual(list(rows[-1]), ["summary"])

    def test_live_events_under_every_option(self):
        data = SAMPLE.read_bytes()
        for options in ((), ("--all-events",), ("--heuristics", "--fingerprints", "--hostnames", "--certificates"), ("--policy", "policy-example.json", "--stats-interval", "0")):
            code, lines = run_json("live_capture.py", "--stdin", "--duration", "0", "--json", *options, stdin=data)
            self.assertEqual(code, 0, options)
            events = self.check("live-event", lines, 10)
            self.assertEqual((events[0]["type"], events[-1]["type"]), ("started", "summary"))
            self.assertIn("session", {event["type"] for event in events})
        truncated = pcap_bytes([frame(A, B, 999, 0, 2)])[:-3]
        code, lines = run_json("live_capture.py", "--stdin", "--duration", "0", "--json", stdin=truncated)
        self.assertEqual(code, 1)
        events = self.check("live-event", lines, 2)
        self.assertIn("error", {event["type"] for event in events})

    def test_tunnel_and_pcapng_rows_conform(self):
        hello = client_hello()
        cr, cs = 1000, 9000
        frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, cr, cs, 24, CONNECT_REQUEST),
                  frame(B, A, cs, cr + len(CONNECT_REQUEST), 24, CONNECT_RESPONSE), frame(A, B, cr + len(CONNECT_REQUEST), cs + len(CONNECT_RESPONSE), 24, hello),
                  frame(B, A, cs + len(CONNECT_RESPONSE), cr + len(CONNECT_REQUEST) + len(hello), 24, TLS_SERVER13)]
        from make_sample_pcap import pcapng_bytes
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tunnel.pcapng"
            path.write_bytes(pcapng_bytes(frames, ">", 9))
            code, lines = run_json("protodetect.py", "analyze", str(path), "--json", "--sessions", "--fingerprints")
            self.assertEqual(code, 0)
            rows = self.check("offline-row", lines, 5)
            session = [row for row in rows if row.get("type") == "session"][0]
            self.assertEqual((session["app"], session["server_protocol"]), ("ssl", "tls"))
            code, lines = run_json("protodetect.py", "schema", "offline-row", "--validate", "-", stdin="\n".join(lines).encode())
            self.assertEqual((code, lines[-1].endswith("ok")), (0, True))
            bad = Path(directory) / "bad.jsonl"
            bad.write_text(json.dumps({"type": "session", "app": 1}) + "\nnot json\n")
            code, lines = run_json("protodetect.py", "schema", "session", "--validate", str(bad))
            self.assertEqual(code, 1)
            self.assertTrue(any("invalid JSON" in line for line in lines))
        code, lines = run_json("protodetect.py", "schema")
        self.assertEqual((code, lines), (0, ["live-event", "offline-row", "session"]))
        code, lines = run_json("protodetect.py", "schema", "session")
        self.assertEqual((code, json.loads("\n".join(lines))["title"]), (0, "Session record"))
        self.assertEqual(run_json("protodetect.py", "schema", "nope")[0], 1)


if __name__ == "__main__":
    unittest.main()
