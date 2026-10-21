"""v0.29: bounded payload heuristics for unknown traffic and documented flow risks.

Heuristics describe the shape of an unknown prefix (entropy, printable ratio)
without changing the engine status; risks are advisory names derived from the
verdict and structural evidence. Neither identifies an application.
"""
import contextlib
import io
import json
import random
import struct
import tempfile
import unittest
from pathlib import Path

from protocol_engine import Config, DatagramInspector, Inspector
from protocol_engine.appid import classify, session_verdict, verdict_fields
from protocol_engine.heuristics import PayloadProfile, label_entropy, payload_class, payload_profile
from protocol_engine.risks import RISKS, risk_severity
from protocol_fixtures import CONNECT_REQUEST, DNP3, DNS, FTP, MODBUS, RDP, SMB1, TELNET, TLS_SERVER13
from proxy_demo import client_hello
from test_fingerprints import hello
from test_services import rdp

HEURISTICS = Config(heuristics=True)
RANDOM = random.Random(29).randbytes(1200)
UNKNOWN = b"\xfa\xfb" + RANDOM  # 0xfa never selects a family: dispatch says unknown at once


def observe(data, hint=None, config=None):
    inspector = Inspector(config, protocol_hint=hint)
    inspector.feed(data)
    return inspector


def fields(observation, *names):
    return {e.field: e.value for e in observation.evidence if e.field in names}


def dns_query(name_labels):
    name = b"".join(bytes([len(label)]) + label for label in name_labels) + b"\x00"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)


class HeuristicMathTests(unittest.TestCase):
    def test_profile_values_on_known_inputs(self):
        self.assertEqual(payload_profile(b""), PayloadProfile(0, 0.0, 0.0, 0.0, 0))
        self.assertEqual(payload_profile(bytes(100)), PayloadProfile(100, 0.0, 0.0, 1.0, 0))
        self.assertEqual(payload_profile(bytes(range(256))).entropy, 8.0)
        self.assertEqual(payload_profile(bytes(range(256)), limit=16).size, 16)
        text = payload_profile(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
        self.assertEqual((text.printable, text.longest_run), (1.0, text.size))
        self.assertEqual(payload_profile(b"\x00\xff").entropy, 1.0)
        self.assertEqual(label_entropy(b"aaaa"), 0.0)
        self.assertEqual(label_entropy(b"ab"), 1.0)
        self.assertEqual(label_entropy(b""), 0.0)
        self.assertNotIn("-", "{:.2f}".format(payload_profile(b"\x07" * 50).entropy))

    def test_class_thresholds(self):
        self.assertEqual(payload_class(payload_profile(b"abc")), "insufficient")
        self.assertEqual(payload_class(payload_profile(b"plain text message")), "text")
        self.assertEqual(payload_class(payload_profile(RANDOM[:64])), "high-entropy")
        self.assertEqual(payload_class(payload_profile(RANDOM[:40])), "binary")  # too short to call high-entropy
        self.assertEqual(payload_class(payload_profile(bytes(30) + b"\x01\x02\x03\x04" * 5)), "sparse-binary")
        self.assertEqual(payload_class(payload_profile(bytes(range(1, 64)) * 2)), "binary")


class HeuristicEngineTests(unittest.TestCase):
    def test_unknown_stream_is_profiled_only_when_enabled_and_bounded(self):
        plain = observe(UNKNOWN[:100])
        self.assertEqual((plain.observation.status, plain.observation.evidence), ("unknown", ()))
        waiting = observe(UNKNOWN[:300], config=HEURISTICS)
        self.assertEqual(waiting.observation.status, "detecting")  # collecting up to heuristic_bytes
        events = waiting.feed(UNKNOWN[300:])
        self.assertEqual([e.kind for e in events], ["updated"])
        observation = waiting.observation
        self.assertEqual((observation.status, observation.application_protocol), ("unknown", None))
        self.assertEqual(fields(observation, "payload_class", "payload_bytes_profiled"), {"payload_class": "high-entropy", "payload_bytes_profiled": "512"})
        self.assertTrue(all(e.strength == "heuristic" and e.source == "wire:heuristic" for e in observation.evidence))
        self.assertLessEqual(waiting.metrics.bytes_inspected, 512)
        self.assertEqual(waiting.feed(RANDOM), ())
        short = observe(UNKNOWN[:100], config=HEURISTICS)
        short.end()
        self.assertEqual(fields(short.observation, "payload_class", "payload_bytes_profiled"), {"payload_class": "high-entropy", "payload_bytes_profiled": "100"})
        tiny = observe(UNKNOWN[:20], config=HEURISTICS)
        tiny.end()
        self.assertEqual(fields(tiny.observation, "payload_class"), {"payload_class": "binary"})  # 20 bytes cannot be called high-entropy
        small = observe(UNKNOWN[:700], config=Config(heuristics=True, heuristic_bytes=64))
        self.assertEqual(fields(small.observation, "payload_bytes_profiled"), {"payload_bytes_profiled": "64"})
        self.assertLessEqual(small.metrics.bytes_inspected, 64 + 24)
        text = observe(b"\xfa" + b"hello " * 100, config=HEURISTICS)
        self.assertEqual(fields(text.observation, "payload_class"), {"payload_class": "text"})
        for value in RANDOM[:600]:
            observed = observe(bytes([value]) * 70, config=HEURISTICS)
            observed.end()
            self.assertIn(observed.observation.status, ("unknown", "malformed", "identified", "incomplete", "detecting"))
        with self.assertRaises(ValueError):
            Config(heuristic_bytes=8)
        with self.assertRaises(ValueError):
            Config(heuristics=1)

    def test_identified_streams_are_never_profiled(self):
        for data in (MODBUS, TELNET, client_hello()):
            observation = observe(data, config=HEURISTICS).observation
            self.assertEqual(observation.status, "identified")
            self.assertFalse(any(e.strength == "heuristic" for e in observation.evidence))

    def test_datagrams_and_dns_name_shape(self):
        plain = DatagramInspector().inspect(RANDOM[:200])
        self.assertEqual((plain.status, plain.evidence), ("unknown", ()))
        profiled = DatagramInspector(HEURISTICS).inspect(RANDOM[:200])
        self.assertEqual((profiled.status, fields(profiled, "payload_class")["payload_class"]), ("unknown", "high-entropy"))
        self.assertEqual(DatagramInspector(HEURISTICS).inspect(b"\xfa\xfbhello").status, "unknown")
        ordinary = DatagramInspector(HEURISTICS).inspect(DNS)
        self.assertEqual((ordinary.application_protocol, fields(ordinary, "dns_query_shape")), ("dns", {"dns_query_shape": "ordinary"}))
        self.assertEqual([e.field for e in DatagramInspector().inspect(DNS).evidence], ["application_protocol", "dns_message"])
        long_label = DatagramInspector(HEURISTICS).inspect(dns_query([b"a" * 40, b"example", b"com"]))
        self.assertEqual(fields(long_label, "dns_query_shape", "dns_query_longest_label"), {"dns_query_shape": "suspicious", "dns_query_longest_label": "40"})
        random_label = b"x7q2k9m4z1p8w3j6v5"  # 18 distinct characters: 4.17 bits per byte
        shaped = DatagramInspector(HEURISTICS).inspect(dns_query([random_label, b"example", b"com"]))
        ordinary_long = DatagramInspector(HEURISTICS).inspect(dns_query([b"mail-relay-production", b"example", b"com"]))
        self.assertEqual(fields(ordinary_long, "dns_query_shape")["dns_query_shape"], "ordinary")
        self.assertEqual(fields(shaped, "dns_query_shape")["dns_query_shape"], "suspicious")
        self.assertGreaterEqual(float(fields(shaped, "dns_label_entropy")["dns_label_entropy"]), 4.0)
        self.assertNotIn(random_label.decode(), repr(shaped))
        long_name = DatagramInspector(HEURISTICS).inspect(dns_query([b"abcdefgh"] * 18 + [b"com"]))
        self.assertEqual(fields(long_name, "dns_query_shape")["dns_query_shape"], "suspicious")
        self.assertEqual(classify(long_name, "udp", 53).risks, ("dns-suspicious-query-name",))
        self.assertEqual(classify(ordinary, "udp", 53).risks, ())
        self.assertEqual(classify(profiled, "udp", 9999).risks, ("unknown-high-entropy-payload",))


class RiskTests(unittest.TestCase):
    def risks(self, data, port, hint=None, config=None):
        return classify(observe(data, hint, config).observation, "tcp", port).risks

    def test_catalog_entries_are_documented(self):
        for name, (severity, description) in RISKS.items():
            self.assertIn(severity, ("low", "medium", "high"))
            self.assertTrue(description)
            self.assertEqual(risk_severity(name), severity)
            self.assertIn(name, Path("RISKS.md").read_text())

    def test_structural_risks(self):
        self.assertEqual(self.risks(TELNET, 23), ("cleartext-credential-protocol", "obsolete-protocol"))
        self.assertEqual(self.risks(SMB1, 445), ("desktop-or-file-sharing-session", "obsolete-protocol"))
        self.assertEqual(self.risks(b"SSH-1.99-OpenSSH_3.9\r\n", 22), ("obsolete-protocol",))
        self.assertEqual(self.risks(b"SSH-2.0-OpenSSH_9.0\r\n", 22), ())
        self.assertEqual(self.risks(b"SSH-2.0-OpenSSH_9.0\r\n", 2222), ("nonstandard-port",))
        self.assertEqual(fields(observe(b"SSH-2.0-OpenSSH_9.0\r\n").observation, "ssh_version"), {"ssh_version": "2.0"})
        self.assertEqual(self.risks(FTP, 21), ("cleartext-credential-protocol", "desktop-or-file-sharing-session"))
        self.assertEqual(self.risks(rdp(security=0), 3389), ("desktop-or-file-sharing-session", "obsolete-protocol"))
        self.assertEqual(self.risks(RDP, 3389), ("desktop-or-file-sharing-session",))
        self.assertEqual(self.risks(MODBUS, 502), ())
        self.assertEqual(self.risks(DNP3[:8] + bytes([DNP3[8] ^ 1]) + DNP3[9:], 20000), ("malformed-protocol",))
        self.assertEqual(self.risks(UNKNOWN[:100], 4444), ())
        self.assertEqual(self.risks(UNKNOWN, 4444, config=HEURISTICS), ("unknown-high-entropy-payload",))
        self.assertEqual(self.risks(CONNECT_REQUEST + client_hello(), 8080), ("http-proxy-tunnel",))
        self.assertEqual(self.risks(CONNECT_REQUEST, 8080), ("http-proxy-tunnel",))

    def test_tls_offer_risks(self):
        modern = observe(client_hello()).observation
        self.assertEqual(fields(modern, "tls_offered_max_version"), {"tls_offered_max_version": "1.3"})
        self.assertEqual(classify(modern, "tcp", 443).risks, ())
        sni = (0, b"\x00\x0c\x00\x00\x09localhost")
        legacy_field = hello([0x002f, 0x000a], [sni])
        self.assertEqual(self.risks(legacy_field, 443), ())  # legacy field 1.2 without supported_versions is TLS 1.2
        tls10 = legacy_field[:9] + b"\x03\x01" + legacy_field[11:]
        self.assertEqual(self.risks(tls10, 443), ("tls-legacy-version-offer",))
        self.assertEqual(self.risks(tls10, 8443), ("nonstandard-port", "tls-legacy-version-offer"))
        grease_only = hello([0x1301], [sni, (43, b"\x04\x0a\x0a\x03\x02")])  # GREASE ignored, TLS 1.1 remains
        self.assertEqual(fields(observe(grease_only).observation, "tls_offered_max_version"), {"tls_offered_max_version": "1.1"})
        self.assertEqual(self.risks(hello([0x1301], [(43, b"\x02\x03\x04")]), 443), ("tls-missing-sni",))
        self.assertEqual(self.risks(TLS_SERVER13, 443), ())
        server13 = observe(TLS_SERVER13).observation
        self.assertEqual(fields(server13, "tls_offered_max_version"), {})  # server hellos carry selected_tls_version instead
        self.assertEqual(observe(hello([0x1301], [(43, b"\x03\x03\x04")])).observation.status, "malformed")

    def test_session_level_fields_and_outputs(self):
        verdict = session_verdict(observe(TELNET).observation, None, "tcp", 2323, 6, 0, True, None)
        self.assertEqual(verdict.risks, ("cleartext-credential-protocol", "nonstandard-port", "obsolete-protocol"))
        self.assertEqual(verdict_fields(verdict)["risks"], list(verdict.risks))
        self.assertEqual(verdict_fields(session_verdict(None, None, "tcp", 80, 0, 0, False, None))["risks"], [])
        from analyze_pcap import analyze, readable_session
        from make_sample_pcap import A, B, frame, pcap_bytes
        frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, 1000, 9000, 24, TELNET)]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "telnet.pcap"
            path.write_bytes(pcap_bytes(frames))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                analyze(path, json_output=True, events_only=True, sessions=True)
        session = [json.loads(line) for line in output.getvalue().splitlines() if '"type": "session"' in line][0]
        self.assertEqual(session["risks"], ["cleartext-credential-protocol", "nonstandard-port", "obsolete-protocol"])
        self.assertIn("risks=cleartext-credential-protocol,nonstandard-port,obsolete-protocol", readable_session(session))

    def test_live_events_and_summary_carry_risks(self):
        from live_capture import CaptureMonitor
        from capture_stream import CaptureRecord
        from make_sample_pcap import A, B, frame
        events = []
        monitor = CaptureMonitor(events.append)
        frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, 1000, 9000, 24, TELNET)]
        for index, data in enumerate(frames):
            record = CaptureRecord(index, data, len(data), 1)
            monitor.accept(record, record.timestamp)
        classification = [e for e in events if e["type"] == "classification"][0]
        self.assertEqual(classification["risks"], ["cleartext-credential-protocol", "nonstandard-port", "obsolete-protocol"])
        summary = monitor.summary(1.0, final=True)
        self.assertIn("risks", summary)
        self.assertTrue(all(e["type"] != "session" or "risks" in e for e in events))
        self.assertNotIn("payload", json.dumps(events))


if __name__ == "__main__":
    unittest.main()
