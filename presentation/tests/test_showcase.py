"""Integration contracts for the presentation adapter, using synthetic traffic only."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import server
from analyze_pcap import analyze
from make_sample_pcap import pcap_bytes, sample_frames, pcapng_bytes
from packets import CaptureError


class ShowcaseTests(unittest.TestCase):
    def test_snapshot_matches_verified_github_blobs(self):
        manifest = json.loads((server.ROOT / "SOURCE.json").read_text())
        for entry in manifest["files"]:
            with self.subTest(path=entry["path"]):
                data = (server.ENGINE / entry["path"]).read_bytes()
                digest = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
                self.assertEqual(digest, entry["sha"])

    def test_demo_has_actual_identifications_uncertainty_and_transitions(self):
        result = server.analyze_bytes(server.demo_bytes())
        rows = result["sessions"]
        self.assertEqual(len(rows), 18)
        self.assertEqual(result["meta"]["identified"], 15)
        self.assertTrue(any(s["app"] == "ssh" and s["server"][1] == 443 and s["port_usage"] == "nonstandard" for s in rows))
        shifted = next(s for s in rows if s["shifted_from"] == "http-proxy")
        self.assertEqual(shifted["encryption"], "tls")
        self.assertTrue(any(e["kind"] == "shifted" for e in shifted["events"]))
        self.assertEqual(sum(s["app"] == "unknown-tcp" for s in rows), 3)
        self.assertTrue(any(s["app"] == "quic" and s["fingerprints"].get("ja4", "").startswith("q") for s in rows))
        self.assertNotIn("s3cret", json.dumps(result))

    def test_session_verdicts_match_engine_cli(self):
        data = pcap_bytes(sample_frames())
        got = server.analyze_bytes(data)
        with tempfile.NamedTemporaryFile(suffix=".pcap") as capture:
            capture.write(data)
            capture.flush()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                analyze(capture.name, json_output=True, events_only=True, sessions=True,
                        fingerprints=True, heuristics=True, certificates=True)
        expected = [r for r in map(json.loads, output.getvalue().splitlines()) if r.get("type") == "session"]
        for actual, original in zip(json.loads(json.dumps(got["sessions"])), expected):
            self.assertEqual({k: v for k, v in actual.items() if k not in ("id", "events", "end_reason")},
                             {k: v for k, v in original.items() if k != "end_reason"})
        self.assertEqual(len(got["sessions"]), len(expected))

    def test_pcapng_upload_same_verdicts_as_classic(self):
        frames = sample_frames()
        a = server.analyze_bytes(pcap_bytes(frames))
        b = server.analyze_bytes(pcapng_bytes(frames))
        self.assertEqual(a["sessions"], b["sessions"])

    def test_invalid_and_truncated_captures_publish_no_result(self):
        for bad in (b"not a pcap", pcap_bytes(sample_frames())[:-3]):
            with self.subTest(length=len(bad)), self.assertRaises((CaptureError, ValueError)):
                server.analyze_bytes(bad)

    def test_frame_session_event_limits(self):
        data = pcap_bytes(sample_frames())
        for limit in ("MAX_FRAMES", "MAX_SESSIONS", "MAX_EVENTS"):
            with self.subTest(limit=limit), patch.object(server, limit, 0), self.assertRaises(ValueError):
                server.analyze_bytes(data)

    def test_empty_capture_error(self):
        with self.assertRaisesRegex(ValueError, "no frames"):
            server.analyze_bytes(pcap_bytes([]))

    def test_catalog_comes_from_actual_engine(self):
        from protocol_engine import supported_protocols
        from protocol_engine.applications import APPLICATIONS
        catalog = server.catalog_data()
        self.assertEqual(len(catalog["protocols"]), len(supported_protocols()))
        self.assertEqual(len(catalog["applications"]), len(APPLICATIONS))
        self.assertEqual(catalog["source"]["version"], "0.58.0")


if __name__ == "__main__":
    unittest.main()
