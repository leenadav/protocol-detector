"""Backend selection of the presentation capture analysis (migration M8): the Go `present` command by default,
the Python reference on request, without a binary, and for a request the binary declines."""
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import server
from protocol_adapters.make_sample_pcap import pcap_bytes, sample_frames
from protocol_adapters.packets import CaptureError

FAKE = """#!{python}
import json, sys
data = sys.stdin.buffer.read()
mode = data[:1]
if mode == b"D":
    sys.stderr.write("not ported in the Go backend: test\\n")
    sys.exit(64)
if mode == b"C":
    print(json.dumps({{"error_type": "CaptureError", "error": "bad capture"}}))
    sys.exit(3)
if mode == b"V":
    print(json.dumps({{"error_type": "ValueError", "error": "over a limit"}}))
    sys.exit(3)
if mode == b"F":
    sys.stderr.write("boom\\n")
    sys.exit(1)
if mode == b"G":
    print("not json")
    sys.exit(0)
print(json.dumps({{"sessions": [], "meta": {{"fake": sys.argv[1:], "bytes": len(data)}}}}))
"""


class PresentationBackendTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.fake = os.path.join(folder.name, "protodetect")
        Path(self.fake).write_text(FAKE.format(python=sys.executable), encoding="utf-8")
        os.chmod(self.fake, os.stat(self.fake).st_mode | stat.S_IXUSR)
        patcher = mock.patch.dict(os.environ, {"PROTODETECT_GO_BINARY": self.fake})
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("PROTODETECT_BACKEND", None)
        self.capture = pcap_bytes(sample_frames())

    def test_go_is_the_default_and_receives_the_capture_and_the_limits(self):
        with mock.patch.object(server, "MAX_FRAMES", 7):
            result = server.analyze_bytes(self.capture)
        self.assertEqual(result["meta"], {"bytes": len(self.capture), "fake": [
            "present", "--max-frames", "7", "--max-sessions", str(server.MAX_SESSIONS), "--max-events", str(server.MAX_EVENTS)]})

    def test_python_on_request_by_argument_or_environment(self):
        self.assertNotIn("fake", server.analyze_bytes(self.capture, backend="python")["meta"])
        with mock.patch.dict(os.environ, {"PROTODETECT_BACKEND": "python"}):
            self.assertNotIn("fake", server.analyze_bytes(self.capture)["meta"])
            self.assertIn("fake", server.analyze_bytes(self.capture, backend="go")["meta"])   # the argument wins

    def test_refusals_raise_the_reference_exception_classes(self):
        with self.assertRaisesRegex(CaptureError, "^bad capture$"):
            server.analyze_bytes(b"C")
        with self.assertRaisesRegex(ValueError, "^over a limit$") as raised:
            server.analyze_bytes(b"V")
        self.assertNotIsInstance(raised.exception, CaptureError)

    def test_a_decline_runs_the_reference_unless_go_was_demanded(self):
        with self.assertRaises(CaptureError):                 # the reference's own answer to these bytes
            server.analyze_bytes(b"D not a capture")
        with self.assertRaisesRegex(ValueError, "Go backend failed \\(status 64\\): not ported"):
            server.analyze_bytes(b"D", backend="go")

    def test_a_failing_or_garbled_binary_is_an_error_never_a_result(self):
        with self.assertRaisesRegex(ValueError, "Go backend failed \\(status 1\\): boom"):
            server.analyze_bytes(b"F")
        with self.assertRaisesRegex(ValueError, "Go backend failed \\(status 0\\)"):
            server.analyze_bytes(b"G")

    def test_without_a_binary_the_reference_runs_unless_go_was_demanded(self):
        with mock.patch.dict(os.environ, {"PROTODETECT_GO_BINARY": self.fake + "-absent"}):
            self.assertEqual(len(server.analyze_bytes(self.capture)["sessions"]), 2)
            with self.assertRaisesRegex(ValueError, "not installed"):
                server.analyze_bytes(self.capture, backend="go")

    def test_unknown_backend_names_are_refused(self):
        with self.assertRaisesRegex(ValueError, "Unknown backend"):
            server.analyze_bytes(self.capture, backend="rust")

    def test_real_binary_and_reference_agree_where_the_binary_is_built(self):
        built = server.ENGINE / "go" / "bin" / "protodetect"
        if not built.is_file():
            # No binary in this checkout (the hosted presentation jobs build none and allow no skip): the
            # comparison itself is `make parity-analyze` in the Go engine gate, on 300 captures.
            return
        with mock.patch.dict(os.environ, {"PROTODETECT_GO_BINARY": str(built)}):
            data = server.demo_bytes()
            go, reference = server.analyze_bytes(data, backend="go"), server.analyze_bytes(data, backend="python")
            go["meta"]["processing_ms"] = reference["meta"]["processing_ms"] = 0
            self.assertEqual(json.dumps(go), json.dumps(reference))
            for limit in ("MAX_FRAMES", "MAX_SESSIONS", "MAX_EVENTS"):
                errors = []
                for backend in ("go", "python"):
                    with mock.patch.object(server, limit, 0), self.assertRaises(ValueError) as raised:
                        server.analyze_bytes(data, backend=backend)
                    errors.append((type(raised.exception), str(raised.exception)))
                self.assertEqual(errors[0], errors[1])


if __name__ == "__main__":
    unittest.main()
