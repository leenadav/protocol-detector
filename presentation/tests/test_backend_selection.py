"""Backend selection of the presentation capture analysis and the key-log decryption analysis (migration M8): the
Go `present` and `decrypt-capture` commands by default, the Python reference on request, without a binary, and
for a request the binary declines."""
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
import unittest.mock as mock

import server
from protocol_adapters.make_sample_pcap import pcap_bytes, sample_frames
from protocol_adapters.packets import CaptureError

FAKE = """#!{python}
import json, sys
data = sys.stdin.buffer.read()
if sys.argv[1] == "decrypt-capture":
    size = int.from_bytes(data[:8], "big")
    capture, keylog = data[8:8 + size], data[8 + size:].decode("utf-8")
    if keylog.startswith("#D"):
        sys.exit(64)
    if keylog.startswith("#R"):
        print(json.dumps({{"error_type": "DecryptionError", "error": "refused", "code": "budget_exhausted"}}))
        sys.exit(3)
    if keylog.startswith("#C"):
        print(json.dumps({{"error_type": "CaptureError", "error": "bad capture", "code": ""}}))
        sys.exit(3)
    if keylog.startswith("#F"):
        sys.stderr.write("a secret-looking detail\\n")
        sys.exit(1)
    print(json.dumps({{"connections": [], "fake": sys.argv[1:], "capture": len(capture), "keylog": len(keylog)}}))
    sys.exit(0)
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


class DecryptionBackendTests(unittest.TestCase):
    """analyze_capture: the capture and the key log reach the Go binary on standard input only."""

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

    def test_go_is_the_default_and_secrets_travel_on_standard_input_only(self):
        from poc_decryption.capture import analyze_capture
        keylog = "# a comment line standing in for secrets\n"
        result = analyze_capture(self.capture, keylog)
        self.assertEqual(result, {"connections": [], "fake": ["decrypt-capture"], "capture": len(self.capture), "keylog": len(keylog)})

    def test_python_on_request_and_for_requests_the_binary_cannot_take(self):
        from poc_decryption import DecryptionError
        from poc_decryption.capture import analyze_capture
        self.assertNotIn("fake", analyze_capture(self.capture, "", backend="python"))
        with mock.patch.dict(os.environ, {"PROTODETECT_BACKEND": "python"}):
            self.assertNotIn("fake", analyze_capture(self.capture, ""))
        with self.assertRaisesRegex(DecryptionError, "Key log must be text"):
            analyze_capture(self.capture, 7)                        # the reference's own answer, not a crash in the glue
        self.assertNotIn("fake", analyze_capture(self.capture, "#D declined\n"))
        with self.assertRaisesRegex(ValueError, "status 64"):
            analyze_capture(self.capture, "#D declined\n", backend="go")

    def test_refusals_keep_their_class_and_reason_code(self):
        from poc_decryption import DecryptionError
        from poc_decryption.capture import analyze_capture
        with self.assertRaisesRegex(DecryptionError, "^refused$") as raised:
            analyze_capture(self.capture, "#R\n")
        self.assertEqual(raised.exception.code, "budget_exhausted")
        with self.assertRaisesRegex(CaptureError, "^bad capture$"):
            analyze_capture(self.capture, "#C\n")

    def test_a_failing_binary_is_an_error_and_its_stderr_is_not_relayed(self):
        from poc_decryption.capture import analyze_capture
        with self.assertRaises(ValueError) as raised:
            analyze_capture(self.capture, "#F\n")
        self.assertEqual(str(raised.exception), "The Go backend failed (status 1).")

    def test_without_a_binary_the_reference_runs_unless_go_was_demanded(self):
        from poc_decryption.capture import analyze_capture
        with mock.patch.dict(os.environ, {"PROTODETECT_GO_BINARY": self.fake + "-absent"}):
            self.assertNotIn("fake", analyze_capture(self.capture, ""))
            with self.assertRaisesRegex(ValueError, "not installed"):
                analyze_capture(self.capture, "", backend="go")

    def test_real_binary_and_reference_agree_where_the_binary_is_built(self):
        from poc_decryption.capture import analyze_capture
        from poc_decryption.demo import fixture
        built = server.ENGINE / "go" / "bin" / "protodetect"
        if not built.is_file():
            return      # no binary in this checkout; the comparison is `make parity-decrypt` in the Go engine gate
        capture, keylog, _, _ = fixture()
        with mock.patch.dict(os.environ, {"PROTODETECT_GO_BINARY": str(built)}):
            for keys in (keylog, ""):
                go, reference = analyze_capture(capture, keys, backend="go"), analyze_capture(capture, keys, backend="python")
                self.assertEqual(json.dumps(go), json.dumps(reference))
            self.assertEqual(go["connections"][0]["status"], "unavailable")
            self.assertEqual(analyze_capture(capture, keylog, backend="go")["decrypted"], 1)


class LiveDecryptionHandOverTests(unittest.TestCase):
    """The live decryption worker replaces itself with the Go binary when one is installed."""

    def setUp(self):
        patcher = mock.patch.dict(os.environ, {"PROTODETECT_GO_BINARY": sys.executable})   # any executable file
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("PROTODETECT_BACKEND", None)

    def test_the_binary_takes_the_worker_with_its_arguments_and_nothing_else(self):
        from poc_decryption import live
        calls = []
        reason = live.hand_over_to_go(["--interface", "lo0", "--filter", "tcp", "--duration", "5"], replace=lambda *a: calls.append(a))
        self.assertEqual(calls, [(sys.executable, [sys.executable, "live-decrypt", "--interface", "lo0", "--filter", "tcp", "--duration", "5"])])
        self.assertIn("did not take over", reason)

    def test_the_reference_stays_on_request_and_without_a_binary(self):
        from poc_decryption import live
        calls = []
        with mock.patch.dict(os.environ, {"PROTODETECT_BACKEND": "python"}):
            self.assertEqual(live.hand_over_to_go(["--interface", "lo0"], replace=lambda *a: calls.append(a)), "the reference was requested")
        with mock.patch.dict(os.environ, {"PROTODETECT_GO_BINARY": __file__ + "-absent"}):
            self.assertIn("not installed", live.hand_over_to_go(["--interface", "lo0"], replace=lambda *a: calls.append(a)))
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
