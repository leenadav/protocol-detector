"""Backend selection of the offline analyze command (migration M8): Go by default, Python on request, when no
Go binary is installed and for the requests the Go binary declines with exit status 64."""
import io
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import unittest.mock as mock

from protocol_adapters import analyze_pcap

ROOT = Path(__file__).resolve().parent
SAMPLE = str(ROOT / "sample.pcap")
FAKE = """#!{python}
import sys
arguments = sys.argv[1:]
if "--content-version" in arguments:
    sys.stderr.write("not ported in the Go backend: --content-version\\n")
    sys.exit(64)
if "--checksums" in arguments:
    sys.stderr.write("Capture error: fake failure\\n")
    sys.exit(1)
print("FAKE-GO " + " ".join(arguments))
"""


def run(arguments, environment):
    output, errors, status = io.StringIO(), io.StringIO(), 0
    with mock.patch.object(sys, "argv", ["analyze_pcap.py"] + arguments), mock.patch.dict(os.environ, environment, clear=False), \
            redirect_stdout(output), redirect_stderr(errors):
        for name in ("PROTODETECT_BACKEND", "PROTODETECT_GO_BINARY"):
            if name not in environment:
                os.environ.pop(name, None)
        try:
            analyze_pcap.main()
        except SystemExit as exit_:
            status = exit_.code or 0
    return output.getvalue(), errors.getvalue(), status


class BackendSelectionTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.fake = os.path.join(folder.name, "protodetect")
        Path(self.fake).write_text(FAKE.format(python=sys.executable), encoding="utf-8")
        os.chmod(self.fake, os.stat(self.fake).st_mode | stat.S_IXUSR)
        self.go = {"PROTODETECT_GO_BINARY": self.fake}

    def test_go_is_the_default_and_receives_the_arguments_without_the_backend_option(self):
        output, errors, status = run([SAMPLE, "--json", "--sessions"], self.go)
        self.assertEqual((output, errors, status), ("FAKE-GO analyze {} --json --sessions\n".format(SAMPLE), "", 0))
        output, _, _ = run(["--backend", "go", SAMPLE, "--backend=go", "--hostnames"], self.go)
        self.assertEqual(output, "FAKE-GO analyze {} --hostnames\n".format(SAMPLE))

    def test_python_on_request_by_option_or_environment(self):
        for arguments, environment in (([SAMPLE, "--backend", "python"], self.go),
                                       ([SAMPLE], dict(self.go, PROTODETECT_BACKEND="python"))):
            output, errors, status = run(arguments, environment)
            self.assertIn("Frames: 12; TCP: 12", output)
            self.assertNotIn("FAKE-GO", output)
            self.assertEqual((errors, status), ("", 0))

    def test_option_wins_over_environment(self):
        output, _, _ = run([SAMPLE, "--backend", "go"], dict(self.go, PROTODETECT_BACKEND="python"))
        self.assertTrue(output.startswith("FAKE-GO"))

    def test_python_answers_what_the_go_binary_declines(self):
        from protocol_engine import content
        self.addCleanup(content.select, content.CURRENT)
        output, errors, status = run([SAMPLE, "--content-version", "2026.11.0"], self.go)
        self.assertIn("Frames: 12; TCP: 12", output)                        # the reference ran the rollback
        self.assertEqual((errors, status), ("", 0))                           # the decline is not an error to the caller
        _, errors, status = run([SAMPLE, "--backend", "go", "--content-version", "2026.11.0"], self.go)
        self.assertEqual(status, 1)                                           # asked for Go explicitly: say why, never swap silently
        self.assertEqual(errors, "Capture error: not ported in the Go backend: --content-version\n")

    def test_go_failure_is_reported_with_its_status_and_text(self):
        output, errors, status = run([SAMPLE, "--checksums", "verify"], self.go)
        self.assertEqual((output, errors, status), ("", "Capture error: fake failure\n", 1))

    def test_without_a_binary_the_reference_runs_unless_go_was_demanded(self):
        missing = {"PROTODETECT_GO_BINARY": self.fake + "-absent"}
        output, errors, status = run([SAMPLE], missing)
        self.assertIn("Frames: 12; TCP: 12", output)
        self.assertEqual((errors, status), ("", 0))
        _, errors, status = run([SAMPLE, "--backend", "go"], missing)
        self.assertEqual(status, 1)
        self.assertIn("Go backend binary is not installed", errors)

    def test_unknown_backend_names_are_usage_errors(self):
        self.assertEqual(run([SAMPLE], dict(self.go, PROTODETECT_BACKEND="rust"))[2], 2)
        self.assertEqual(run([SAMPLE, "--backend", "rust"], self.go)[2], 2)

    def test_binary_lookup_order(self):
        with mock.patch.dict(os.environ, self.go):
            self.assertEqual(analyze_pcap.go_binary(), self.fake)
        with mock.patch.dict(os.environ, {"PROTODETECT_GO_BINARY": __file__}):   # a file that is not executable
            self.assertIsNone(analyze_pcap.go_binary())


class LiveHandOverTests(unittest.TestCase):
    """The live adapter hands the capture to the Go binary (process replacement) when the binary accepts it."""

    FAKE = """#!{python}
import sys
arguments = sys.argv[1:]
if "--content-version" in arguments:
    sys.stderr.write("not ported in the Go backend: --content-version\\n")
    sys.exit(64)
if "--policy" in arguments:
    sys.stderr.write("Policy file could not be read\\n")
    sys.exit(1)
sys.exit(0 if arguments[:2] == ["live", "--check"] else 9)
"""

    def setUp(self):
        from protocol_adapters import live_capture
        self.live = live_capture
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.fake = os.path.join(folder.name, "protodetect")
        Path(self.fake).write_text(self.FAKE.format(python=sys.executable), encoding="utf-8")
        os.chmod(self.fake, os.stat(self.fake).st_mode | stat.S_IXUSR)
        patcher = mock.patch.dict(os.environ, {"PROTODETECT_GO_BINARY": self.fake})
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("PROTODETECT_BACKEND", None)

    def test_an_accepted_request_replaces_the_process_without_the_backend_option(self):
        calls = []
        reason = self.live.hand_over_to_go(["--stdin", "--backend", "go", "--json", "--backend=go"], replace=lambda *a: calls.append(a))
        self.assertEqual(calls, [(self.fake, [self.fake, "live", "--stdin", "--json"])])
        self.assertIn("did not take over", reason)        # only reachable with an injected replace

    def test_a_declined_or_rejected_request_stays_with_the_reference(self):
        calls = []
        declined = self.live.hand_over_to_go(["--stdin", "--content-version", "2026.11.0"], replace=lambda *a: calls.append(a))
        rejected = self.live.hand_over_to_go(["--stdin", "--policy", "missing.json"], replace=lambda *a: calls.append(a))
        self.assertEqual(calls, [])
        self.assertEqual(declined, "request not served by the Go backend: not ported in the Go backend: --content-version")
        self.assertEqual(rejected, "the Go backend rejected the request: Policy file could not be read")
        with mock.patch.dict(os.environ, {"PROTODETECT_GO_BINARY": self.fake + "-absent"}):
            self.assertIn("not installed", self.live.hand_over_to_go(["--stdin"], replace=lambda *a: calls.append(a)))
        self.assertEqual(calls, [])

    def run_main(self, arguments, environment=None, stdin=b""):
        import subprocess
        variables = dict(os.environ, **(environment or {}))
        # The adapter's own entry point: `protodetect.py live` hands every request to the Go binary (PRO-402).
        done = subprocess.run([sys.executable, "-B", str(ROOT / "live_capture.py")] + arguments, input=stdin, env=variables,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
        return done.stdout.decode("utf-8"), done.returncode

    def test_options_right_after_the_live_command_reach_the_adapter(self):
        output, status = self.run_main(["--stdin", "--duration", "0", "--stats-interval", "0", "--backend", "python"],
                                       stdin=Path(SAMPLE).read_bytes())
        self.assertEqual(status, 0)
        self.assertIn("STARTED: Passive initial-message inspection", output)
        self.assertIn("SUMMARY ", output)

    def test_python_runs_when_the_binary_declines_and_go_on_demand_reports_why(self):
        capture = Path(SAMPLE).read_bytes()
        output, status = self.run_main(["--stdin", "--duration", "0", "--stats-interval", "0", "--content-version", "2026.11.0"], stdin=capture)
        self.assertEqual(status, 0)
        self.assertIn("SUMMARY ", output)                              # the reference ran the rollback
        output, status = self.run_main(["--stdin", "--duration", "0", "--json", "--backend", "go", "--content-version", "2026.11.0"], stdin=capture)
        self.assertEqual(status, 1)
        self.assertEqual(output.strip(), '{"type": "error", "reason": "request not served by the Go backend: not ported in the Go backend: --content-version"}')

    def test_the_built_binary_and_the_reference_report_the_same_replay(self):
        import json
        built = ROOT / "go" / "bin" / "protodetect"
        if not built.is_file():
            return      # no binary in this checkout; the comparison is `make parity-live` in the Go engine gate
        capture, outputs = Path(SAMPLE).read_bytes(), []
        for backend in ("go", "python"):
            output, status = self.run_main(["--stdin", "--duration", "0", "--stats-interval", "0", "--json", "--backend", backend],
                                           {"PROTODETECT_GO_BINARY": str(built)}, capture)
            self.assertEqual(status, 0)
            events = [json.loads(line) for line in output.splitlines()]
            outputs.append([(event["type"], event.get("app"), event.get("status"), event.get("counts")) for event in events])
        self.assertEqual(outputs[0], outputs[1])
        self.assertGreater(len(outputs[0]), 4)


if __name__ == "__main__":
    unittest.main()
