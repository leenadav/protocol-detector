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
from unittest import mock

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


if __name__ == "__main__":
    unittest.main()
