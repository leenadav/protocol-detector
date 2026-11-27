"""PRO-402: the root launchers start the Go engine. `protodetect.py analyze|live|serve` runs the Go binary with
the arguments unchanged (no Python backend, no fallback), and `main.py` starts the demo page on it."""
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FAKE = """#!{python}
import json, sys
print(json.dumps(sys.argv[1:]))
sys.exit(7)
"""


class ProtodetectLauncherTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.fake = os.path.join(folder.name, "protodetect")
        Path(self.fake).write_text(FAKE.format(python=sys.executable), encoding="utf-8")
        os.chmod(self.fake, os.stat(self.fake).st_mode | stat.S_IXUSR)

    def run_cli(self, arguments, binary):
        env = {k: v for k, v in os.environ.items() if not k.startswith("PROTODETECT_")}
        env["PROTODETECT_GO_BINARY"] = binary
        return subprocess.run([sys.executable, "-B", str(ROOT / "protodetect.py")] + arguments, env=env, cwd=str(ROOT),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60, check=False)

    def test_go_commands_reach_the_binary_unchanged(self):
        for arguments in (["analyze", "capture.pcap", "--json", "--backend", "python"], ["live", "--stdin", "--duration", "0"],
                          ["serve", "--port", "0"], ["analyze", "--help"]):
            done = self.run_cli(arguments, self.fake)
            self.assertEqual((done.returncode, json.loads(done.stdout)), (7, arguments), done.stderr)

    def test_without_the_binary_it_refuses_instead_of_falling_back(self):
        done = self.run_cli(["analyze", str(ROOT / "sample.pcap"), "--json"], self.fake + "-absent")
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")
        self.assertIn("Go engine binary is not installed", done.stderr)

    def test_subcommands_of_the_removed_python_engine_refuse_and_name_the_tag(self):
        # PRO-403: these ran the Python reference, which is gone; they exit 2 and never reach the Go binary.
        for name in ("protocols", "apps", "risks", "demo", "content", "explain", "policy", "signatures"):
            done = self.run_cli([name, "lint", "x.json"], self.fake)
            self.assertEqual((done.returncode, done.stdout), (2, ""), name)
            self.assertIn("python-final", done.stderr)
        self.assertFalse((ROOT / "protocol_engine").exists() or (ROOT / "protocol_adapters").exists())

    def test_version_and_schema_need_no_engine(self):
        done = self.run_cli(["version"], self.fake + "-absent")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertRegex(done.stdout, r"^protocol-detector \d+\.\d+\.\d+\n$")
        done = self.run_cli(["schema"], self.fake + "-absent")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("offline-row", done.stdout.split())

    def test_the_launcher_imports_no_adapter_for_go_commands(self):
        source = (ROOT / "protodetect.py").read_text(encoding="utf-8")
        self.assertNotIn('_delegate("analyze_pcap"', source)
        self.assertNotIn('_delegate("live_capture"', source)

    def test_main_starts_the_demo_page_on_go(self):
        source = (ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn("from presentation.launch import main", source)
        self.assertNotIn("detectors", source)
        sys.path.insert(0, str(ROOT))
        try:
            from presentation import launch
        finally:
            sys.path.remove(str(ROOT))
        self.assertEqual(launch.server_command(8765, binary=self.fake)[:2], [self.fake, "serve"])


if __name__ == "__main__":
    unittest.main()
