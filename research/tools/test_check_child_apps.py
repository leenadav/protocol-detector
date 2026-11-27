"""Tests for check_child_apps.py: its self-test and the committed wave files (PRO-495)."""
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TOOL = HERE / "check_child_apps.py"


class CheckChildAppsTest(unittest.TestCase):
    def run_tool(self, *args):
        return subprocess.run([sys.executable, "-B", str(TOOL), *args], cwd=ROOT, capture_output=True, text=True)

    def test_self_test(self):
        r = self.run_tool("--self-test")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_committed_waves_are_valid_and_rendered(self):
        waves = sorted((ROOT / "research" / "child-apps").glob("wave-*.json"))
        self.assertTrue(waves)
        for wave in waves:
            r = self.run_tool(str(wave.relative_to(ROOT)))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertNotIn("FAILED", r.stdout)


if __name__ == "__main__":
    unittest.main()
