"""v0.37: the behaviour diff tool compares two trees over fixtures, truncations and mutations."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))


class CompareEngineTests(unittest.TestCase):
    def test_self_comparison_reports_no_differences_and_rejects_non_trees(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.md"
            result = subprocess.run([sys.executable, "-B", "tools/compare_engine.py", ".", "--iterations", "5", "--report", str(report)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            text = report.read_text()
            self.assertIn("No behaviour differences.", text)
            self.assertIn("inputs compared (5 seeded mutations per fixture", text)
            self.assertIn("0 fixtures differ", result.stdout)
            bad = subprocess.run([sys.executable, "-B", "tools/compare_engine.py", directory], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, text=True)
            self.assertEqual((bad.returncode, "not a protocol-detector tree" in bad.stdout), (2, True))

    def test_differences_are_reported_and_fail_unless_report_only(self):
        from compare_engine import render
        differences = {"telnet": [("fffd18", ("identified", "telnet", None), ("unknown", None, None))]}
        text = render(Path("/x"), 10, differences, 1, 7)
        self.assertIn("## telnet (1 differing inputs)", text)
        self.assertIn("| `fffd18` | identified / telnet / None | unknown / None / None |", text)
        self.assertIn("1 fixtures differ", text)


if __name__ == "__main__":
    unittest.main()
