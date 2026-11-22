"""The capture-level parity differentials (migration/parity/*_diff.py, schema_go.py, adversarial.py) fail closed.

Codex PRO-20/PRO-21: a differential that compares two empty answers, ignores an exit status or a timeout, or
normalizes a value away entirely, passes while it proves nothing. These tests drive each verdict with the
failure it must catch; none needs the Go binary, capture privileges or the network.
"""
import contextlib
import io
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "migration" / "parity"))

import analyze_diff  # noqa: E402
import decrypt_diff  # noqa: E402


def quiet(function, *args):
    with contextlib.redirect_stdout(io.StringIO()) as output:
        status = function(*args)
    return status, output.getvalue()


class AnalyzeCoverageTests(unittest.TestCase):
    def test_zero_requested_captures_fail(self):
        status, output = quiet(analyze_diff.main, ["--binary", "/nonexistent/protodetect", "--count", "0"])
        self.assertEqual(status, 1, output)
        self.assertIn("no captures", output)

    def test_rows_without_a_known_positive_fail(self):
        self.assertEqual(analyze_diff.coverage_problems(300, 4000, 12, 300), [])
        self.assertIn("the reference produced no rows", analyze_diff.coverage_problems(300, 0, 0, 300))
        self.assertIn("no row identifies a protocol (no known positive)", analyze_diff.coverage_problems(300, 4000, 0, 300))
        self.assertIn("no presentation result was a completed analysis", analyze_diff.coverage_problems(300, 4000, 12, 0))

    def test_identified_rows_are_counted_in_both_output_forms(self):
        rows = ('{"frame": 1, "classification": null, "events": []}\n'
                '{"frame": 8, "classification": {"status": "identified", "application_protocol": "http/1.1"}}\n'
                "#4 a -> b | HTTP=NO_MATCH (Excluded by prefix dispatch)\n"
                "#8 a -> b | HTTP=MATCH (HTTP start-line and headers validated)\n")
        self.assertEqual(analyze_diff.positive_rows(rows), 2)
        self.assertEqual(analyze_diff.positive_rows(""), 0)


class DecryptCoverageTests(unittest.TestCase):
    def test_zero_requested_captures_fail(self):
        status, output = quiet(decrypt_diff.main, ["--binary", "/nonexistent/protodetect", "--count", "0"])
        self.assertEqual(status, 1, output)

    def test_runs_without_a_decrypted_inner_application_fail(self):
        self.assertEqual(decrypt_diff.coverage_problems(300, {"decrypted": 13, "unavailable/gap": 4}, {"ssh"}), [])
        self.assertIn("no captures were requested", decrypt_diff.coverage_problems(0, {}, set()))
        self.assertIn("the reference reported no connection rows", decrypt_diff.coverage_problems(300, {"refused": 300}, set()))
        self.assertIn("no connection was decrypted (no known positive)", decrypt_diff.coverage_problems(300, {"unavailable/gap": 9}, set()))
        self.assertIn("no decrypted connection named an inner application", decrypt_diff.coverage_problems(300, {"decrypted": 3}, set()))


if __name__ == "__main__":
    unittest.main()
