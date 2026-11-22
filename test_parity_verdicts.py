"""Codex PRO-20/PRO-21 P2 (PRO-201): the capture-level differentials fail when they proved nothing, not only
when the two backends diverge."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "migration" / "parity"))
import analyze_diff  # noqa: E402
import decrypt_diff  # noqa: E402


class AnalyzeVerdictTests(unittest.TestCase):
    def test_identified_rows_are_counted_in_text_and_json_forms(self):
        text = "#3 No new contiguous data\n#4 a -> b | contiguous=9 pending=0 | HTTP=NO_MATCH (x); TLS=MATCH (ClientHello)\n"
        rows = '{"frame": 1, "classification": null}\n{"frame": 4, "classification": {"status": "identified"}}\n'
        self.assertEqual(analyze_diff.positive_rows(text), 1)
        self.assertEqual(analyze_diff.positive_rows(rows), 1)
        self.assertEqual(analyze_diff.positive_rows("#1 SYN: waiting\n#4 a -> b | HTTP=NO_MATCH (x)\n"), 0)
        self.assertEqual(analyze_diff.positive_rows('{"classification": {"status": "detecting"}}\n'), 0)

    def test_no_capture_or_no_identified_row_is_a_failure(self):
        self.assertEqual(analyze_diff.shortfall(300, 120, 120), [])
        self.assertTrue(analyze_diff.shortfall(0, 0, 0))
        self.assertTrue(analyze_diff.shortfall(5, 0, 0))
        self.assertTrue(analyze_diff.shortfall(5, 10, 0))


class DecryptVerdictTests(unittest.TestCase):
    def test_no_capture_or_no_decrypted_row_is_a_failure(self):
        self.assertEqual(decrypt_diff.shortfall(300, {"decrypted": 3, "refused": 1}), [])
        self.assertTrue(decrypt_diff.shortfall(0, {}))
        self.assertTrue(decrypt_diff.shortfall(4, {"refused": 4, "unavailable/gap": 2}))


if __name__ == "__main__":
    unittest.main()
