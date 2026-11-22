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


def completed(returncode, lines, stderr=b""):
    import subprocess
    return subprocess.CompletedProcess([], returncode, "".join(line + "\n" for line in lines).encode("utf-8"), stderr)


class ControlWorkerTests(unittest.TestCase):
    """Codex PRO-21 P2: a worker that exits early must not hand both control planes the same empty stream."""

    def setUp(self):
        import control_diff
        self.control = control_diff

    def summary(self, quality):
        return '{"type": "summary", "capture_quality": "%s"}' % quality

    def test_a_finished_worker_hands_over_its_lines(self):
        check = self.control.worker_result
        self.assertEqual(check("live", completed(0, ['{"type": "x"}', self.summary("unverified")])), ['{"type": "x"}', self.summary("unverified")])
        self.assertEqual(len(check("live", completed(2, [self.summary("truncated")]))), 1)        # documented: truncated input
        self.assertEqual(len(check("live", completed(2, [self.summary("loss_reported")]))), 1)
        self.assertEqual(len(check("live", completed(1, [self.summary("failed")]))), 1)           # documented: capture error
        self.assertEqual(len(check("live-decrypt", completed(0, ['{"type": "summary"}']))), 1)
        self.assertEqual(len(check("live-decrypt", completed(1, ['{"type": "error", "code": "key_log"}']))), 1)

    def test_an_early_or_unexplained_exit_is_a_failure_naming_stderr(self):
        check = self.control.worker_result
        for command, done in (("live", completed(0, [])), ("live", completed(2, [])), ("live", completed(-9, ['{"type": "x"}'], b"killed")),
                              ("live", completed(1, [self.summary("unverified")], b"panic: boom")),
                              ("live", completed(0, [self.summary("failed")])), ("live", completed(0, ['{"type": "x"}'])),
                              ("live", completed(0, ["not json"])),
                              ("live-decrypt", completed(2, ['{"type": "summary"}'], b"usage")),
                              ("live-decrypt", completed(0, []))):
            with self.assertRaises(self.control.WorkerError) as raised:
                check(command, done)
            if done.stderr:
                self.assertIn(done.stderr.decode(), str(raised.exception))


if __name__ == "__main__":
    unittest.main()
