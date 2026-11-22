"""The capture-level parity differentials (migration/parity/*_diff.py, schema_go.py, adversarial.py) fail closed.

Codex PRO-20/PRO-21: a differential that compares two empty answers, ignores an exit status or a timeout, or
normalizes a value away entirely, passes while it proves nothing. These tests drive each verdict with the
failure it must catch; none needs the Go binary, capture privileges or the network.
"""
import contextlib
import io
import json
import random
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "migration" / "parity"))

import analyze_diff  # noqa: E402
import control_diff  # noqa: E402
import decrypt_diff  # noqa: E402
import server_diff  # noqa: E402


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


def fake_binary(folder, body):
    """A stand-in protodetect: a shell script that drains its input, then runs body."""
    path = Path(folder) / "protodetect"
    path.write_text("#!/bin/sh\ncat > /dev/null\n" + body)
    path.chmod(0o755)
    return str(path)


class ControlWorkerTests(unittest.TestCase):
    """PRO-21: a worker that exits before emitting events gave both implementations the same empty stream."""
    STREAM = '{"type": "started"}\n{"type": "summary", "packets": 1}\n'

    def lines(self, body):
        with tempfile.TemporaryDirectory() as folder:
            binary = fake_binary(folder, body)
            return control_diff.worker_lines(binary, random.Random(1), [], Path(folder), 2, "s.json", "p.json")

    def test_a_crashed_or_silent_worker_fails(self):
        emit = "printf '%s' '" + self.STREAM + "'\n"
        for body in ("exit 0\n", "echo 'panic: boom' >&2\nexit 2\n", "exit 139\n", emit + "exit 3\n",
                     emit + "echo 'panic: late' >&2\n", "echo '{\"type\": \"started\"}'\n", "echo 'not json'\n"):
            with self.subTest(body=body), self.assertRaises(control_diff.WorkerFailure):
                self.lines(body)

    def test_a_completed_worker_stream_is_returned(self):
        for status in (0, 1, 2):                      # live_capture.py: 1 after an error event, 2 drops or truncation
            self.assertEqual(len(self.lines("printf '%s' '" + self.STREAM + "'\nexit {}\n".format(status))), 2)

    def test_worker_problem_names_the_cause(self):
        stream = self.STREAM.encode()
        self.assertIsNone(control_diff.worker_problem("live", 0, stream, b"", (0, 1, 2)))
        self.assertIn("exit status 3", control_diff.worker_problem("live", 3, stream, b"", (0, 1, 2)))
        self.assertIn("exit status 1", control_diff.worker_problem("live-decrypt", 1, stream, b"", (0,)))
        self.assertIn("no events", control_diff.worker_problem("live", 0, b"", b"", (0, 1, 2)))
        self.assertIn("no summary", control_diff.worker_problem("live", 0, json.dumps({"type": "started"}).encode(), b"", (0, 1, 2)))
        self.assertIn("standard error", control_diff.worker_problem("live", 0, stream, b"panic", (0, 1, 2)))
        started = json.dumps({"type": "started"}).encode()
        self.assertIsNone(control_diff.worker_problem("live-decrypt", 0, started, b"", (0,), summary=False))

    def test_decryption_events_must_equal_the_reference_worker(self):
        done = type("Done", (), {"returncode": 0, "stdout": self.STREAM.encode(), "stderr": b""})
        self.assertEqual(len(control_diff.checked_lines("live-decrypt", done, (0,), False, self.STREAM)), 2)
        with self.assertRaises(control_diff.WorkerFailure):
            control_diff.checked_lines("live-decrypt", done, (0,), False, self.STREAM + '{"type": "summary", "final": true}\n')


def histogram(count, total):
    return {"count": count, "sum": total, "min": total, "max": total, "p50": 0.001, "p95": 0.001, "p99": 0.001,
            "buckets": [[0.001, count], ["+inf", 0]]}


def state(counters=None, histograms=None):
    telemetry = {"counters": {"bytes.new": 40, "capture.gaps": 0} if counters is None else counters,
                 "histograms": {"stage_seconds.packet": histogram(3, 0.0004), "session_lifetime_seconds": histogram(1, 2.5)}
                 if histograms is None else histograms}
    return {"state": "stopped", "summary": {"telemetry": telemetry}}


class ServerNormalizerTests(unittest.TestCase):
    """PRO-21: the normalizer replaced whole telemetry and histograms values with one constant."""

    def normal(self, document):
        return json.dumps(server_diff.Normalizer().walk(document))

    def test_measured_durations_and_the_tick_count_are_the_only_volatile_telemetry(self):
        timed = state(histograms={"stage_seconds.packet": dict(histogram(3, 0.9), buckets=[[0.001, 1], ["+inf", 2]]),
                                  "session_lifetime_seconds": histogram(1, 3.5)})
        self.assertEqual(self.normal(state()), self.normal(timed))
        ticks = {"stage_seconds.tick": histogram(14, 0.01)}
        self.assertEqual(self.normal(state(histograms=ticks)), self.normal(state(histograms={"stage_seconds.tick": histogram(6, 0.02)})))

    def test_counters_histogram_entries_and_structure_are_compared(self):
        for changed in (state(counters={"bytes.new": 41, "capture.gaps": 0}), state(counters={"bytes.new": 40}),
                        state(histograms={"stage_seconds.packet": histogram(3, 0.0004)}),
                        state(histograms={"stage_seconds.packet": histogram(4, 0.0004), "session_lifetime_seconds": histogram(1, 2.5)}),
                        state(histograms={"stage_seconds.packet": histogram(3, 0.0004), "session_lifetime_seconds": histogram(2, 2.5)}),
                        state(histograms={"stage_seconds.packet": dict(histogram(3, 0.0004), buckets=[[0.005, 3], ["+inf", 0]]),
                                          "session_lifetime_seconds": histogram(1, 2.5)}),
                        state(histograms={"stage_seconds.packet": dict(histogram(3, 0.0004), min=None),
                                          "session_lifetime_seconds": histogram(1, 2.5)}),
                        state(histograms={"stage_seconds.packet": None, "session_lifetime_seconds": histogram(1, 2.5)}),
                        {"state": "stopped", "summary": {"telemetry": None}}, {"state": "stopped", "summary": {"telemetry": {}}}):
            with self.subTest(changed=changed):
                self.assertNotEqual(self.normal(state()), self.normal(changed))


class StuckService:
    """A service whose live run never reaches a state and whose jobs never leave the queue."""
    name = "stuck"

    def json(self, method, path):
        return {"state": "running", "events_total": 0}

    def request(self, method, path):
        return b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"state": "queued"}'


class ServerProbeTests(unittest.TestCase):
    """PRO-21: readiness and terminal waits returned None (or the last answer) on timeout and the callers went on;
    the admission and handler-pool probes compared whatever both services answered."""

    def test_a_wait_that_times_out_fails(self):
        with self.assertRaises(server_diff.ProbeFailure) as caught:
            server_diff.wait_until(StuckService(), lambda state: state["state"] == "stopped", 0.3, "the run stopped")
        self.assertIn("the run stopped", str(caught.exception))
        with self.assertRaises(server_diff.ProbeFailure):
            server_diff.poll_job(StuckService(), "job", 0.3)

    def test_probe_answers_must_have_the_expected_status(self):
        accepted = b'HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\n\r\n{"id": "a", "state": "queued"}'
        refused = b'HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\n\r\n{"error": "busy"}'
        server_diff.require_status("go", "admission 0", accepted, 202)
        for answer in (refused, b"", b"garbage"):
            with self.subTest(answer=answer), self.assertRaises(server_diff.ProbeFailure):
                server_diff.require_status("go", "admission 0", answer, 202)
        self.assertEqual(server_diff.admission_statuses(), [202] * 6 + [429])


if __name__ == "__main__":
    unittest.main()
