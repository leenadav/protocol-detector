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

    def test_only_refused_presentations_are_a_failure(self):
        """PRO-261 (from PR #99, Codex PRO-20): a run whose every presentation result is a refusal compared no
        completed analysis, so agreement on it proves nothing about `present`."""
        self.assertEqual(analyze_diff.shortfall(300, 120, 120, completed=1), [])
        self.assertEqual(analyze_diff.shortfall(300, 120, 120, completed=0),
                         ["no presentation result was a completed analysis"])


class DecryptVerdictTests(unittest.TestCase):
    def test_no_capture_or_no_decrypted_row_is_a_failure(self):
        self.assertEqual(decrypt_diff.shortfall(300, {"decrypted": 3, "refused": 1}, {"http/1.1"}), [])
        self.assertTrue(decrypt_diff.shortfall(0, {}, set()))
        self.assertTrue(decrypt_diff.shortfall(4, {"refused": 4, "unavailable/gap": 2}, set()))

    def test_decrypted_rows_without_an_inner_application_are_a_failure(self):
        """PRO-261 (from PR #99, Codex PRO-20): decrypting connections that never name their inner application
        leaves the inner classification, the part the differential exists to compare, unexercised."""
        self.assertEqual(decrypt_diff.shortfall(300, {"decrypted": 3}, set()),
                         ["no decrypted connection named an inner application"])

    def test_pro_260_approves_only_the_reference_under_the_hybrid_model(self):
        """PRO-260: a decrypt report that differs from the reference is approved only when it equals the
        reference's report under migration/parity/pro260.py; the model is restored afterwards."""
        from unittest import mock
        import pro260
        from protocol_engine import tls_server
        original = tls_server.parse_server_hello

        def fake_reference(capture, keylog):
            return 0, "model" if hasattr(tls_server.parse_server_hello, "pro260") else "reference"
        with mock.patch.object(decrypt_diff, "reference", fake_reference):
            self.assertTrue(decrypt_diff.approved_divergence(b"", "", 0, "model"))
            self.assertFalse(decrypt_diff.approved_divergence(b"", "", 0, "other"))
            self.assertFalse(decrypt_diff.approved_divergence(b"", "", 1, "model"))     # the exit status too
        self.assertIs(tls_server.parse_server_hello, original)
        self.assertEqual(pro260.self_test(), 0)


class SecSess1PinTests(unittest.TestCase):
    """SEC-SESS-1 (PRO-398, Lee's option B of 2026-11-25): the random-suite divergences are pinned case by case."""

    def test_the_pin_rules_hold(self):
        import sec_sess1
        self.assertEqual(sec_sess1.self_test(), 0)

    def test_exactly_the_reviewed_cases_are_pinned(self):
        """Seed 1: analyze 20, live 6, live-decrypt 18 under OpenSSL 3.0 (CI) and 15 under 3.5, each with its reason
        and both digests; adding or dropping one is a reviewed change."""
        import sec_sess1
        pins = sec_sess1.load()
        analyze = ["seed1/capture-1-{}.pcap/{}".format(n, kind) for n, kind in (
            (50, "present"), (57, "present"), (61, "analyze"), (85, "present"), (101, "analyze"), (101, "present"),
            (127, "present"), (131, "analyze"), (131, "present"), (155, "analyze"), (155, "present"), (182, "analyze"),
            (182, "present"), (209, "analyze"), (209, "present"), (212, "present"), (230, "analyze"), (230, "present"),
            (236, "analyze"), (284, "analyze"))]
        live = ["seed1/capture-{}".format(n) for n in (53, 77, 92, 206, 266, 270)]
        decrypt = (["seed1/openssl-3.0/script-{}".format(n) for n in (4, 25, 27, 31, 44, 62, 64, 74, 97, 122, 175, 187, 230, 260, 280,
                                                                      293, 295, 296)]
                   + ["seed1/openssl-3.5/script-{}".format(n) for n in (4, 19, 47, 88, 129, 137, 154, 169, 172, 179, 182, 245, 248, 296, 297)])
        self.assertEqual(sorted(pins["analyze"]), sorted(analyze))
        self.assertEqual(sorted(pins["live"]), sorted(live))
        self.assertEqual(sorted(pins["live-decrypt"]), sorted(decrypt))
        volatile = sorted(case for suite in sec_sess1.SUITES for case, pin in pins[suite].items() if pin.get("volatile"))
        self.assertEqual(volatile, ["seed1/openssl-3.0/script-175", "seed1/openssl-3.0/script-230", "seed1/openssl-3.0/script-295",
                                    "seed1/openssl-3.0/script-296", "seed1/openssl-3.0/script-31", "seed1/openssl-3.0/script-44",
                                    "seed1/openssl-3.5/script-154", "seed1/openssl-3.5/script-169", "seed1/openssl-3.5/script-179",
                                    "seed1/openssl-3.5/script-19", "seed1/openssl-3.5/script-296"])
        self.assertRegex(sec_sess1.openssl_line(), r"^openssl-\d+\.\d+$")
        for suite in sec_sess1.SUITES:
            for case, pin in pins[suite].items():
                self.assertTrue(pin["reason"].startswith("SEC-SESS-1, PRO-398: "), case)
                self.assertRegex(pin["go_sha256"] + pin["frozen_sha256"], "^[0-9a-f]{128}$")


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


def telemetry(counter=3, count=2, total=0.25, extra=None):
    document = {"telemetry": {"counters": {"bytes.new": counter, "queue.depth": 0},
                              "histograms": {"stage_seconds.packet": {"count": count, "sum": total, "min": total / 4, "max": total, "p50": 0.1,
                                                                      "p95": 0.5, "p99": 0.5, "buckets": [[0.1, 1], [0.5, count - 1], ["+inf", 0]]},
                                             "session_lifetime_seconds": {"count": 1, "sum": 0.004, "min": 0.004, "max": 0.004, "p50": 0.005,
                                                                          "p95": 0.005, "p99": 0.005, "buckets": [[0.005, 1], ["+inf", 0]]}}}}
    document["telemetry"].update(extra or {})
    return document


class ServerNormalizerTests(unittest.TestCase):
    """Codex PRO-21 P2: only wall-clock measurements are normalized away; telemetry structure, keys, counters and
    sample counts are compared."""

    def same(self, left, right):
        import server_diff
        return server_diff.Normalizer().walk(left) == server_diff.Normalizer().walk(right)

    def test_wall_clock_durations_are_normalized(self):
        self.assertTrue(self.same(telemetry(total=0.25), telemetry(total=0.75)))
        changed = telemetry()
        changed["telemetry"]["histograms"]["session_lifetime_seconds"].update(sum=0.009, min=0.009, max=0.009)
        self.assertTrue(self.same(telemetry(), changed))
        ticks = [telemetry(extra={"histograms": {"stage_seconds.tick": {"count": n, "sum": n / 10.0}}}) for n in (6, 14)]
        self.assertTrue(self.same(*ticks))                          # the live loop's idle wake-ups: elapsed time

    def test_counters_counts_keys_and_structure_are_compared(self):
        self.assertFalse(self.same(telemetry(), telemetry(counter=4)))
        self.assertFalse(self.same(telemetry(), telemetry(count=3)))
        self.assertFalse(self.same(telemetry(), telemetry(extra={"counters": {"bytes.new": 3}})))
        self.assertFalse(self.same(telemetry(), {"telemetry": {"counters": {}, "histograms": {}}}))
        changed = telemetry()
        changed["telemetry"]["histograms"]["session_lifetime_seconds"]["count"] = 2
        self.assertFalse(self.same(telemetry(), changed))
        changed = telemetry()
        changed["telemetry"]["histograms"]["session_lifetime_seconds"]["buckets"].pop(0)
        self.assertFalse(self.same(telemetry(), changed))
        self.assertFalse(self.same({"histograms": {"a": {"count": 1}}}, {"histograms": {"a": {"count": 2}}}))

    def test_a_null_in_place_of_a_measurement_is_compared(self):
        """PRO-261 (from PR #99, Codex PRO-21): only a measured number becomes a marker. A null where the other side
        has a number (a missing minimum, a bucket without a count) is a structural difference, not a timing."""
        changed = telemetry()
        changed["telemetry"]["histograms"]["session_lifetime_seconds"]["min"] = None
        self.assertFalse(self.same(telemetry(), changed))
        changed = telemetry()
        buckets = changed["telemetry"]["histograms"]["session_lifetime_seconds"]["buckets"]
        buckets[0] = [buckets[0][0], None]
        self.assertFalse(self.same(telemetry(), changed))
        changed = telemetry(extra={"histograms": {"stage_seconds.tick": {"count": None, "sum": 0.5}}})
        self.assertFalse(self.same(telemetry(extra={"histograms": {"stage_seconds.tick": {"count": 5, "sum": 0.5}}}), changed))


class FakeService:
    name = "fake"

    def __init__(self, state=None, job_state="running"):
        self.state, self.job_state = state or {"state": "running"}, job_state

    def json(self, method, path):
        return dict(self.state)

    def request(self, method, path, **kwargs):
        return b'HTTP/1.0 200 OK\r\n\r\n{"state": "%s"}' % self.job_state.encode()


def answer(status, state=None):
    body = b"{}" if state is None else b'{"id": "x", "state": "%s"}' % state.encode()
    return b"HTTP/1.0 " + status + b"\r\nContent-Type: application/json\r\n\r\n" + body


class ServerProbeTests(unittest.TestCase):
    """Codex PRO-21 P2: a readiness or terminal wait that times out, or a probe whose precondition did not hold
    (the pool not full, admission not reached), is a failure, never an answer to compare."""

    def setUp(self):
        import server_diff
        self.server = server_diff

    def test_waits_that_time_out_fail(self):
        with self.assertRaises(self.server.ProbeError):
            self.server.wait_until(FakeService(), lambda state: state["state"] == "stopped", 0.05, "stopped")
        with self.assertRaises(self.server.ProbeError):
            self.server.poll_job(FakeService(job_state="running"), "job", 0.05)
        self.assertEqual(self.server.wait_until(FakeService({"state": "stopped"}), lambda s: s["state"] == "stopped", 1, "stopped")["state"], "stopped")
        self.assertIn(b"done", self.server.poll_job(FakeService(job_state="done"), "job", 1))

    def test_admission_must_run_two_queue_four_and_refuse_the_seventh(self):
        good = [answer(b"202 Accepted", "running")] * 2 + [answer(b"202 Accepted", "queued")] * 4 + [answer(b"429 Too Many Requests")]
        self.assertEqual(self.server.admission_problems(good), [])
        self.assertTrue(self.server.admission_problems(good[:6] + [answer(b"202 Accepted", "queued")]))     # nothing refused
        self.assertTrue(self.server.admission_problems([answer(b"202 Accepted", "running")] * 6 + good[6:]))  # nothing queued
        self.assertTrue(self.server.admission_problems(good[:5]))
        self.assertTrue(self.server.admission_problems([b""] * 7))

    def test_the_ninth_connection_must_be_refused_by_a_full_pool(self):
        self.assertEqual(self.server.pool_problem(b"HTTP/1.1 503 Service Unavailable\r\n\r\n{}"), None)
        self.assertTrue(self.server.pool_problem(b"HTTP/1.1 200 OK\r\n\r\n{}"))
        self.assertTrue(self.server.pool_problem(b""))


class SchemaInvocationTests(unittest.TestCase):
    """Codex PRO-21 P2: schema_go validated whatever lines a run left, whatever its exit status; a crashed or
    timed-out invocation could pass with fewer (or no) lines."""

    def setUp(self):
        import schema_go
        self.schema = schema_go

    def test_finished_invocations_pass(self):
        problem = self.schema.invocation_problem
        self.assertIsNone(problem("analyze", completed(0, ['{"frame": 1}'])))
        self.assertIsNone(problem("analyze", completed(1, ['{"type": "capture_gap"}'], b"Capture error: Incomplete or failed PCAP\n")))
        self.assertIsNone(problem("live", completed(2, ['{"type": "summary", "capture_quality": "truncated"}'])))

    def test_crashed_or_unexplained_invocations_fail(self):
        problem = self.schema.invocation_problem
        self.assertIn("panic", problem("analyze", completed(2, ['{"frame": 1}'], b"panic: index out of range")))
        self.assertTrue(problem("analyze", completed(1, ['{"frame": 1}'], b"usage: protodetect analyze")))
        self.assertTrue(problem("analyze", completed(-11, [])))
        self.assertTrue(problem("analyze", completed(0, [], b"warning")))
        self.assertTrue(problem("live", completed(0, ['{"type": "classification"}'])))
        self.assertTrue(problem("live", completed(1, ['{"type": "summary", "capture_quality": "unverified"}'], b"boom")))

    def test_a_timed_out_invocation_is_a_problem_not_a_traceback(self):
        done, problem = self.schema.invoke("analyze", [sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.2)
        self.assertIsNone(done)
        self.assertIn("timed out", problem)
        done, problem = self.schema.invoke("analyze", [sys.executable, "-c", "print('{}')"], timeout=30)
        self.assertIsNone(problem)
        self.assertEqual(done.stdout.strip(), b"{}")


def record(app, basis, engine_status="identified"):
    return {"app": app, "engine_status": engine_status, "layers": {"application": {"basis": basis}}}


class AdversarialJudgeTests(unittest.TestCase):
    """Codex PRO-21 P2: the session judge skipped every check for an outcome record (so "identified yet unknown"
    was unreachable), passed an empty record list, and let a named application stand on a port hint, a content
    class or no basis at all."""

    def setUp(self):
        import adversarial
        self.judge = adversarial.judge

    def verdict(self, records, allowed=("ssl",)):
        return self.judge("session", set(allowed), {"records": records})

    def test_honest_sessions_pass(self):
        self.assertIsNone(self.verdict([record("ssl", "structural")]))
        self.assertIsNone(self.verdict([record("youtube", "client_assertion")], ("ssl", "youtube")))
        self.assertIsNone(self.verdict([record("unknown-tcp", "none", "unknown")]))
        self.assertIsNone(self.verdict([record("not-applicable", "none", "invalidated")]))

    def test_identified_yet_unknown_is_caught(self):
        self.assertIn("identified yet unknown", self.verdict([record("unknown-tcp", "none", "identified")]))
        self.assertIn("identified yet unknown", self.verdict([record("unknown-udp", "none", "identified")]))

    def test_an_outcome_must_not_claim_identity_evidence(self):
        self.assertIn("basis structural", self.verdict([record("unknown-tcp", "structural", "unknown")]))

    def test_an_empty_record_list_fails(self):
        self.assertIn("no session record", self.verdict([]))

    def test_a_named_application_needs_structural_or_asserted_evidence(self):
        for basis in ("port_hint", "content_class", None, "heuristic"):
            self.assertIn("application basis {}".format(basis), self.verdict([record("ssl", basis)]), basis)
        self.assertIn("session app web-browsing", self.verdict([record("web-browsing", "structural")]))


if __name__ == "__main__":
    unittest.main()
