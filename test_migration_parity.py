"""Migration M1: the differential harness is sound (python-vs-python zero diffs, planted regressions detected)."""
import json
import unittest
from pathlib import Path

from migration.parity import cases as parity_cases
from migration.parity import compare

CASES = Path(__file__).resolve().parent / "migration" / "fixtures" / "cases.json"


class ParityHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = json.loads(CASES.read_text(encoding="utf-8"))
        cls.results = compare.run_backend("python", cls.doc)

    def test_committed_cases_match_the_python_reference(self):
        report = compare.compare(self.doc, self.results)
        self.assertEqual(report["mismatched"][:3], [])
        self.assertEqual((report["missing"], report["extra"], report["exempted"]), ([], [], 0))
        self.assertEqual(report["matched"], len(self.doc["cases"]))
        self.assertGreater(report["matched"], 1000)

    def test_committed_inputs_are_current(self):
        """The fixture tables changed → regenerate migration/fixtures/cases.json (python3 -B migration/parity/cases.py)."""
        strip = lambda case: {k: v for k, v in case.items() if k != "expected"}  # noqa: E731
        self.assertEqual([strip(c) for c in parity_cases.generate()], [strip(c) for c in self.doc["cases"]])

    def test_generation_is_deterministic(self):
        self.assertEqual(parity_cases.with_expectations(parity_cases.generate(limit=3)),
                         parity_cases.with_expectations(parity_cases.generate(limit=3)))

    def test_every_planted_regression_is_detected(self):
        for kind in compare.PLANTS:
            with self.subTest(plant=kind):
                planted, touched = compare.plant(self.results["results"], kind, self.doc)
                report = compare.compare(self.doc, {"results": planted})
                self.assertFalse(report["ok"])
                self.assertEqual([item["id"] for item in report["mismatched"] + report["unexpected_gaps"]], [touched])
                self.assertEqual(report["matched"], len(self.doc["cases"]) - 1)

    def test_unsupported_answers_need_an_exact_allowlist_entry(self):
        """Review R2 (2026-11-14): answering every case with a plausible unsupported reason passed the gate."""
        everything = {"results": {c["id"]: {"unsupported": "family http"} for c in self.doc["cases"]}}
        report = compare.compare(self.doc, everything, families=("http", "tls", "kerberos"))
        self.assertFalse(report["ok"])
        self.assertEqual(len(report["unexpected_gaps"]), len(self.doc["cases"]))
        self.assertEqual(report["claimed_without_match"], ["http", "kerberos", "tls"])
        first, second = self.doc["cases"][0]["id"], self.doc["cases"][1]["id"]
        results = dict(self.results["results"])
        results[first] = {"unsupported": "not ported: option x"}
        listed = compare.compare(self.doc, {"results": results}, gaps={first: "not ported: option x"})
        self.assertTrue(listed["ok"], listed["unexpected_gaps"])
        self.assertEqual((listed["unsupported"], listed["matched"]), (1, len(self.doc["cases"]) - 1))
        reworded = compare.compare(self.doc, {"results": results}, gaps={first: "not ported: option y"})
        self.assertEqual([item["id"] for item in reworded["unexpected_gaps"]], [first])
        self.assertFalse(reworded["ok"])
        stale = compare.compare(self.doc, {"results": results}, gaps={first: "not ported: option x", second: "not ported: option x",
                                                                      "stream/no-such-case": "x"})
        self.assertEqual([item["id"] for item in stale["stale_gaps"]], [second, "stream/no-such-case"])
        self.assertFalse(stale["ok"])

    def test_results_for_unknown_cases_fail(self):
        results = dict(self.results["results"])
        results["stream/not-a-case"] = results[self.doc["cases"][0]["id"]]
        report = compare.compare(self.doc, {"results": results})
        self.assertEqual(report["extra"], ["stream/not-a-case"])
        self.assertFalse(report["ok"])

    def test_committed_gap_list_names_existing_cases(self):
        gaps = compare.load_gaps(CASES.parent.parent / "parity" / "gaps.json")
        ids = {c["id"] for c in self.doc["cases"]}
        self.assertTrue(gaps)
        self.assertEqual(sorted(set(gaps) - ids), [])
        self.assertTrue(all(isinstance(reason, str) and reason for reason in gaps.values()))

    def test_outcome_coverage(self):
        statuses = {c["expected"].get("final", c["expected"].get("observation", {})).get("status") for c in self.doc["cases"] if c["kind"] != "session"}
        self.assertEqual(statuses, {"identified", "malformed", "incomplete", "unknown", "budget_exhausted"})
        engine = {r["engine_status"] for c in self.doc["cases"] if c["kind"] == "session" for r in c["expected"]["records"]}
        self.assertTrue({"identified", "invalidated", "incomplete", "no_handshake"} <= engine, engine)
        kinds = {e["kind"] for c in self.doc["cases"] if c["kind"] == "stream" for e in c["expected"]["events"]}
        self.assertEqual(kinds, {"updated", "refined", "shifted"})

    def test_deltas_name_a_case_and_a_justification(self):
        deltas = json.loads((CASES.parent.parent / "parity" / "deltas.json").read_text(encoding="utf-8"))
        ids = {c["id"] for c in self.doc["cases"]}
        for cid, items in deltas.items():
            self.assertIn(cid, ids)
            for item in items:
                self.assertTrue(item.get("path") and item.get("justification"), item)

    def test_go_config_ranges_equal_the_python_limits(self):
        """Review R4 (2026-11-14): both runtimes enforce one range table; each bound is probed on the Python Config."""
        import re
        from protocol_engine import Config
        source = (CASES.parent.parent.parent / "go" / "internal" / "contracts" / "contracts.go").read_text(encoding="utf-8")
        table = source[source.index("var ConfigRanges"):source.index("func (c Config) integer")]
        ranges = [(name, int(low), int(high)) for name, low, high in re.findall(r'\{"([a-z0-9_]+)", (\d+), (\d+)\}', table)]
        self.assertEqual(len(ranges), 9)

        def accepted(name, value):
            try:
                Config(**{name: value})
                return True
            except ValueError:
                return False

        for name, low, high in ranges:
            with self.subTest(option=name):
                self.assertEqual([accepted(name, value) for value in (low - 1, low, low + 1, high - 1, high, high + 1)],
                                 [False, True, True, True, True, False])
        integers = sorted(name for name, value in vars(Config()).items() if type(value) is int)
        self.assertEqual(sorted(name for name, _, _ in ranges), integers)


if __name__ == "__main__":
    unittest.main()
