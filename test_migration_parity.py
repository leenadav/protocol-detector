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
                self.assertEqual([item["id"] for item in report["mismatched"]], [touched])
                self.assertEqual(report["matched"], len(self.doc["cases"]) - 1)

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


if __name__ == "__main__":
    unittest.main()
