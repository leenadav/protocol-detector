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

    def test_a_boolean_never_matches_a_number(self):
        """Codex PRO-14: Python equality has True == 1 and False == 0.0, so a backend that put a JSON boolean
        where the reference has a number (or the reverse) used to pass exact parity."""
        for expected, actual in ((1, True), (True, 1), (0, False), (False, 0.0), ({"n": [1]}, {"n": [True]})):
            with self.subTest(expected=expected, actual=actual):
                self.assertTrue(compare.diff(expected, actual))
        self.assertEqual(compare.diff({"n": [1, True, "x"]}, {"n": [1, True, "x"]}), [])

    def test_leaf_comparison_is_strict_on_json_type(self):
        """SEC-PAR-2: True, 1 and 1.0 are equal in Python, but a JSON boolean is never a number. 1 and 1.0 are the
        same JSON number (Go's encoder writes float64 40 as 40), so they still match."""
        for expected, actual in ((True, 1), (1, True), (True, 1.0), (1.0, True), (False, 0), (0.0, False),
                                 (None, False), (0, None), ("1", 1), ([], {}), ({"n": {"m": 2}}, {"n": {"m": True}})):
            with self.subTest(expected=expected, actual=actual):
                self.assertEqual(len(compare.diff(expected, actual)), 1)
        for expected, actual in ((1, 1.0), (40.0, 40), (0, 0.0), ({"n": [0.0]}, {"n": [0]})):
            with self.subTest(expected=expected, actual=actual):
                self.assertEqual(compare.diff(expected, actual), [])
        for same in (1, 1.5, True, False, None, "x", [1, 2.0, False], {"a": [0, 0.0]}):
            with self.subTest(same=same):
                self.assertEqual(compare.diff(same, json.loads(json.dumps(same))), [])

    def test_bool_to_int_plant_changes_one_boolean_leaf(self):
        planted, touched = compare.plant(self.results["results"], "bool-to-int", self.doc)
        found = compare.diff(self.results["results"][touched], planted[touched])
        self.assertEqual(len(found), 1)
        path, expected, actual = found[0]
        self.assertIs(type(expected), bool)
        self.assertIs(type(actual), int)
        self.assertEqual(expected, actual)  # equal under Python ==, so only the type check catches it

    def test_committed_gap_list_names_existing_cases(self):
        gaps = compare.load_gaps(CASES.parent.parent / "parity" / "gaps.json")
        ids = {c["id"] for c in self.doc["cases"]}
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

    def test_pinned_go_only_deltas_expect_exactly_the_recorded_value(self):
        """PRO-260: a delta with `go` exempts its subtree only while the backend gives exactly that value."""
        deltas = json.loads((CASES.parent.parent / "parity" / "deltas.json").read_text(encoding="utf-8"))
        pinned = {cid: items for cid, items in deltas.items() if any("go" in item for item in items)}
        self.assertEqual(len(pinned), 18)                       # 3 hybrids, short, bad point, HRR; x whole/bytes/sevens
        cases = [c for c in self.doc["cases"] if c["id"] in pinned]
        go = {"backend": "go", "results": {}}
        for case in cases:
            result = json.loads(json.dumps(self.results["results"][case["id"]]))
            for item in pinned[case["id"]]:
                self.assertNotEqual(compare.value_at(result, item["path"]), item["go"], case["id"])  # the reference differs
                if item["path"] == "$.final":
                    result["final"] = item["go"]
                else:
                    result["events"][0]["observation"] = item["go"]
            go["results"][case["id"]] = result
        doc = dict(self.doc, cases=cases)
        report = compare.compare(doc, go, deltas)
        self.assertEqual((report["matched"], report["mismatched"]), (18, []))
        self.assertGreater(report["exempted"], 0)
        # Any other Go value at a pinned path fails too.
        # A Go result that went back to the reference's answer fails: the difference is expected, not tolerated.
        reverted = {"backend": "go", "results": {c["id"]: self.results["results"][c["id"]] for c in cases}}
        self.assertEqual(len(compare.compare(doc, reverted, deltas)["mismatched"]), 18)
        # The reference itself is judged against the expectation alone.
        self.assertEqual(compare.compare(doc, dict(reverted, backend="python"), deltas)["matched"], 18)
        changed = json.loads(json.dumps(go))
        first = cases[0]["id"]
        changed["results"][first]["final"]["reason"] += "x"
        report = compare.compare(doc, changed, deltas)
        self.assertEqual([m["id"] for m in report["mismatched"]], [first])
        self.assertEqual(compare.value_at({"a": [{"b": 1}]}, "$.a[0].b"), 1)
        self.assertEqual(compare.value_at({"a": []}, "$.a[0]"), "<absent>")

    def test_pinned_go_values_are_the_reference_under_the_pro260_model(self):
        """PRO-260: the pinned values are not hand-written: the reference under migration/parity/pro260.py gives
        exactly them, and changes no other TLS or DTLS case."""
        import sys
        sys.path.insert(0, str(CASES.parent.parent / "parity"))
        import pro260
        deltas = json.loads((CASES.parent.parent / "parity" / "deltas.json").read_text(encoding="utf-8"))
        pinned = {cid: items for cid, items in deltas.items() if any("go" in item for item in items)}
        tls = [c for c in self.doc["cases"] if (c.get("label") or "").split("/")[0] in ("tls", "dtls")]
        with pro260.with_hybrid_groups():
            model = {c["id"]: parity_cases.run_case(c) for c in tls}
        changed = sorted(c["id"] for c in tls if compare.diff(c["expected"], model[c["id"]]))
        self.assertEqual(changed, sorted(pinned))
        for cid, items in pinned.items():
            for item in items:
                self.assertEqual(compare.value_at(model[cid], item["path"]), item["go"], (cid, item["path"]))

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

    def test_go_udp_hints_equal_the_python_validators(self):
        """The Go DatagramHints table is the Python VALIDATORS table: no valid hint refused, no invalid one accepted."""
        import re
        from protocol_engine.datagram import VALIDATORS
        source = (CASES.parent.parent.parent / "go" / "internal" / "engine" / "datagram.go").read_text(encoding="utf-8")
        table = source[source.index("var DatagramHints"):source.index("func sipProbe")]
        self.assertEqual(sorted(re.findall(r'"([a-z0-9-]+)": true', table)), sorted(VALIDATORS))

    def test_go_compat_families_equal_the_python_tcp_families(self):
        """The legacy per-family table in Go analyze messages lists the Python TCP_FAMILIES in the same order."""
        import re
        from protocol_adapters.sessions import TCP_FAMILIES
        source = (CASES.parent.parent.parent / "go" / "internal" / "analyzer" / "analyzer.go").read_text(encoding="utf-8")
        table = source[source.index("var compatFamilies"):source.index("var textCandidates")]
        self.assertEqual(re.findall(r'"([a-z0-9-]+)"', table), list(TCP_FAMILIES))

    def test_go_embedded_content_pack_is_the_shared_pack(self):
        shared = CASES.parent / "content.json"
        embedded = CASES.parent.parent.parent / "go" / "internal" / "content" / "pack.json"
        self.assertEqual(shared.read_bytes(), embedded.read_bytes(), "copy migration/fixtures/content.json to go/internal/content/pack.json")


if __name__ == "__main__":
    unittest.main()
