"""Run a unittest suite where a skipped test fails the run unless it is named in an allow-list.

`python -m unittest` exits 0 with `OK (skipped=N)`, so a suite whose prerequisites are missing
(no Node, no Playwright with a Chromium, no optional extra) reads as a pass. CI and release gates
call this instead: a skip passes only when its test id is given with --allow-skip, and the reason
is printed, so every skip that is accepted is named in the workflow that accepts it. A suite that
discovers no test, or a test id given with --allow-skip that the suite does not contain (a renamed
test would otherwise widen the allow-list silently), also fails. Failures, errors and unexpected
successes fail as usual. Standard library only, Python 3.9 syntax. Usage:
  run_tests_strict.py [--cwd DIR] [--start DIR] [--top DIR] [--allow-skip TEST_ID ...] [--summary FILE]
  run_tests_strict.py --self-test
Discovery matches `cd DIR && python -m unittest discover -s START [-t TOP]`: DIR is put first on
sys.path, START defaults to `.` and TOP to START.
"""
import argparse
import os
import sys
import tempfile
import unittest
from pathlib import Path


def iter_ids(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from iter_ids(item)
        else:
            yield item.id()


def decide(result, discovered, allowed):
    """The problems with a finished run, empty when it may count as a pass."""
    problems = []
    if not discovered:
        problems.append("no test was discovered")
    for test, _ in result.failures + result.errors:
        problems.append("failed: " + test.id())
    for test in result.unexpectedSuccesses:
        problems.append("unexpected success: " + test.id())
    for test, reason in result.skipped:
        if test.id() not in allowed:
            problems.append("skipped without an allow-list entry: {} ({})".format(test.id(), reason))
    for name in sorted(set(allowed) - set(discovered)):
        problems.append("--allow-skip names a test the suite does not contain: " + name)
    return problems


def run(cwd, start, top, allowed, stream):
    os.chdir(cwd)
    sys.path.insert(0, os.getcwd())
    suite = unittest.defaultTestLoader.discover(start, top_level_dir=top or start)
    discovered = list(iter_ids(suite))
    result = unittest.TextTestRunner(stream=stream, verbosity=1).run(suite)
    return result, discovered, decide(result, discovered, allowed)


def report(result, discovered, allowed, problems):
    lines = ["{} tests discovered, {} run, {} skipped".format(len(discovered), result.testsRun, len(result.skipped))]
    for test, reason in result.skipped:
        lines.append("  skipped{}: {} ({})".format(" (allowed)" if test.id() in allowed else "", test.id(), reason))
    lines.extend("  " + problem for problem in problems)
    lines.append("strict test run: " + ("ok" if not problems else "FAILED, {} problem(s)".format(len(problems))))
    return lines


def self_test():
    tree = tempfile.mkdtemp(prefix="strict-self-test-")
    tests = Path(tree, "tests")
    tests.mkdir()

    def problems_of(body, allowed=()):
        (tests / "test_case.py").write_text("import unittest\n\n\nclass Case(unittest.TestCase):\n" + body, encoding="utf-8")
        sys.modules.pop("test_case", None)
        with open(os.devnull, "w", encoding="utf-8") as sink:
            return run(tree, "tests", None, set(allowed), sink)[2]

    skipped_ui = "    @unittest.skip('no node')\n    def test_ui(self):\n        pass\n"
    here = os.getcwd()
    try:
        assert problems_of("    def test_ok(self):\n        pass\n") == []
        assert any("skipped without" in p for p in problems_of(skipped_ui))
        assert problems_of(skipped_ui, ["test_case.Case.test_ui"]) == []
        assert any("does not contain" in p for p in problems_of("    def test_other(self):\n        pass\n", ["test_case.Case.test_ui"]))
        assert any(p.startswith("failed:") for p in problems_of("    def test_bad(self):\n        self.fail('x')\n"))
        assert any(p.startswith("failed:") for p in problems_of("    def test_err(self):\n        raise RuntimeError('x')\n"))
        assert any("unexpected success" in p for p in problems_of("    @unittest.expectedFailure\n    def test_u(self):\n        pass\n"))
        assert problems_of("    @unittest.expectedFailure\n    def test_x(self):\n        self.fail('known')\n") == []
        (tests / "test_case.py").unlink()
        with open(os.devnull, "w", encoding="utf-8") as sink:
            assert run(tree, "tests", None, set(), sink)[2] == ["no test was discovered"]
    finally:
        os.chdir(here)
    print("run_tests_strict self-test: ok")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cwd", default=".")
    parser.add_argument("--start", default=".")
    parser.add_argument("--top")
    parser.add_argument("--allow-skip", action="append", default=[], metavar="TEST_ID")
    parser.add_argument("--summary", help="append the report to this file (e.g. $GITHUB_STEP_SUMMARY)")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    summary = os.path.abspath(args.summary) if args.summary else None
    result, discovered, problems = run(args.cwd, args.start, args.top, set(args.allow_skip), sys.stderr)
    lines = report(result, discovered, set(args.allow_skip), problems)
    print("\n".join(lines))
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
