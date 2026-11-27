"""Verify that every security requirement in SECURITY-REQUIREMENTS.md names a test.

Each requirement row has an identifier (SR-n) and a verification column that must reference existing tests. The
gate fails on a requirement without an executable check or on a reference that no longer exists.

Reference forms (comma-separated in the last column):
  go/<package dir>::TestName   a top-level Go test or fuzz function in a *_test.go file of that package directory
                               (PRO-403: the Go engine is the product, so its tests verify the requirements)
  <dir>/test_<name>::test_<name>
                               a unittest test method in a Python test module (path without .py); both the module
                               and the method must be named test_*, so a helper `def` or a bare module never counts
                               (SEC-PYRM-2, PRO-546)

`--run` also runs every referenced test and fails unless each one passes: every Go test with `go test -run '^(...)$'
-v` per package (offline and vendored, with the pinned toolchain), and every Python test method in a fresh
interpreter per module (the module's folder and its parents up to the repository root on sys.path). A Python test
that is skipped (including a class-level skipUnless), an expected failure, an unexpected success, a failure, an
error, an import error, or a name that loads no TestCase method never verifies a requirement. `--self-test` checks
the parser, the checks and the Python runner on scratch trees.
"""
import argparse
import contextlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROW = re.compile(r"^\|\s*(SR-\d+)\s*\|(.*)\|\s*`([^`]+)`\s*\|\s*$")
GO_FUNC = r"^func {}\(\w+ \*testing\.[TF]\)"
PY_MODULE = re.compile(r"^(?:[A-Za-z0-9_.-]+/)*test_\w+$")
PY_TEST = re.compile(r"^test_\w+$")
PY_TIMEOUT = 900
RESULT = re.compile(r"^\s*--- (PASS|FAIL|SKIP): (\w+) ")


def rows(text):
    found = [ROW.match(line) for line in text.splitlines()]
    return [match for match in found if match]


def references(match):
    for item in match.group(3).split(","):
        module, _, function = item.strip().partition("::")
        yield module, function


def check_go(root, package, function):
    """None when go/<package> has `function` as a top-level test, else the failure text."""
    folder = root / package
    if not folder.is_dir() or not function:
        return "missing Go package {}".format(package) if not folder.is_dir() else "Go reference {} names no test".format(package)
    if not re.match(r"(Test|Fuzz)[A-Z0-9_]", function):
        return "Go reference {}::{} is not a test or fuzz function".format(package, function)
    pattern = re.compile(GO_FUNC.format(re.escape(function)), re.M)
    for path in sorted(folder.glob("*_test.go")):
        if pattern.search(path.read_text(encoding="utf-8")):
            return None
    return "missing Go test {} in {}".format(function, package)


def check_python(root, module, function):
    """None when module is a test_* file defining test method `function` (test_*), else the failure text."""
    if not PY_MODULE.match(module) or ".." in module.split("/"):
        return "Python reference {} is not a test_* module".format(module)
    if not function:
        return "Python reference {} names no test (use {}::test_name)".format(module, module)
    if not PY_TEST.match(function):
        return "Python reference {}::{} is not a test_* method".format(module, function)
    path = root / (module + ".py")
    if not path.is_file():
        return "missing test module {}".format(module)
    if not re.search(r"^[ \t]+def {}\(self\b".format(re.escape(function)), path.read_text(encoding="utf-8"), re.M):
        return "missing test {} in {}".format(function, module)
    return None


def check(root):
    """(row count, failure lines, {go package: test names}, {python module: test names}) for root's requirements."""
    text = (root / "SECURITY-REQUIREMENTS.md").read_text(encoding="utf-8")
    matches = rows(text)
    failures, go_tests, python_tests = [], {}, {}
    if not matches:
        return 0, ["no requirements found"], go_tests, python_tests
    for match in matches:
        identifier = match.group(1)
        for module, function in references(match):
            if module.startswith("go/"):
                problem = check_go(root, module, function)
                if problem is None:
                    go_tests.setdefault(module, set()).add(function)
            else:
                problem = check_python(root, module, function)
                if problem is None:
                    python_tests.setdefault(module, set()).add(function)
            if problem:
                failures.append("{}: {}".format(identifier, problem))
    return len(matches), failures, go_tests, python_tests


def go_toolchain(root):
    text = (root / "go" / "go.mod").read_text(encoding="utf-8")
    match = re.search(r"^toolchain (go\S+)$", text, re.M) or re.search(r"^go (\S+)$", text, re.M)
    return match.group(1) if match.group(1).startswith("go") else "go" + match.group(1)


def run_go(root, go_tests):
    """Failure lines for referenced Go tests that do not PASS when run."""
    failures = []
    env = dict(os.environ, GOTOOLCHAIN=go_toolchain(root), GOFLAGS="-mod=vendor", GOPROXY="off")
    for package in sorted(go_tests):
        names = sorted(go_tests[package])
        relative = "./" + package[len("go/"):]
        command = ["go", "test", "-count=1", "-v", "-run", "^(" + "|".join(names) + ")$", relative]
        done = subprocess.run(command, cwd=str(root / "go"), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,  # noqa: S603
                              text=True, check=False)
        outcome = {}
        for line in done.stdout.splitlines():
            result = RESULT.match(line)
            if result:
                outcome.setdefault(result.group(2), result.group(1))
        for name in names:
            if outcome.get(name) != "PASS":
                failures.append("{}::{}: {}".format(package, name, (outcome.get(name) or "did not run").lower()))
        print("go {}: {} referenced, {} passed".format(package, len(names), sum(1 for name in names if outcome.get(name) == "PASS")))
    return failures


def python_worker(root, module, output, names):
    """Run the named test methods of one Python test module (in this fresh interpreter); write outcomes as JSON.

    The outcome of a name is "pass" only when at least one TestCase method of that name ran and every one of them
    passed with nothing skipped, expected to fail or unexpectedly passing.
    """
    root = Path(root).resolve()
    path = root / (module + ".py")
    folder = path.parent
    folders = [folder] + [parent for parent in folder.parents if parent == root or root in parent.parents]
    for entry in reversed(folders):
        sys.path.insert(0, str(entry))
    outcomes = {}
    try:
        spec = importlib.util.spec_from_file_location(path.stem, str(path))
        loaded = importlib.util.module_from_spec(spec)
        sys.modules[path.stem] = loaded
        spec.loader.exec_module(loaded)
        cases = []
        pending = [unittest.defaultTestLoader.loadTestsFromModule(loaded)]
        while pending:
            item = pending.pop()
            if isinstance(item, unittest.TestSuite):
                pending.extend(item)
            elif isinstance(item, unittest.TestCase):
                cases.append(item)
    except BaseException as error:  # noqa: BLE001 - any import failure means no referenced test ran
        cases = None
        detail = "import error: {}".format(type(error).__name__)
    for name in names:
        if cases is None:
            outcomes[name] = detail
            continue
        selected = [case for case in cases if case._testMethodName == name]
        if not selected:
            outcomes[name] = "did not run"
            continue
        result = unittest.TestResult()
        unittest.TestSuite(sorted(selected, key=lambda case: case.id())).run(result)
        if result.errors:
            outcomes[name] = "error"
        elif result.failures:
            outcomes[name] = "fail"
        elif result.skipped:
            outcomes[name] = "skip"
        elif result.expectedFailures:
            outcomes[name] = "expected failure"
        elif result.unexpectedSuccesses:
            outcomes[name] = "unexpected success"
        elif result.testsRun < len(selected):
            outcomes[name] = "did not run"
        else:
            outcomes[name] = "pass"
    Path(output).write_text(json.dumps(outcomes), encoding="utf-8")
    return 0


def run_python(root, python_tests):
    """Failure lines for referenced Python test methods that do not pass, one fresh interpreter per module."""
    failures = []
    for module in sorted(python_tests):
        names = sorted(python_tests[module])
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "outcomes.json"
            command = [sys.executable, "-B", str(Path(__file__).resolve()), "--python-worker", str(root), module,
                       str(output)] + names
            try:
                subprocess.run(command, cwd=str(root), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,  # noqa: S603
                               timeout=PY_TIMEOUT, check=False)
            except subprocess.TimeoutExpired:
                pass
            try:
                outcome = json.loads(output.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                outcome = {}
        for name in names:
            if outcome.get(name) != "pass":
                failures.append("{}::{}: {}".format(module, name, outcome.get(name) or "did not run"))
        print("python {}: {} referenced, {} passed".format(module, len(names), sum(1 for name in names if outcome.get(name) == "pass")))
    return failures


PY_FIXTURE = """import unittest


def helper():
    pass


def test_top_level():
    pass


class Demo(unittest.TestCase):
    def test_pass(self):
        pass

    def test_skip(self):
        self.skipTest("no")

    def test_fail(self):
        self.fail("no")

    def test_error(self):
        raise RuntimeError("no")

    def test_subtest_skip(self):
        with self.subTest(case=1):
            self.skipTest("no")

    @unittest.expectedFailure
    def test_expected_failure(self):
        self.fail("no")


@unittest.skip("whole class")
class Skipped(unittest.TestCase):
    def test_skipped_class(self):
        pass
"""


def self_test_python_run():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "pkg").mkdir()
        (root / "pkg" / "test_demo.py").write_text(PY_FIXTURE, encoding="utf-8")
        (root / "pkg" / "test_broken.py").write_text("import absent_module_for_the_self_test\n", encoding="utf-8")
        names = ["test_pass", "test_skip", "test_fail", "test_error", "test_subtest_skip", "test_expected_failure",
                 "test_skipped_class", "test_top_level", "test_absent"]
        with contextlib.redirect_stdout(io.StringIO()):
            failures = run_python(root, {"pkg/test_demo": set(names), "pkg/test_broken": {"test_pass"}})
        expected = {
            "pkg/test_broken::test_pass: import error: ModuleNotFoundError",
            "pkg/test_demo::test_skip: skip", "pkg/test_demo::test_fail: fail", "pkg/test_demo::test_error: error",
            "pkg/test_demo::test_subtest_skip: skip", "pkg/test_demo::test_expected_failure: expected failure",
            "pkg/test_demo::test_skipped_class: skip", "pkg/test_demo::test_top_level: did not run",
            "pkg/test_demo::test_absent: did not run",
        }
        assert set(failures) == expected, sorted(set(failures) ^ expected)


def self_test():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "go" / "internal" / "demo").mkdir(parents=True)
        (root / "go" / "internal" / "demo" / "demo_test.go").write_text(
            "package demo\n\nfunc TestGuard(t *testing.T) {}\nfunc FuzzGuard(f *testing.F) {}\nfunc helper(t *testing.T) {}\n"
            "func TestGuardAndMore(t *testing.T) {}\n", encoding="utf-8")
        (root / "test_demo.py").write_text("import unittest\n\n\nclass T(unittest.TestCase):\n    def test_guard(self):\n"
                                           "        pass\n\n\ndef helper_guard():\n    pass\n", encoding="utf-8")
        (root / "tools").mkdir()
        (root / "tools" / "demo.py").write_text("def test_guard():\n    pass\n", encoding="utf-8")
        table = "| ID | Requirement | Verified by |\n|---|---|---|\n| SR-1 | guard | `{}` |\n"
        cases = {
            "go test": ("go/internal/demo::TestGuard", 0),
            "go fuzz": ("go/internal/demo::FuzzGuard", 0),
            "python test": ("test_demo::test_guard", 0),
            "missing go test": ("go/internal/demo::TestAbsent", 1),
            "prefix only is not a test": ("go/internal/demo::TestGuar", 1),
            "helper is not a test": ("go/internal/demo::helper", 1),
            "missing go package": ("go/internal/absent::TestGuard", 1),
            "go package without a test name": ("go/internal/demo", 1),
            "missing python module": ("test_absent::test_guard", 1),
            "bare python module": ("test_demo", 1),
            "python helper is not a test": ("test_demo::helper_guard", 1),
            "python test prefix only": ("test_demo::test_guar", 1),
            "python module not named test_*": ("tools/demo::test_guard", 1),
            "python parent escape": ("../test_demo::test_guard", 1),
            "several, one missing": ("go/internal/demo::TestGuard, go/internal/demo::TestNope", 1),
        }
        for name, (reference, expected) in cases.items():
            (root / "SECURITY-REQUIREMENTS.md").write_text(table.format(reference), encoding="utf-8")
            count, failures, _, _ = check(root)
            assert count == 1 and len(failures) == expected, (name, failures)
        (root / "SECURITY-REQUIREMENTS.md").write_text("no table\n", encoding="utf-8")
        assert check(root)[1] == ["no requirements found"]
    assert RESULT.match("    --- SKIP: TestGuard (0.00s)").groups() == ("SKIP", "TestGuard")
    self_test_python_run()
    print("check_security_requirements self-test: ok")
    return 0


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run", action="store_true", help="also run every referenced Go and Python test; each must pass")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--python-worker", nargs="+", metavar="ARG", help=argparse.SUPPRESS)
    args = parser.parse_args(arguments)
    if args.python_worker:
        if len(args.python_worker) < 4:
            parser.error("--python-worker needs ROOT MODULE OUTPUT NAME...")
        root, module, output = args.python_worker[:3]
        return python_worker(root, module, output, args.python_worker[3:])
    if args.self_test:
        return self_test()
    root = Path.cwd()
    count, failures, go_tests, python_tests = check(root)
    for line in failures:
        print(line)
    if args.run and not failures:
        failures += run_go(root, go_tests) + run_python(root, python_tests)
        for line in failures:
            print(line)
    referenced = sum(len(names) for names in go_tests.values())
    python_referenced = sum(len(names) for names in python_tests.values())
    print("security requirements: {} rows, {} Go tests in {} packages and {} Python tests in {} modules referenced{}, "
          "{} failures".format(count, referenced, len(go_tests), python_referenced, len(python_tests),
                               " and run" if args.run else "", len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
