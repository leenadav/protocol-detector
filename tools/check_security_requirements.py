"""Verify that every security requirement in SECURITY-REQUIREMENTS.md names a test, and that none disappears.

    check_security_requirements.py                         check the table against the lock (CI, make requirements)
    check_security_requirements.py --run                   also run every referenced Go and Python test; each must pass
    check_security_requirements.py --write-lock [--retire SR-n ...]
                                                           pin the table's id set in the lock
    check_security_requirements.py --self-test

Each requirement row has an identifier (SR-n) and a verification column that must reference existing tests.
Reference forms (comma-separated in the last column):
  go/<package dir>::TestName   a top-level Go test or fuzz function in a *_test.go file of that package directory
                               (PRO-403: the Go engine is the product, so its tests verify the requirements)
  <dir>/test_<name>::test_<name>
                               a unittest test method in a Python test module (path without .py); both the module
                               and the method must be named test_*, so a helper `def` or a bare module never counts
                               (SEC-PYRM-2, PRO-546)

The gate fails (SEC-PYRM-1) on:
- any table line (a line holding `|`) other than the header and separators that does not parse as
  `| SR-n | requirement | `refs` |` (free text, "manual review", prose after the closing backtick, a missing
  cell, `SR-07`; and, SEC-PYRM-10, no leading pipe, a Cyrillic or fullwidth look-alike id, a non-ASCII space),
  or a pipe-less line starting with an id-like token: such a row used to be dropped silently, so its
  requirement lost its evidence while the gate stayed green;
- an empty reference item, a missing Go package or test, a Go name that is not a top-level test or fuzz function,
  a Python reference that is not `test_*::test_*` (a bare module, a helper, a `..` path), a missing Python test
  module or a missing test method;
- a duplicate id (two rows claiming one requirement number);
- an id set that differs from tools/security_requirements.lock.json: a deleted row (an id in the lock that the
  table lacks), an unpinned new row (an id the lock lacks: run --write-lock and commit the lock with the row), or
  a retired id that is back in the table.

--write-lock pins the table's ids. It refuses to drop a pinned id unless that id is named with --retire, which
moves it to the lock's `retired` list for good, so removing a requirement is always a visible, reviewed change to
the lock and a retired number is never reused.

`--run` also runs every referenced test and fails unless each one passes: every Go test with `go test -run '^(...)$'
-v` per package (offline and vendored, with the pinned toolchain), and every Python test method in a fresh
interpreter per module (the module's folder and its parents up to the repository root on sys.path). A Go test that
is skipped, missing at run time or failing, and a Python test that is skipped (including a class-level skipUnless),
an expected failure, an unexpected success, a failure, an error, an import error, or a name that loads no TestCase
method never verifies a requirement. It runs only when the static checks pass.
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
import unicodedata
from pathlib import Path

TABLE = "SECURITY-REQUIREMENTS.md"
LOCK = "tools/security_requirements.lock.json"

# Fail closed (SEC-PYRM-1, SEC-PYRM-10): every line holding a `|` is a table line and must be the header, a
# separator or a strict requirement row, whatever its first cell says; a row without its leading pipe, with a
# look-alike id (Cyrillic or fullwidth letters) or with a non-ASCII space is reported, never skipped. A line
# without a `|` that starts with an id-like token (two letters, a dash, a digit, after NFKC) is a broken row too.
HEADER = re.compile(r"^\|[ \t]*ID[ \t]*\|[ \t]*Requirement[ \t]*\|[ \t]*Verified by[ \t]*\|[ \t]*$")
SEPARATOR = re.compile(r"^\|(?:[ \t]*:?-{3,}:?[ \t]*\|)+[ \t]*$")
ROW = re.compile(r"^\|[ \t]*(SR-[1-9][0-9]*)[ \t]*\|(.*)\|[ \t]*`([^`]+)`[ \t]*\|[ \t]*$")
ID_LIKE = re.compile(r"^\W*[^\W\d_]{2}\s*[-\u2010-\u2015\u2212\ufe63\uff0d]\s*\d")
ITEM = re.compile(r"^[A-Za-z0-9_./-]+(?:::[A-Za-z_]\w*)?$")
GO_FUNC = r"^func {}\(\w+ \*testing\.[TF]\)"
PY_MODULE = re.compile(r"^(?:[A-Za-z0-9_.-]+/)*test_\w+$")
PY_TEST = re.compile(r"^test_\w+$")
PY_TIMEOUT = 900
RESULT = re.compile(r"^\s*--- (PASS|FAIL|SKIP): (\w+) ")


def id_key(identifier):
    return int(identifier.split("-", 1)[1])


def parse(text):
    """Return (rows, failures): rows are (line number, id, reference); failures are messages."""
    rows, failures = [], []
    for number, line in enumerate(text.splitlines(), 1):
        if "|" not in line:
            if ID_LIKE.match(unicodedata.normalize("NFKC", line)):
                failures.append("line {}: unparsable requirement row (no table cells): {}".format(
                    number, line.strip()[:80]))
            continue
        if HEADER.match(line) or SEPARATOR.match(line):
            continue
        match = ROW.match(line)
        if not match:
            failures.append("line {}: unparsable requirement row (expected `| SR-n | requirement | `module::test[, "
                            "...]` |`): {}".format(number, line.strip()[:80]))
            continue
        identifier, _, reference = match.groups()
        rows.append((number, identifier, reference))
    return rows, failures


def check_go(root, package, function):
    """None when go/<package> has `function` as a top-level test or fuzz function, else the failure text."""
    folder = root / package
    if not folder.is_dir():
        return "missing Go package {}".format(package)
    if not function:
        return "Go reference {} names no test".format(package)
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


def check_references(root, rows, go_tests, python_tests):
    """Failure lines; every valid reference is added to go_tests or python_tests ({package or module: test names})."""
    failures = []
    for _, identifier, reference in rows:
        for item in reference.split(","):
            item = item.strip()
            if not ITEM.match(item):
                failures.append("{}: malformed test reference {!r}".format(identifier, item))
                continue
            module, _, function = item.partition("::")
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
    return failures


def check_duplicates(rows):
    seen, failures = {}, []
    for number, identifier, _ in rows:
        if identifier in seen:
            failures.append("{}: duplicate id on lines {} and {}".format(identifier, seen[identifier], number))
        else:
            seen[identifier] = number
    return failures


def read_lock(root):
    path = root / LOCK
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return None, ["{}: unreadable lock ({}); run --write-lock".format(LOCK, error)]
    ids, retired = data.get("ids"), data.get("retired", [])
    if not isinstance(ids, list) or not isinstance(retired, list):
        return None, ["{}: `ids` and `retired` must be lists".format(LOCK)]
    return (set(ids), set(retired)), []


def check_lock(root, rows):
    lock, failures = read_lock(root)
    if lock is None:
        return failures
    pinned, retired = lock
    present = {identifier for _, identifier, _ in rows}
    for identifier in sorted(pinned - present, key=id_key):
        failures.append("{}: pinned in {} but missing from {} (deleted or renumbered row; retire it with "
                        "--write-lock --retire {})".format(identifier, LOCK, TABLE, identifier))
    for identifier in sorted(present - pinned - retired, key=id_key):
        failures.append("{}: not pinned in {}; run --write-lock and commit the lock with the row".format(
            identifier, LOCK))
    for identifier in sorted(present & retired, key=id_key):
        failures.append("{}: retired in {}; a retired id is never reused".format(identifier, LOCK))
    return failures


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
        done = subprocess.run(command, cwd=str(root / "go"), env=env, stdout=subprocess.PIPE,  # noqa: S603
                              stderr=subprocess.STDOUT, text=True, check=False)
        outcome = {}
        for line in done.stdout.splitlines():
            result = RESULT.match(line)
            if result:
                outcome.setdefault(result.group(2), result.group(1))
        for name in names:
            if outcome.get(name) != "PASS":
                failures.append("{}::{}: {}".format(package, name, (outcome.get(name) or "did not run").lower()))
        print("go {}: {} referenced, {} passed".format(
            package, len(names), sum(1 for name in names if outcome.get(name) == "PASS")))
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
    outcomes, cases, detail = {}, None, None
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
    except Exception as error:  # noqa: BLE001 - any import failure means no referenced test ran
        # A SystemExit or KeyboardInterrupt ends this worker without writing outcomes: "did not run", also a failure.
        cases, detail = None, "import error: {}".format(type(error).__name__)
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
            fallback = "did not run"
            try:
                subprocess.run(command, cwd=str(root), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,  # noqa: S603
                               timeout=PY_TIMEOUT, check=False)
            except subprocess.TimeoutExpired:
                fallback = "timed out after {} s".format(PY_TIMEOUT)
            try:
                outcome = json.loads(output.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                outcome = {}  # the worker wrote no outcomes: every name fails with the fallback below
        for name in names:
            if outcome.get(name) != "pass":
                failures.append("{}::{}: {}".format(module, name, outcome.get(name) or fallback))
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


def check(root, run=False):
    path = root / TABLE
    rows, failures = parse(path.read_text(encoding="utf-8"))
    if not rows and not failures:
        print("no requirements found")
        return 1
    go_tests, python_tests = {}, {}
    failures += check_duplicates(rows)
    failures += check_references(root, rows, go_tests, python_tests)
    failures += check_lock(root, rows)
    for failure in failures:
        print(failure)
    if run and not failures:
        ran = run_go(root, go_tests) + run_python(root, python_tests)
        for failure in ran:
            print(failure)
        failures += ran
    referenced = sum(len(names) for names in go_tests.values())
    python_referenced = sum(len(names) for names in python_tests.values())
    print("security requirements: {} rows, {} Go tests in {} packages and {} Python tests in {} modules referenced{}, "
          "{} failures".format(len(rows), referenced, len(go_tests), python_referenced, len(python_tests),
                               " and run" if run else "", len(failures)))
    return 1 if failures else 0


def write_lock(root, retire):
    rows, failures = parse((root / TABLE).read_text(encoding="utf-8"))
    failures += check_duplicates(rows)
    if failures:
        for failure in failures:
            print(failure)
        print("lock not written: fix the table first")
        return 1
    present = {identifier for _, identifier, _ in rows}
    old_ids, old_retired = set(), set()
    if (root / LOCK).exists():
        lock, errors = read_lock(root)
        if lock is None:
            for error in errors:
                print(error)
            return 1
        old_ids, old_retired = lock
    retire = set(retire)
    problems = []
    for identifier in sorted(retire & present, key=id_key):
        problems.append("{}: still in {}; remove the row before retiring it".format(identifier, TABLE))
    for identifier in sorted(retire - old_ids, key=id_key):
        problems.append("{}: not pinned, nothing to retire".format(identifier))
    for identifier in sorted(old_ids - present - retire, key=id_key):
        problems.append("{}: pinned but missing from {}; restore the row or pass --retire {}".format(
            identifier, TABLE, identifier))
    for identifier in sorted(present & old_retired, key=id_key):
        problems.append("{}: retired; a retired id is never reused".format(identifier))
    if problems:
        for problem in problems:
            print(problem)
        print("lock not written")
        return 1
    data = {
        "comment": "Pinned SR ids of {}; written by tools/check_security_requirements.py --write-lock.".format(TABLE),
        "ids": sorted(present, key=id_key),
        "retired": sorted(old_retired | retire, key=id_key),
    }
    (root / LOCK).write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
    print("{}: {} ids pinned, {} retired".format(LOCK, len(data["ids"]), len(data["retired"])))
    return 0


def self_test():
    header = "| ID | Requirement | Verified by |\n|---|---|---|\n"
    good = "| SR-1 | A | `tests/test_a::test_one` |\n| SR-2 | B `x` | `tests/test_a::test_one, tests/test_a::test_two` |\n"
    cases = [
        # (name, table body, lock ids or None for "as written", lock retired, expected rc, expected substring)
        ("valid", good, None, [], 0, "2 rows, 0 Go tests in 0 packages and 2 Python tests in 1 modules referenced, 0 failures"),
        ("free text", good + "| SR-3 | C | manual review |\n", None, [], 1, "line 5: unparsable"),
        ("prose after backtick", good + "| SR-3 | C | `tests/test_a::test_one` and more |\n", None, [], 1,
         "unparsable"),
        ("missing cell", good + "| SR-3 | `tests/test_a::test_one` |\n", None, [], 1, "unparsable"),
        ("leading zero", good + "| SR-03 | C | `tests/test_a::test_one` |\n", None, [], 1, "unparsable"),
        ("lowercase id", good + "| sr-3 | C | `tests/test_a::test_one` |\n", None, [], 1, "unparsable"),
        ("duplicate", good + "| SR-2 | C | `tests/test_a::test_one` |\n", None, [], 1, "SR-2: duplicate id"),
        ("deleted row", good, ["SR-1", "SR-2", "SR-3"], [], 1, "SR-3: pinned"),
        ("unpinned row", good, ["SR-1"], [], 1, "SR-2: not pinned"),
        ("retired reuse", good, ["SR-1"], ["SR-2"], 1, "SR-2: retired"),
        ("empty item", "| SR-1 | A | `tests/test_a::test_one, ` |\n", None, [], 1, "malformed test reference"),
        ("missing test", "| SR-1 | A | `tests/test_a::test_three` |\n", None, [], 1, "missing test test_three"),
        ("bare python module", "| SR-1 | A | `tests/test_a` |\n", None, [], 1, "names no test"),
        ("python helper is not a test", "| SR-1 | A | `tests/test_a::helper_one` |\n", None, [], 1,
         "is not a test_* method"),
        ("python top-level function is not a method", "| SR-1 | A | `tests/test_a::test_top` |\n", None, [], 1,
         "missing test test_top"),
        ("python test prefix only", "| SR-1 | A | `tests/test_a::test_on` |\n", None, [], 1, "missing test test_on"),
        ("python module not named test_*", "| SR-1 | A | `tools/demo::test_one` |\n", None, [], 1,
         "is not a test_* module"),
        ("python parent escape", "| SR-1 | A | `../tests/test_a::test_one` |\n", None, [], 1, "is not a test_* module"),
        ("missing module", "| SR-1 | A | `tests/test_b::test_one` |\n", None, [], 1, "missing test module"),
        ("go test", "| SR-1 | A | `go/internal/demo::TestGuard` |\n", None, [], 0, "1 Go tests in 1 packages"),
        ("go fuzz", "| SR-1 | A | `go/internal/demo::FuzzGuard` |\n", None, [], 0, "1 rows, 1 Go tests"),
        ("go and python", "| SR-1 | A | `go/internal/demo::TestGuard, tests/test_a::test_one` |\n", None, [], 0,
         "0 failures"),
        ("missing go test", "| SR-1 | A | `go/internal/demo::TestAbsent` |\n", None, [], 1, "missing Go test"),
        ("prefix only is not a test", "| SR-1 | A | `go/internal/demo::TestGuar` |\n", None, [], 1,
         "missing Go test TestGuar"),
        ("helper is not a test", "| SR-1 | A | `go/internal/demo::helper` |\n", None, [], 1,
         "is not a test or fuzz function"),
        ("missing go package", "| SR-1 | A | `go/internal/absent::TestGuard` |\n", None, [], 1,
         "missing Go package"),
        ("go package without a test name", "| SR-1 | A | `go/internal/demo` |\n", None, [], 1, "names no test"),
        ("several, one missing go", "| SR-1 | A | `go/internal/demo::TestGuard, go/internal/demo::TestNope` |\n",
         None, [], 1, "missing Go test TestNope"),
        # SEC-PYRM-10: a row the old CANDIDATE regex never saw must fail, not vanish with rc 0.
        ("no leading pipe", good + "SR-3 | C | manual review |\n", None, [], 1, "line 5: unparsable"),
        ("no leading pipe, valid refs", good + "SR-3 | C | `tests/test_a::test_one` |\n", None, [], 1,
         "line 5: unparsable"),
        ("cyrillic S", good + "| \u0405R-3 | C | manual review |\n", None, [], 1, "line 5: unparsable"),
        ("cyrillic S and R, valid refs", good + "| \u0405\u0420-3 | C | `tests/test_a::test_one` |\n", None, [], 1,
         "line 5: unparsable"),
        ("fullwidth id", good + "| \uff33\uff32-3 | C | `tests/test_a::test_one` |\n", None, [], 1, "unparsable"),
        ("non-breaking space", good + "|\u00a0SR-3 | C | `tests/test_a::test_one` |\n", None, [], 1, "unparsable"),
        ("id line without pipes", good + "SR-3 manual review\n", None, [], 1, "line 5: unparsable"),
        ("indented row", good + "  | SR-3 | C | `tests/test_a::test_one` |\n", None, [], 1, "line 5: unparsable"),
        ("stray table row", good + "| XR-3 | C | `tests/test_a::test_one` |\n", None, [], 1, "line 5: unparsable"),
        ("prose and blank lines", "\nSome prose about SR-1 and SR-2.\n\n" + good, None, [], 0, "2 rows, 0 Go tests in 0 packages and 2 Python tests in 1 modules referenced, 0 failures"),
    ]
    failed = 0
    for name, body, ids, retired, want_rc, want_text in cases:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tests").mkdir()
            (root / "tools").mkdir()
            (root / "tests" / "test_a.py").write_text(
                "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_one(self):\n        pass\n\n"
                "    def test_two(self):\n        pass\n\n    def helper_one(self):\n        pass\n\n\n"
                "def test_top():\n    pass\n", encoding="utf-8")
            (root / "tools" / "demo.py").write_text("def test_one():\n    pass\n", encoding="utf-8")
            (root / "go" / "internal" / "demo").mkdir(parents=True)
            (root / "go" / "internal" / "demo" / "demo_test.go").write_text(
                "package demo\n\nfunc TestGuard(t *testing.T) {}\nfunc FuzzGuard(f *testing.F) {}\n"
                "func helper(t *testing.T) {}\nfunc TestGuardAndMore(t *testing.T) {}\n", encoding="utf-8")
            (root / TABLE).write_text(header + body, encoding="utf-8")
            if ids is None:
                ids = sorted({m.group(1) for m in map(ROW.match, body.splitlines()) if m}, key=id_key)
            (root / LOCK).write_text(json.dumps({"ids": ids, "retired": retired}), encoding="utf-8")
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                rc = check(root)
            text = buffer.getvalue()
            if rc != want_rc or want_text not in text:
                failed += 1
                print("FAIL {}: rc {} (want {}), output {!r}".format(name, rc, want_rc, text))
    failed += self_test_write_lock(header, good)
    if RESULT.match("    --- SKIP: TestGuard (0.00s)").groups() != ("SKIP", "TestGuard"):
        failed += 1
        print("FAIL go test result line parse")
    try:
        self_test_python_run()
    except AssertionError as error:
        failed += 1
        print("FAIL python runner {}".format(error))
    print("security requirements self-test: {} cases, {} failed".format(len(cases) + 6, failed))
    return 1 if failed else 0


def self_test_write_lock(header, good):
    failed = 0
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "tools").mkdir()
        (root / TABLE).write_text(header + good, encoding="utf-8")
        quiet = []
        with contextlib.redirect_stdout(io.StringIO()):
            def table(body):
                (root / TABLE).write_text(header + body, encoding="utf-8")

            steps = [
                ("first write", lambda: write_lock(root, []), 0),
                ("drop without retire", lambda: (table(good.splitlines(True)[0]), write_lock(root, []))[1], 1),
                ("drop with retire", lambda: write_lock(root, ["SR-2"]), 0),
                ("reuse retired", lambda: (table(good), write_lock(root, []))[1], 1),
            ]
            for name, step, want in steps:
                rc = step()
                if rc != want:
                    failed += 1
                    quiet.append("FAIL write-lock {}: rc {} (want {})\n".format(name, rc, want))
        lock = json.loads((root / LOCK).read_text(encoding="utf-8"))
        if lock["ids"] != ["SR-1"] or lock["retired"] != ["SR-2"]:
            failed += 1
            quiet.append("FAIL write-lock final lock {!r}\n".format(lock))
    print("".join(quiet), end="")
    return failed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--run", action="store_true", help="also run every referenced Go and Python test; each must pass")
    parser.add_argument("--python-worker", nargs="+", metavar="ARG", help=argparse.SUPPRESS)
    parser.add_argument("--write-lock", action="store_true")
    parser.add_argument("--retire", action="append", default=[], metavar="SR-n")
    args = parser.parse_args(argv)
    if args.python_worker:
        if len(args.python_worker) < 4:
            parser.error("--python-worker needs ROOT MODULE OUTPUT NAME...")
        root, module, output = args.python_worker[:3]
        return python_worker(root, module, output, args.python_worker[3:])
    if args.self_test:
        return self_test()
    if args.retire and not args.write_lock:
        parser.error("--retire needs --write-lock")
    if args.run and args.write_lock:
        parser.error("--run and --write-lock are separate runs")
    root = Path.cwd()
    if args.write_lock:
        return write_lock(root, args.retire)
    return check(root, run=args.run)


if __name__ == "__main__":
    sys.exit(main())
