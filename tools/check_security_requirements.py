"""Verify that every security requirement in SECURITY-REQUIREMENTS.md names a test, and that none disappears.

    check_security_requirements.py                         check the table against the lock (make requirements)
    check_security_requirements.py --run                   also run every referenced test (CI, make requirements-run)
    check_security_requirements.py --write-lock [--retire SR-n ...]
                                                           pin the table's id set in the lock
    check_security_requirements.py --self-test

Reference forms (comma-separated in the last column):
  go/<package dir>::TestName   a top-level Go test or fuzz function in a *_test.go file of that package directory
                               (PRO-403: the Go engine is the product, so its tests verify the requirements)
  <dir>/test_<name>::test_<name>
                               a unittest test method in a Python test module (path without .py); both the module
                               and the method must be named test_*, so a helper `def` or a bare module never counts
                               (SEC-PYRM-2, PRO-546)

The gate fails closed (SEC-PYRM-1, PRO-545; SEC-PYRM-9 combines both fixes) on:
- any line that starts a table row with `SR` but does not parse as `| SR-n | requirement | `refs` |` (free text,
  "manual review", prose after the closing backtick, a missing cell, `SR-07`): such a row used to be dropped
  silently, so its requirement lost its evidence while the gate stayed green;
- an empty or malformed reference item, a reference whose path leaves the repository (an absolute path, a `.` or
  `..` component, or a symlink that resolves outside the tree), or a reference that names no existing test;
- a duplicate id (two rows claiming one requirement number);
- an id set that differs from tools/security_requirements.lock.json: a deleted row (an id in the lock that the
  table lacks), an unpinned new row (an id the lock lacks: run --write-lock and commit the lock with the row), or
  a retired id that is back in the table.

`--run` also runs every referenced test and fails unless each one passes: every Go test with `go test -run '^(...)$'
-v` per package (offline and vendored, with the pinned toolchain), and every Python test method in a fresh
interpreter per module (the module's folder and its parents up to the repository root on sys.path). A Python test
that is skipped (including a class-level skipUnless), an expected failure, an unexpected success, a failure, an
error, an import error, or a name that loads no TestCase method never verifies a requirement. Tests run only when
the static checks above found nothing.

--write-lock pins the table's ids. It refuses to drop a pinned id unless that id is named with --retire, which
moves it to the lock's `retired` list for good, so removing a requirement is always a visible, reviewed change to
the lock and a retired number is never reused.
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

TABLE = "SECURITY-REQUIREMENTS.md"
LOCK = "tools/security_requirements.lock.json"

# Any table row whose first cell starts with SR (any case, any spacing) is a requirement row and must parse.
CANDIDATE = re.compile(r"^\s*\|\s*sr", re.IGNORECASE)
ROW = re.compile(r"^\|\s*(SR-[1-9]\d*)\s*\|(.*)\|\s*`([^`]+)`\s*\|\s*$")
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
        if not CANDIDATE.match(line):
            continue
        match = ROW.match(line)
        if not match:
            failures.append("line {}: unparsable requirement row (expected `| SR-n | requirement | `module::test[, "
                            "...]` |`): {}".format(number, line.strip()[:80]))
            continue
        identifier, _, reference = match.groups()
        rows.append((number, identifier, reference))
    return rows, failures


def confined(root, relative):
    """None when `relative` is a plain relative path that stays inside root (symlinks resolved), else the reason."""
    parts = relative.split("/")
    if relative.startswith("/") or any(part in ("", ".", "..") for part in parts):
        return "path {} is not a plain relative path inside the repository".format(relative)
    base = root.resolve()
    target = (root / relative).resolve()
    if target != base and base not in target.parents:
        return "path {} resolves outside the repository".format(relative)
    return None


def check_go(root, package, function):
    """None when go/<package> has `function` as a top-level test, else the failure text."""
    problem = confined(root, package)
    if problem:
        return "Go reference {}".format(problem)
    folder = root / package
    if not folder.is_dir():
        return "missing Go package {}".format(package)
    if not function:
        return "Go reference {} names no test".format(package)
    if not re.match(r"(Test|Fuzz)[A-Z0-9_]", function):
        return "Go reference {}::{} is not a test or fuzz function".format(package, function)
    pattern = re.compile(GO_FUNC.format(re.escape(function)), re.M)
    for path in sorted(folder.glob("*_test.go")):
        if confined(root, path.relative_to(root).as_posix()) is None and pattern.search(path.read_text(encoding="utf-8")):
            return None
    return "missing Go test {} in {}".format(function, package)


def check_python(root, module, function):
    """None when module is a test_* file defining test method `function` (test_*), else the failure text."""
    if not PY_MODULE.match(module):
        return "Python reference {} is not a test_* module".format(module)
    problem = confined(root, module + ".py")
    if problem:
        return "Python reference {}".format(problem)
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


def check_references(root, rows):
    """(failure lines, {go package: test names}, {python module: test names}) for the rows' references."""
    failures, go_tests, python_tests = [], {}, {}
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
    return failures, go_tests, python_tests


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
    if not isinstance(data, dict):
        return None, ["{}: not a JSON object".format(LOCK)]
    ids, retired = data.get("ids"), data.get("retired", [])
    if not isinstance(ids, list) or not isinstance(retired, list):
        return None, ["{}: `ids` and `retired` must be lists".format(LOCK)]
    if not all(isinstance(item, str) and re.match(r"^SR-[1-9]\d*$", item) for item in ids + retired):
        return None, ["{}: every entry of `ids` and `retired` must be an SR-n id".format(LOCK)]
    if len(set(ids)) != len(ids) or len(set(retired)) != len(retired) or set(ids) & set(retired):
        return None, ["{}: an id appears twice in `ids`/`retired`".format(LOCK)]
    return (set(ids), set(retired)), []


def check_lock(root, rows):
    lock, failures = read_lock(root)
    if lock is None:
        return failures
    pinned, retired = lock
    present = {identifier for _, identifier, _ in rows}
    for identifier in sorted(pinned - present, key=id_key):
        failures.append("{}: pinned in {} but missing from {} (deleted, renumbered or unparsable row; retire it with "
                        "--write-lock --retire {})".format(identifier, LOCK, TABLE, identifier))
    for identifier in sorted(present - pinned - retired, key=id_key):
        failures.append("{}: not pinned in {}; run --write-lock and commit the lock with the row".format(
            identifier, LOCK))
    for identifier in sorted(present & retired, key=id_key):
        failures.append("{}: retired in {}; a retired id is never reused".format(identifier, LOCK))
    return failures


def check(root, text=None):
    """(row count, failure lines, {go package: test names}, {python module: test names}) for root's requirements.

    `text` replaces the table's contents (the self-test mutates the real table without writing it).
    """
    if text is None:
        try:
            text = (root / TABLE).read_text(encoding="utf-8")
        except OSError as error:
            return 0, ["{}: unreadable ({})".format(TABLE, error)], {}, {}
    rows, failures = parse(text)
    if not rows and not failures:
        return 0, ["no requirements found"], {}, {}
    failures += check_duplicates(rows)
    reference_failures, go_tests, python_tests = check_references(root, rows)
    failures += reference_failures
    failures += check_lock(root, rows)
    return len(rows), failures, go_tests, python_tests


def write_lock(root, retire):
    try:
        text = (root / TABLE).read_text(encoding="utf-8")
    except OSError as error:
        print("{}: unreadable ({})".format(TABLE, error))
        return 1
    rows, failures = parse(text)
    failures += check_duplicates(rows)
    if not rows and not failures:
        failures.append("no requirements found")
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
    for identifier in sorted(item for item in retire if not re.match(r"^SR-[1-9]\d*$", item)):
        problems.append("{}: not an SR-n id".format(identifier))
    retire = {item for item in retire if re.match(r"^SR-[1-9]\d*$", item)}
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
    """Failure lines (none when healthy) for the Python runner's nine outcomes."""
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
        if set(failures) != expected:
            return ["python runner: {}".format(sorted(set(failures) ^ expected))]
    return []


HEADER = "| ID | Requirement | Verified by |\n|---|---|---|\n"
GO_DEMO = ("package demo\n\nfunc TestGuard(t *testing.T) {}\nfunc FuzzGuard(f *testing.F) {}\nfunc helper(t *testing.T) {}\n"
           "func TestGuardAndMore(t *testing.T) {}\n")
PY_DEMO = ("import unittest\n\n\nclass T(unittest.TestCase):\n    def test_guard(self):\n        pass\n\n"
           "    def test_one(self):\n        pass\n\n\ndef helper_guard():\n    pass\n")


def scratch_tree(directory):
    """A scratch repository: one Go package, Python test modules, a stdlib-like module and a tree outside root."""
    outside = Path(directory) / "outside"
    root = Path(directory) / "repo"
    (outside / "usr" / "lib" / "python3").mkdir(parents=True)
    (outside / "usr" / "lib" / "python3" / "os.py").write_text("def makedirs(name):\n    pass\n", encoding="utf-8")
    (outside / "test_escape.py").write_text(PY_DEMO, encoding="utf-8")
    (outside / "escape").mkdir()
    (outside / "escape" / "escape_test.go").write_text(GO_DEMO, encoding="utf-8")
    (root / "go" / "internal" / "demo").mkdir(parents=True)
    (root / "go" / "internal" / "demo" / "demo_test.go").write_text(GO_DEMO, encoding="utf-8")
    (root / "tests").mkdir()
    (root / "tests" / "test_a.py").write_text(PY_DEMO, encoding="utf-8")
    (root / "test_demo.py").write_text(PY_DEMO, encoding="utf-8")
    (root / "tools").mkdir()
    (root / "tools" / "demo.py").write_text(PY_DEMO, encoding="utf-8")  # a real test method in a non-test_ module
    try:
        (root / "tests" / "linked").symlink_to(outside, target_is_directory=True)
        (root / "go" / "linked").symlink_to(outside / "escape", target_is_directory=True)
    except (OSError, NotImplementedError):
        pass  # the symlink cases below then fail on a missing path, which is still a failure
    return root


def pin(root, body, ids=None, retired=()):
    """Write the table and a lock pinning `ids` (default: the ids the table's parsable rows carry)."""
    (root / TABLE).write_text(HEADER + body, encoding="utf-8")
    if ids is None:
        ids = sorted({identifier for _, identifier, _ in parse(body)[0]}, key=id_key)
    (root / LOCK).write_text(json.dumps({"ids": list(ids), "retired": list(retired)}), encoding="utf-8")


def self_test_references(root):
    """SEC-PYRM-2 reference forms (PRO-546) and confinement: each case is one row and its expected failure count."""
    cases = {
        "go test": ("go/internal/demo::TestGuard", 0),
        "go fuzz": ("go/internal/demo::FuzzGuard", 0),
        "python test": ("test_demo::test_guard", 0),
        "python test in a folder": ("tests/test_a::test_one", 0),
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
        "python escape to a test_ module": ("../outside/test_escape::test_guard", 1),
        "python escape to the stdlib (SEC-PYRM-9)": ("../../../../../../usr/lib/python3/os::makedirs", 1),
        "python absolute path": ("/" + str(root.parent / "outside" / "test_escape").lstrip("/") + "::test_guard", 1),
        "python dot component": ("./test_demo::test_guard", 1),
        "python symlink out of the tree": ("tests/linked/test_escape::test_guard", 1),
        "go parent escape": ("go/../../outside/escape::TestGuard", 1),
        "go symlink out of the tree": ("go/linked::TestGuard", 1),
        "several, one missing": ("go/internal/demo::TestGuard, go/internal/demo::TestNope", 1),
        "empty item": ("go/internal/demo::TestGuard, ", 1),
    }
    problems = []
    for name, (reference, expected) in cases.items():
        pin(root, "| SR-1 | guard | `{}` |\n".format(reference))
        count, failures, _, _ = check(root)
        if count != 1 or len(failures) != expected:
            problems.append("references {}: {} rows, failures {}".format(name, count, failures))
    return len(cases), problems


def self_test_table(root):
    """SEC-PYRM-1 table and lock cases (PRO-545): (name, body, lock ids, lock retired, failures, wanted substring)."""
    good = "| SR-1 | A | `tests/test_a::test_one` |\n| SR-2 | B `x` | `tests/test_a::test_one, go/internal/demo::TestGuard` |\n"
    cases = [
        ("valid", good, None, [], 0, ""),
        ("free text", good + "| SR-3 | C | manual review |\n", None, [], 1, "line 5: unparsable"),
        ("prose after backtick", good + "| SR-3 | C | `tests/test_a::test_one` and more |\n", None, [], 1, "unparsable"),
        ("missing cell", good + "| SR-3 | `tests/test_a::test_one` |\n", None, [], 1, "unparsable"),
        ("leading zero", good + "| SR-03 | C | `tests/test_a::test_one` |\n", None, [], 1, "unparsable"),
        ("lowercase id", good + "| sr-3 | C | `tests/test_a::test_one` |\n", None, [], 1, "unparsable"),
        ("indented row", good + "  | SR-3 | C | `tests/test_a::test_one` |\n", None, [], 1, "unparsable"),
        ("pinned row turned to free text", good + "| SR-3 | C | manual review |\n", ["SR-1", "SR-2", "SR-3"], [], 2,
         "SR-3: pinned"),
        ("duplicate", good + "| SR-2 | C | `tests/test_a::test_one` |\n", None, [], 1, "SR-2: duplicate id"),
        ("deleted row", good, ["SR-1", "SR-2", "SR-3"], [], 1, "SR-3: pinned"),
        ("unpinned row", good, ["SR-1"], [], 1, "SR-2: not pinned"),
        ("retired reuse", good, ["SR-1"], ["SR-2"], 1, "SR-2: retired"),
        ("missing test", "| SR-1 | A | `tests/test_a::test_two` |\n", None, [], 1, "missing test test_two"),
        ("missing module", "| SR-1 | A | `tests/test_b::test_one` |\n", None, [], 1, "missing test module"),
        ("no rows", "nothing here\n", [], [], 1, "no requirements found"),
    ]
    problems = []
    for name, body, ids, retired, want, text in cases:
        pin(root, body, ids, retired)
        _, failures, _, _ = check(root)
        if len(failures) != want or (text and not any(text in line for line in failures)):
            problems.append("table {}: failures {}".format(name, failures))
    for name, content in (("missing lock", None), ("lock not an object", "[]"), ("lock ids not ids", '{"ids": [3]}'),
                          ("lock id twice", '{"ids": ["SR-1", "SR-1"]}')):
        pin(root, good)
        if content is None:
            (root / LOCK).unlink()
        else:
            (root / LOCK).write_text(content, encoding="utf-8")
        if not any(LOCK in line for line in check(root)[1]):
            problems.append("table {}: not refused".format(name))
    (root / TABLE).unlink()
    if not any("unreadable" in line for line in check(root)[1]):
        problems.append("table missing file: not refused")
    return len(cases) + 5, problems


def self_test_joint(root):
    """SEC-PYRM-9: both bypasses in one table must each fail, and neither may hide the other."""
    body = ("| SR-1 | A | `tests/test_a::test_one` |\n"
            "| SR-67 | corpus harness | manual review |\n"
            "| SR-68 | escape | `../../../../../../usr/lib/python3/os::makedirs` |\n")
    pin(root, body, ["SR-1", "SR-67", "SR-68"])
    count, failures, _, python_tests = check(root)
    wanted = ["line 4: unparsable", "SR-67: pinned", "SR-68: Python reference"]
    problems = []
    if count != 2 or len(failures) != 3 or not all(any(text in line for line in failures) for text in wanted):
        problems.append("joint: {} rows, failures {}".format(count, failures))
    if any("os" in module for module in python_tests):
        problems.append("joint: the escaping module was queued to run: {}".format(sorted(python_tests)))
    with contextlib.redirect_stdout(io.StringIO()):
        if main_in(root, ["--run"]) != 1:
            problems.append("joint: --run did not fail")
    return 1, problems


def self_test_repository():
    """The two SEC-PYRM-9 mutations of the repository's own table: SR-67 as manual review, SR-67 escaping the tree."""
    root = Path(__file__).resolve().parents[1]
    problems = []
    try:
        text = (root / TABLE).read_text(encoding="utf-8")
    except OSError as error:
        return 1, ["repository: {} unreadable ({})".format(TABLE, error)]
    if check(root, text)[1]:
        problems.append("repository: the unchanged table fails: {}".format(check(root, text)[1]))
    row = [line for line in text.splitlines() if line.startswith("| SR-67 |")]
    if len(row) != 1:
        return 1, problems + ["repository: no single SR-67 row"]
    cell = row[0].rstrip().rsplit("|", 2)[1]
    mutations = {
        "SR-67 manual review": (" manual review ", ["unparsable", "SR-67: pinned"]),
        "SR-67 escapes to the stdlib": (" `../../../../../../usr/local/lib/python3.13/os::makedirs` ",
                                        ["SR-67: Python reference"]),
    }
    for name, (replacement, wanted) in mutations.items():
        failures = check(root, text.replace(row[0], row[0].replace(cell, replacement)))[1]
        if not failures or not all(any(item in line for line in failures) for item in wanted):
            problems.append("repository {}: failures {}".format(name, failures))
    return len(mutations) + 1, problems


def self_test_write_lock(root):
    good = "| SR-1 | A | `tests/test_a::test_one` |\n| SR-2 | B | `tests/test_a::test_one` |\n"
    problems = []

    def table(body):
        (root / TABLE).write_text(HEADER + body, encoding="utf-8")

    if (root / LOCK).exists():
        (root / LOCK).unlink()
    table(good)
    steps = [
        ("first write", lambda: write_lock(root, []), 0),
        ("drop without retire", lambda: (table(good.splitlines(True)[0]), write_lock(root, []))[1], 1),
        ("retire a malformed id", lambda: write_lock(root, ["SR-02"]), 1),
        ("drop with retire", lambda: write_lock(root, ["SR-2"]), 0),
        ("reuse retired", lambda: (table(good), write_lock(root, []))[1], 1),
        ("unparsable table", lambda: (table(good + "| SR-3 | C | manual review |\n"), write_lock(root, []))[1], 1),
    ]
    with contextlib.redirect_stdout(io.StringIO()):
        for name, step, want in steps:
            rc = step()
            if rc != want:
                problems.append("write-lock {}: rc {} (want {})".format(name, rc, want))
    lock = json.loads((root / LOCK).read_text(encoding="utf-8"))
    if lock["ids"] != ["SR-1"] or lock["retired"] != ["SR-2"]:
        problems.append("write-lock final lock {!r}".format(lock))
    return len(steps) + 1, problems


def self_test():
    total, problems = 0, []
    with tempfile.TemporaryDirectory() as directory:
        root = scratch_tree(directory)
        for suite in (self_test_references, self_test_table, self_test_joint, self_test_write_lock):
            count, found = suite(root)
            total += count
            problems += found
    count, found = self_test_repository()
    total, problems = total + count, problems + found
    total += 2
    if RESULT.match("    --- SKIP: TestGuard (0.00s)").groups() != ("SKIP", "TestGuard"):
        problems.append("go result line not parsed")
    problems += self_test_python_run()
    for problem in problems:
        print("FAIL " + problem)
    print("check_security_requirements self-test: {} cases, {} failed".format(total, len(problems)))
    return 1 if problems else 0


def main_in(root, arguments):
    """Run the gate on root with arguments (main() uses the working directory)."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run", action="store_true", help="also run every referenced Go and Python test; each must pass")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--write-lock", action="store_true", help="pin the table's id set in the lock")
    parser.add_argument("--retire", action="append", default=[], metavar="SR-n", help="with --write-lock: retire an id")
    parser.add_argument("--python-worker", nargs="+", metavar="ARG", help=argparse.SUPPRESS)
    args = parser.parse_args(arguments)
    if args.python_worker:
        if len(args.python_worker) < 4:
            parser.error("--python-worker needs ROOT MODULE OUTPUT NAME...")
        worker_root, module, output = args.python_worker[:3]
        return python_worker(worker_root, module, output, args.python_worker[3:])
    if args.self_test:
        return self_test()
    if args.retire and not args.write_lock:
        parser.error("--retire needs --write-lock")
    if args.write_lock:
        if args.run:
            parser.error("--write-lock does not take --run")
        return write_lock(root, args.retire)
    count, failures, go_tests, python_tests = check(root)
    for line in failures:
        print(line)
    ran_tests = args.run and not failures
    if ran_tests:
        ran = run_go(root, go_tests) + run_python(root, python_tests)
        for line in ran:
            print(line)
        failures += ran
    referenced = sum(len(names) for names in go_tests.values())
    python_referenced = sum(len(names) for names in python_tests.values())
    print("security requirements: {} rows, {} Go tests in {} packages and {} Python tests in {} modules referenced{}, "
          "{} failures".format(count, referenced, len(go_tests), python_referenced, len(python_tests),
                               " and run" if ran_tests else "", len(failures)))
    return 1 if failures else 0


def main(arguments=None):
    return main_in(Path.cwd(), arguments)


if __name__ == "__main__":
    sys.exit(main())
