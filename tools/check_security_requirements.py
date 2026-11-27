"""Verify that every security requirement in SECURITY-REQUIREMENTS.md names a test.

Each requirement row has an identifier (SR-n) and a verification column that must reference existing tests. The
gate fails on a requirement without an executable check or on a reference that no longer exists.

Reference forms (comma-separated in the last column):
  go/<package dir>::TestName   a top-level Go test or fuzz function in a *_test.go file of that package directory
                               (PRO-403: the Go engine is the product, so its tests verify the requirements)
  <module>::test_function      a Python test module (path without .py) and one of its test functions

`--run` also runs every referenced Go test (`go test -run '^(...)$' -v` per package, offline and vendored, with the
pinned toolchain) and fails unless each named test reports PASS: a test that is skipped, missing at run time or
failing never verifies a requirement. `--self-test` checks the parser and the checks on scratch trees.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROW = re.compile(r"^\|\s*(SR-\d+)\s*\|(.*)\|\s*`([^`]+)`\s*\|\s*$")
GO_FUNC = r"^func {}\(\w+ \*testing\.[TF]\)"
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
    path = root / (module + ".py")
    if not path.exists():
        return "missing test module {}".format(module)
    if function and not re.search(r"def {}\b".format(re.escape(function)), path.read_text(encoding="utf-8")):
        return "missing test {} in {}".format(function, module)
    return None


def check(root):
    """(row count, failure lines, {go package: set of test names}) for the requirements file under root."""
    text = (root / "SECURITY-REQUIREMENTS.md").read_text(encoding="utf-8")
    matches = rows(text)
    failures, go_tests = [], {}
    if not matches:
        return 0, ["no requirements found"], go_tests
    for match in matches:
        identifier = match.group(1)
        for module, function in references(match):
            if module.startswith("go/"):
                problem = check_go(root, module, function)
                if problem is None:
                    go_tests.setdefault(module, set()).add(function)
            else:
                problem = check_python(root, module, function)
            if problem:
                failures.append("{}: {}".format(identifier, problem))
    return len(matches), failures, go_tests


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


def self_test():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "go" / "internal" / "demo").mkdir(parents=True)
        (root / "go" / "internal" / "demo" / "demo_test.go").write_text(
            "package demo\n\nfunc TestGuard(t *testing.T) {}\nfunc FuzzGuard(f *testing.F) {}\nfunc helper(t *testing.T) {}\n"
            "func TestGuardAndMore(t *testing.T) {}\n", encoding="utf-8")
        (root / "test_demo.py").write_text("def test_guard():\n    pass\n", encoding="utf-8")
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
            "several, one missing": ("go/internal/demo::TestGuard, go/internal/demo::TestNope", 1),
        }
        for name, (reference, expected) in cases.items():
            (root / "SECURITY-REQUIREMENTS.md").write_text(table.format(reference), encoding="utf-8")
            count, failures, _ = check(root)
            assert count == 1 and len(failures) == expected, (name, failures)
        (root / "SECURITY-REQUIREMENTS.md").write_text("no table\n", encoding="utf-8")
        assert check(root)[1] == ["no requirements found"]
    assert RESULT.match("    --- SKIP: TestGuard (0.00s)").groups() == ("SKIP", "TestGuard")
    print("check_security_requirements self-test: ok")
    return 0


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run", action="store_true", help="also run every referenced Go test; each must PASS")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(arguments)
    if args.self_test:
        return self_test()
    root = Path.cwd()
    count, failures, go_tests = check(root)
    for line in failures:
        print(line)
    if args.run and not failures:
        failures += run_go(root, go_tests)
        for line in failures:
            print(line)
    referenced = sum(len(names) for names in go_tests.values())
    print("security requirements: {} rows, {} Go tests in {} packages referenced{}, {} failures".format(
        count, referenced, len(go_tests), " and run" if args.run else "", len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
