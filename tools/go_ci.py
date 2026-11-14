"""Hosted CI for the Go migration (M10): run the Go engine's gate, and the Python oracle, when the
commit carries them; fail when it carries them only in part.

`main` before the migration lands has no Go module, so "nothing to check" must be distinguished
from "the module disappeared while its sources stayed" and from "the gate target vanished".
Shell conditionals are not allowed in ci.yml (workflow policy rule 13), so that decision lives
here, where it has a self-test.

    go_ci.py go [--summary FILE]      the `go-engine` job: `make go-check` (gofmt, vet,
                                      go test -race, fuzz smoke, then `make parity-go`)
    go_ci.py oracle [--summary FILE]  each `tests (python ...)` job: the committed parity
                                      fixtures replayed through the Python reference on that
                                      interpreter (issue #2 R6: the oracle must hold across the
                                      supported Python range)
    go_ci.py --self-test

Decisions, checked in this order:
- no `go/go.mod`, no tracked `.go` file outside tools/scanners and no migration fixtures:
  nothing to check, success, and the summary says so;
- `.go` sources or migration fixtures without `go/go.mod`: failure (a partial migration tree);
- `go/go.mod` whose `go` directive differs from tools/scanners/go.mod: failure (one Go toolchain
  for the scanners and the engine; tools/check_go_drift.py keeps that one current);
- the installed `go version` differs from the directive: failure (setup-go and GOTOOLCHAIN=local
  must give exactly the pinned toolchain, never a download chosen by go.mod);
- the Makefile lacks the `go-check` target, or the oracle tool is missing: failure;
- otherwise the target runs, and its exit status is this tool's.
Standard library only; Python 3.9 syntax.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

GO_MOD = Path("go/go.mod")
SCANNER_MOD = Path("tools/scanners/go.mod")
FIXTURES = Path("migration/fixtures/cases.json")
COMPARE = Path("migration/parity/compare.py")
REPORT = Path("migration/parity/go-report.json")
DIRECTIVE = re.compile(r"^go\s+(\d+\.\d+(?:\.\d+)?)\s*$", re.M)
GO_VERSION = re.compile(r"\bgo version go(\d+\.\d+(?:\.\d+)?)\s")
TARGET = re.compile(r"^go-check\s*:", re.M)


def directive(text):
    found = DIRECTIVE.findall(text or "")
    return found[0] if len(found) == 1 else None


def decide(mode, tree):
    """tree: {"go_mod", "scanner_mod", "makefile": text or None, "go_sources": [paths],
    "fixtures": bool, "compare": bool, "go_version": `go version` output or None}.
    Returns (action, problems): action is "skip", "run" or "fail"."""
    problems = []
    module = tree.get("go_mod")
    sources = sorted(tree.get("go_sources") or [])
    if module is None:
        if sources:
            problems.append("{} Go source file(s) are tracked (first: {}) but {} is missing".format(
                len(sources), sources[0], GO_MOD))
        if tree.get("fixtures") or tree.get("compare"):
            problems.append("migration parity files are tracked but {} is missing".format(GO_MOD))
        return ("fail", problems) if problems else ("skip", [])
    if not tree.get("fixtures") or not tree.get("compare"):
        problems.append("{} exists but {} or {} is missing: the parity oracle is part of the Go gate".format(
            GO_MOD, FIXTURES, COMPARE))
    if mode == "oracle":
        return ("fail", problems) if problems else ("run", [])
    wanted, pinned = directive(module), directive(tree.get("scanner_mod"))
    if wanted is None:
        problems.append("{} has no single `go` directive".format(GO_MOD))
    elif wanted != pinned:
        problems.append("{} declares go {} but {} pins go {}: one Go toolchain for the scanners and the engine".format(
            GO_MOD, wanted, SCANNER_MOD, pinned))
    installed = GO_VERSION.search(tree.get("go_version") or "")
    if installed is None:
        problems.append("`go version` gave no version: {!r}".format((tree.get("go_version") or "")[:120]))
    elif wanted is not None and installed.group(1) != wanted:
        problems.append("installed go {} differs from the go {} that {} declares".format(installed.group(1), wanted, GO_MOD))
    if not TARGET.search(tree.get("makefile") or ""):
        problems.append("Makefile has no `go-check` target")
    return ("fail", problems) if problems else ("run", [])


def read(path):
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        return None


def tracked_go_sources():
    listing = subprocess.run(["git", "ls-files", "-z", "--", "*.go"], stdout=subprocess.PIPE, check=True).stdout  # noqa: S603,S607
    return [name for name in listing.decode("utf-8").split("\0") if name and not name.startswith("tools/scanners/")]


def go_version():
    try:
        return subprocess.run(["go", "version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,  # noqa: S603,S607
                              check=False, timeout=60).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired) as error:
        return "go version failed: {}".format(error)


def survey(mode):
    tree = {"go_mod": read(GO_MOD), "scanner_mod": read(SCANNER_MOD), "makefile": read("Makefile"),
            "go_sources": tracked_go_sources(), "fixtures": FIXTURES.is_file(), "compare": COMPARE.is_file()}
    if mode == "go" and tree["go_mod"] is not None:
        tree["go_version"] = go_version()
    return tree


def summarise(path, lines):
    if path:
        with open(path, "a", encoding="utf-8") as stream:
            stream.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)


def fixture_case_count():
    """The number of cases in the committed fixtures, or None when unreadable."""
    try:
        cases = json.loads(FIXTURES.read_text(encoding="utf-8")).get("cases")
    except (OSError, ValueError, AttributeError):
        return None
    return len(cases) if isinstance(cases, list) else None


def report_problems(report, expected_cases=None):
    """A floor under the parity report, independent of compare.py's own verdict (issue #2 R2: an
    all-unsupported answer set once passed it): it must have compared cases, matched every one and
    listed no mismatch or extra result. Closing R2 itself (an explicit gap allowlist) is the engine's.
    With `expected_cases` (the committed fixtures' count) the report must also account for exactly
    those cases, compared plus unsupported, none missing, so it describes this checkout's fixtures
    (issue #7 M10 review of eaa8a99). This is a consistency check on the counts, not a binding to the
    fixtures' contents; the full parity comparison is the evidence. `exempted` is not a case count: compare.py counts the difference
    paths an approved delta exempts inside cases already counted as compared, so it stays out of the
    sum and is not constrained here."""
    if not isinstance(report, dict):
        return ["{} is not a JSON object".format(REPORT)]
    problems = []
    compared, matched = report.get("compared"), report.get("matched")
    if report.get("ok") is not True:
        problems.append("the parity report is not ok")
    if not isinstance(compared, int) or compared <= 0:
        problems.append("the parity report compared no case (compared={!r})".format(compared))
    elif matched != compared:
        problems.append("the parity report matched {!r} of {} compared cases".format(matched, compared))
    # mismatched/extra in either format (counts since the engine's R2 fix 321e088, lists before);
    # the gap-allowlist counters that fix added are checked whenever the report carries them
    for key in ("mismatched", "extra", "unexpected_gaps", "stale_gaps", "claimed_without_match"):
        if report.get(key):
            problems.append("the parity report lists {} {}".format(key, report[key] if isinstance(report[key], int) else len(report[key])))
    if expected_cases is not None:
        parts = [report.get(key, 0) for key in ("compared", "unsupported")]
        if not all(isinstance(part, int) and not isinstance(part, bool) for part in parts):
            problems.append("the parity report's case counts are not integers: {!r}".format(parts))
        elif sum(parts) != expected_cases:
            problems.append("the parity report accounts for {} cases (compared + unsupported) but {} holds {}: "
                            "it does not describe this checkout's fixtures".format(sum(parts), FIXTURES, expected_cases))
        if report.get("missing"):
            problems.append("the parity report lists missing {}".format(report["missing"]))
    return problems


def clear_report():
    """Remove a parity report left by an earlier run, so the gate only ever reads the one `make go-check`
    writes now; None, or the reason the old report could not be removed."""
    try:
        REPORT.unlink()
    except FileNotFoundError:
        return None
    except OSError as error:
        return "a stale {} could not be removed before the run: {}".format(REPORT, error)
    return None if not REPORT.exists() else "a stale {} is still present after removal".format(REPORT)


def parity_lines():
    """(summary lines, problems) for the report `make parity-go` writes."""
    expected = fixture_case_count()
    if expected is None:
        return ["- parity report: {} is unreadable".format(FIXTURES)], ["{} has no readable case list".format(FIXTURES)]
    try:
        report = json.loads(REPORT.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return ["- parity report: {} unreadable ({})".format(REPORT, error)], ["{} was not written".format(REPORT)]
    keys = ("ok", "total", "compared", "matched", "unsupported")
    line = "- parity report: " + ", ".join("{} {}".format(key, report[key]) for key in keys if isinstance(report, dict) and key in report)
    problems = report_problems(report, expected)
    return [line] + ["- FAILED: " + problem for problem in problems], problems


def run(mode, summary):
    title = "### Go engine (M10)" if mode == "go" else "### Parity oracle on python {}".format(sys.version.split()[0])
    action, problems = decide(mode, survey(mode))
    if action == "skip":
        summarise(summary, [title, "", "No Go module, Go sources or migration fixtures on this commit: nothing to check."])
        return 0
    if action == "fail":
        summarise(summary, [title, ""] + ["- FAILED: " + problem for problem in problems])
        return 1
    if mode == "go":
        stale = clear_report()
        if stale:
            summarise(summary, [title, "", "- FAILED: " + stale])
            return 1
        command = ["make", "go-check", "PYTHON=" + sys.executable]
    else:
        command = [sys.executable, "-B", str(COMPARE), "--backend", "python", "--cases", str(FIXTURES)]
    code = subprocess.run(command, check=False).returncode  # noqa: S603
    lines, problems = [title, "", "- `{}`: exit {}".format(" ".join(command), code)], []
    if mode == "go":
        report_lines, problems = parity_lines()
        lines += report_lines
    summarise(summary, lines)
    return 0 if code == 0 and not problems else 1


def self_test():
    scanner = "module m\n\ngo 1.27.4\n"
    full = {"go_mod": "module x\n\ngo 1.27.4\n", "scanner_mod": scanner, "makefile": "go-check:\n\tgo test\n",
            "go_sources": ["go/main.go"], "fixtures": True, "compare": True,
            "go_version": "go version go1.27.4 linux/amd64\n"}
    empty = {"go_mod": None, "scanner_mod": scanner, "makefile": "check:\n", "go_sources": [], "fixtures": False, "compare": False}
    assert decide("go", empty) == ("skip", [])
    assert decide("oracle", empty) == ("skip", [])
    assert decide("go", full) == ("run", [])
    assert decide("oracle", dict(full, go_version=None, makefile="")) == ("run", [])
    cases = {
        "module deleted, sources stay": (dict(full, go_mod=None), "Go source file(s) are tracked"),
        "module deleted, fixtures stay": (dict(full, go_mod=None, go_sources=[]), "migration parity files are tracked"),
        "fixtures deleted": (dict(full, fixtures=False), "the parity oracle is part of the Go gate"),
        "compare tool deleted": (dict(full, compare=False), "the parity oracle is part of the Go gate"),
        "second toolchain": (dict(full, go_mod="module x\n\ngo 1.26.10\n"), "one Go toolchain"),
        "no directive": (dict(full, go_mod="module x\n"), "no single `go` directive"),
        "two directives": (dict(full, go_mod="module x\ngo 1.27.4\ngo 1.27.3\n"), "no single `go` directive"),
        "downloaded toolchain": (dict(full, go_version="go version go1.28.1 linux/amd64\n"), "differs from the go 1.27.4"),
        "no go binary": (dict(full, go_version="go version failed: [Errno 2]"), "gave no version"),
        "target removed": (dict(full, makefile="check:\n\tgo test\n"), "no `go-check` target"),
    }
    for label, (tree, expected) in cases.items():
        action, problems = decide("go", tree)
        assert action == "fail" and any(expected in problem for problem in problems), (label, action, problems)
    oracle_action, oracle_problems = decide("oracle", dict(full, compare=False))
    assert oracle_action == "fail" and oracle_problems, oracle_problems
    good = {"ok": True, "compared": 4084, "matched": 4084, "unsupported": 169, "mismatched": [], "extra": []}
    assert report_problems(good) == []
    current = {"ok": True, "compared": 5185, "matched": 5185, "mismatched": 0, "missing": 0, "extra": 0, "unsupported": 180,
               "unexpected_gaps": 0, "stale_gaps": 0, "claimed_without_match": 0}
    assert report_problems(current) == []
    for label, bad, expected in (
            ("all unsupported", dict(good, compared=0, matched=0, unsupported=4253), "compared no case"),
            ("not ok", dict(good, ok=False), "not ok"),
            ("ok as a string", dict(good, ok="true"), "not ok"),
            ("a mismatch", dict(good, matched=4083, mismatched=["case-1"]), "matched 4083 of 4084"),
            ("an extra result", dict(good, extra=["stray"]), "lists extra 1"),
            ("an extra count (321e088 format)", dict(good, extra=2), "lists extra 2"),
            ("an unexpected gap", dict(good, unexpected_gaps=1), "lists unexpected_gaps 1"),
            ("a stale gap entry", dict(good, stale_gaps=3), "lists stale_gaps 3"),
            ("a claim without a match", dict(good, claimed_without_match=1), "lists claimed_without_match 1"),
            ("no compared count", {"ok": True}, "compared no case"),
            ("not an object", [], "not a JSON object")):
        found = report_problems(bad)
        assert any(expected in problem for problem in found), (label, found)
    counted = dict(current)
    assert report_problems(counted, 5365) == []
    # an approved delta exempts difference paths inside compared cases (engine lane, compare.py)
    assert report_problems(dict(counted, exempted=3), 5365) == []
    assert report_problems(good, 4253) == []
    for label, bad, expected in (
            ("other fixtures", counted, "accounts for 5365 cases"),
            ("a missing case", dict(counted, missing=1), "lists missing 1"),
            ("a boolean count", dict(counted, unsupported=True), "not integers"),
            ("exempted counted as cases", dict(counted, compared=5184, matched=5184, exempted=1), "accounts for 5364 cases")):
        found = report_problems(bad, 5366 if label == "other fixtures" else 5365)
        assert any(expected in problem for problem in found), (label, found)
    stale_regression()
    assert directive("module x\n\ngo 1.27\n") == "1.27"
    assert GO_VERSION.search("go version go1.27.4 darwin/arm64 ").group(1) == "1.27.4"
    print("go_ci self-test: ok ({} tree refusals, 15 report refusals, 3 end-to-end runs)".format(len(cases) + 1))
    return 0


def stale_regression():
    """End to end, in a scratch git tree with a stub `go` (issue #7 M10 review of eaa8a99): a passing
    report left from an earlier run must not pass a `go-check` that no longer runs parity, and a fresh
    report must describe the committed fixtures; a fresh matching report passes."""
    for tool in ("git", "make"):
        if shutil.which(tool) is None:
            raise AssertionError("the end-to-end self-test needs `{}` on PATH".format(tool))
    passing = {"ok": True, "compared": 2, "matched": 2, "mismatched": 0, "extra": 0, "unsupported": 1}
    copy = "go-check:\n\tcp fresh.json {}\n".format(REPORT)
    targets = {
        "stale report, no-op target": ("go-check:\n\t@echo NO_TESTS_EXECUTED\n", passing, 1),
        "fresh report for other fixtures": (copy, dict(passing, compared=4084, matched=4084), 1),
        "fresh matching report": (copy, passing, 0),
    }
    here = Path(__file__).resolve()
    for label, (makefile, fresh, wanted) in targets.items():
        root = Path(tempfile.mkdtemp(prefix="go_ci_selftest_"))
        try:
            for path, text in {"go/go.mod": "module x\n\ngo 1.27.4\n", "tools/scanners/go.mod": "module s\n\ngo 1.27.4\n",
                               "go/main.go": "package main\n", "Makefile": makefile, "fresh.json": json.dumps(fresh),
                               str(FIXTURES): json.dumps({"cases": [{"id": "a"}, {"id": "b"}, {"id": "c"}]}),
                               str(COMPARE): "import sys\nsys.exit(99)\n",
                               str(REPORT): json.dumps(dict(passing, compared=3, matched=3, unsupported=0)),
                               "bin/go": "#!/bin/sh\necho 'go version go1.27.4 linux/amd64'\n"}.items():
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")
            (root / "bin/go").chmod(0o755)
            subprocess.run(["git", "init", "-q"], cwd=str(root), check=True)  # noqa: S603,S607
            subprocess.run(["git", "add", "-A"], cwd=str(root), check=True)  # noqa: S603,S607
            env = dict(os.environ, PATH=str(root / "bin") + os.pathsep + os.environ.get("PATH", ""))
            result = subprocess.run([sys.executable, "-B", str(here), "go"], cwd=str(root), env=env,  # noqa: S603
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, timeout=120)
            output = result.stdout.decode("utf-8", "replace")
            assert result.returncode == wanted, (label, result.returncode, output)
        finally:
            shutil.rmtree(str(root), ignore_errors=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", nargs="?", choices=("go", "oracle"))
    parser.add_argument("--summary", help="append a markdown summary here (GITHUB_STEP_SUMMARY)")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.mode is None:
        parser.error("a mode (go or oracle) or --self-test is required")
    return run(args.mode, args.summary)


if __name__ == "__main__":
    sys.exit(main())
