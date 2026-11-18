"""Nightly long fuzzing of every Go fuzz target (the `go-fuzz` job of nightly-fuzz.yml).

The per-push gate (`make go-check`) runs each fuzz target for seconds; this runs each one for minutes.
Targets are discovered, not listed: every `func FuzzXxx(f *testing.F)` in a `_test.go` file under go/
(vendor/ and testdata/ excluded), so a new target is fuzzed the night it lands. The time budget is
split evenly across the targets (at least one minute each) and every target runs even after one fails.

When a target fails, `go test` writes the failing input to <package>/testdata/fuzz/<Target>/; every
file there that was not tracked before the run is copied to fuzz-crashers/<package>/<Target>/ for the
workflow to upload, and the summary names it. A crasher reproduces with
`go test ./<package> -run '<Target>/<file>'` once copied back into testdata/fuzz/<Target>/.

The Go checks are tools/go_ci.py's: the installed Go must be the compiler go/go.mod builds with, a
dependency must be vendored, and GOFLAGS=-mod=vendor is set when go/vendor is committed. A commit
without go/go.mod has nothing to fuzz and says so.

    go_fuzz_long.py [--budget-minutes N] [--summary FILE] [--out DIR]
    go_fuzz_long.py --self-test
Standard library only; Python 3.9 syntax.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_ci  # noqa: E402  (one reading of go.mod, the installed Go and the vendor tree)

GO_ROOT = Path("go")
FUZZ_FUNC = re.compile(r"^func\s+(Fuzz\w+)\s*\(\s*\w+\s+\*testing\.F\s*\)", re.M)
SKIP_DIRS = {"vendor", "testdata"}
MAX_BUDGET = 100   # the go-fuzz job times out at 130 minutes: room for builds and many small targets


def discover(root=GO_ROOT):
    """[(package path relative to go/, e.g. "./internal/buffer", target name)], sorted."""
    targets = []
    for directory, dirs, files in os.walk(str(root)):
        dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS and not name.startswith("."))
        for name in sorted(files):
            if not name.endswith("_test.go"):
                continue
            text = Path(directory, name).read_text(encoding="utf-8", errors="replace")
            package = "./" + Path(directory).relative_to(root).as_posix()
            targets += [(package if package != "./." else ".", target) for target in FUZZ_FUNC.findall(text)]
    return sorted(set(targets))


def per_target_seconds(budget_minutes, count):
    """Each target's -fuzztime in whole seconds: the budget split evenly, at least 60 s each."""
    if count == 0:
        return 0
    return max(60, int(budget_minutes * 60 // count))


def corpus_files(root, package, target):
    directory = Path(root, package, "testdata", "fuzz", target)
    return {path.name for path in directory.iterdir() if path.is_file()} if directory.is_dir() else set()


def run(budget_minutes, summary, out):
    title = "### Nightly Go fuzzing"
    tree, problems = go_ci.toolchain_problems()
    if tree is None:
        go_ci.summarise(summary, [title, "", "No {} on this commit: nothing to fuzz.".format(go_ci.GO_MOD)])
        return 0
    if problems:
        go_ci.summarise(summary, [title, ""] + ["- FAILED: " + problem for problem in problems])
        return 1
    targets = discover()
    if not targets:
        go_ci.summarise(summary, [title, "", "- FAILED: {} exists but no fuzz target was found under go/".format(go_ci.GO_MOD)])
        return 1
    seconds = per_target_seconds(budget_minutes, len(targets))
    env = go_ci.go_env(tree.get("vendored"))
    lines = [title, "", "{} targets, {} s each{}".format(len(targets), seconds,
                                                          ", GOFLAGS=-mod=vendor" if tree.get("vendored") else ""), "",
             "| package | target | result |", "|---|---|---|"]
    failed = 0
    for package, target in targets:
        before = corpus_files(GO_ROOT, package, target)
        command = ["go", "test", package, "-run", "^$", "-fuzz", "^{}$".format(target), "-fuzztime", "{}s".format(seconds)]
        code = subprocess.run(command, cwd=str(GO_ROOT), env=env, check=False).returncode  # noqa: S603,S607
        new = sorted(corpus_files(GO_ROOT, package, target) - before)
        if code == 0:
            lines.append("| `{}` | `{}` | ok |".format(package, target))
            continue
        failed += 1
        saved = Path(out, package.lstrip("./") or "root", target)
        for name in new:
            saved.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(Path(GO_ROOT, package, "testdata", "fuzz", target, name)), str(saved / name))
        lines.append("| `{}` | `{}` | FAILED (exit {}; {}) |".format(
            package, target, code, "crashers: " + ", ".join(new) if new else "no new corpus file"))
    lines += ["", "{} of {} targets failed".format(failed, len(targets)) if failed else "all {} targets ok".format(len(targets))]
    go_ci.summarise(summary, lines)
    return 1 if failed else 0


def self_test():
    root = Path(tempfile.mkdtemp(prefix="go_fuzz_long_selftest_"))
    try:
        for path, text in {
                "a/a_test.go": "package a\n\nimport \"testing\"\n\nfunc FuzzOne(f *testing.F) {}\nfunc FuzzTwo( f *testing.F ) {}\n"
                               "func TestNot(t *testing.T) {}\nfunc FuzzHelper(t *testing.T) {}\n",
                "a/a.go": "package a\n\nfunc FuzzNotATest(f *testing.F) {}\n",
                "b/c/c_test.go": "package c\n\nimport \"testing\"\n\nfunc FuzzDeep(f *testing.F) {}\n",
                "vendor/x/x_test.go": "package x\n\nimport \"testing\"\n\nfunc FuzzVendored(f *testing.F) {}\n",
                "a/testdata/t_test.go": "package t\n\nfunc FuzzInTestdata(f *testing.F) {}\n",
                "root_test.go": "package r\n\nimport \"testing\"\n\nfunc FuzzRoot(f *testing.F) {}\n"}.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        found = discover(root)
        assert found == [(".", "FuzzRoot"), ("./a", "FuzzOne"), ("./a", "FuzzTwo"), ("./b/c", "FuzzDeep")], found
        corpus = root / "a/testdata/fuzz/FuzzOne"
        corpus.mkdir(parents=True)
        (corpus / "seed").write_text("go test fuzz v1\n", encoding="utf-8")
        assert corpus_files(root, "./a", "FuzzOne") == {"seed"}
        assert corpus_files(root, "./a", "FuzzTwo") == set()
    finally:
        shutil.rmtree(str(root), ignore_errors=True)
    assert per_target_seconds(80, 16) == 300
    assert per_target_seconds(5, 16) == 60                  # never under a minute
    assert per_target_seconds(80, 0) == 0
    assert parse_budget("80") == 80
    for bad in ("", "0", "-5", "1e3", "80; rm", str(MAX_BUDGET + 1)):
        try:
            parse_budget(bad)
        except ValueError:
            continue
        raise AssertionError("budget {!r} accepted".format(bad))
    print("go_fuzz_long self-test: ok (discovery, corpus snapshot, budget split, budget validation)")
    return 0


def parse_budget(text):
    """The dispatch input arrives as text: a whole number of minutes, 1..MAX_BUDGET, nothing else."""
    if not re.fullmatch(r"[0-9]{1,3}", text or "") or not 1 <= int(text) <= MAX_BUDGET:
        raise ValueError("budget must be a whole number of minutes from 1 to {}, got {!r}".format(MAX_BUDGET, text))
    return int(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--budget-minutes", default="80", help="total fuzzing time, split across the targets")
    parser.add_argument("--summary", help="append a markdown summary here (GITHUB_STEP_SUMMARY)")
    parser.add_argument("--out", default="fuzz-crashers", help="where new failing inputs are copied")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        budget = parse_budget(args.budget_minutes)
    except ValueError as error:
        print("go_fuzz_long: {}".format(error), file=sys.stderr)
        return 2
    return run(budget, args.summary, args.out)


if __name__ == "__main__":
    sys.exit(main())
