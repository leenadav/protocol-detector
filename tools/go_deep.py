"""The Go engine's deep gate (the `go-determinism` and `go-licenses` ci jobs), after Culvert's pr-deep-gate.

  determinism  `go test -race -shuffle=on -count=2 ./...` in go/: every test twice, in a random order per run, with
               the race detector, so a test that depends on another's state, on execution order, or that fails
               only some of the time shows up. go test prints the order's seed (`-test.shuffle N`) with a
               failure; `go test -race -shuffle=N -count=2 ./<package>` reproduces it.
  licenses     go-licenses (built by the job from tools/golint/go-licenses/go.mod and go.sum, pinned like the lint
               tools) checks every module the engine's packages link: a licence of type forbidden or restricted,
               or one it cannot identify (unknown), fails. The engine's own module is left out (--ignore): it is
               this repository's code, not a dependency, and the repository has no LICENSE file for it to read.
               The report (module, licence) goes to the job summary; today the vendored golang.org/x/crypto and
               golang.org/x/sys are BSD-3-Clause, a notice type, and pass.

Both run on the pinned Go with the committed vendor tree and no module download (tools/go_ci.py; the jobs set
GOPROXY=off). A commit without go/go.mod has nothing to check and says so.

    go_deep.py determinism [--summary FILE]
    go_deep.py licenses --bin DIR [--summary FILE]
    go_deep.py --self-test
Standard library only; Python 3.9 syntax.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_ci  # noqa: E402  (the pinned Go, the vendor tree, the environment)

GO_ROOT = Path("go")
DETERMINISM = ["go", "test", "-race", "-shuffle=on", "-count=2", "./..."]
DISALLOWED = "forbidden,restricted,unknown"
MODULE = re.compile(r"^module\s+(\S+)", re.M)
RESULT = re.compile(r"^(ok|FAIL|---\s+FAIL:|panic:|-test\.shuffle\s+\d+)", re.M)


def module_path(gomod_text):
    match = MODULE.search(gomod_text or "")
    return match.group(1) if match else None


def licenses_commands(bin_dir, module):
    """The go-licenses check (fails on a disallowed or unidentified licence) and report (for the summary)."""
    tool = str(Path(bin_dir).resolve() / "go-licenses")
    return ([tool, "check", "--disallowed_types=" + DISALLOWED, "--ignore", module, "./..."],
            [tool, "report", "--ignore", module, "./..."])


def report_rows(text):
    """[(module, licence)] from go-licenses' CSV report (module,url,licence)."""
    rows = []
    for line in (text or "").splitlines():
        fields = line.split(",")
        if len(fields) >= 3 and fields[0] and not fields[0].startswith(("W1", "E1")):
            rows.append((fields[0], fields[-1]))
    return rows


def determinism_lines(output, code):
    """Summary lines from go test's output: the package results, failures and the shuffle seeds."""
    passed = len(re.findall(r"^ok\s", output, re.M))
    failed = [line for line in output.splitlines() if RESULT.match(line) and not line.startswith("ok")]
    lines = ["{} package(s) passed twice in shuffled order with -race".format(passed)]
    if code:
        lines += ["- FAILED: `{}`".format(line.strip()) for line in failed[:40]] or ["- FAILED: go test exited {}".format(code)]
    return lines


def run_determinism(summary):
    title = "### Go determinism (go test -race -shuffle=on -count=2)"
    tree, problems = go_ci.toolchain_problems()
    if tree is None:
        go_ci.summarise(summary, [title, "", "No {} on this commit: nothing to test.".format(go_ci.GO_MOD)])
        return 0
    if problems:
        go_ci.summarise(summary, [title, ""] + ["- FAILED: " + problem for problem in problems])
        return 1
    result = subprocess.run(DETERMINISM, cwd=str(GO_ROOT), env=go_ci.go_env(tree.get("vendored")),  # noqa: S603,S607
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    output = result.stdout.decode("utf-8", "replace")
    print(output)
    go_ci.summarise(summary, [title, ""] + determinism_lines(output, result.returncode))
    return 1 if result.returncode else 0


def run_licenses(bin_dir, summary):
    title = "### Go dependency licences (go-licenses, {} disallowed)".format(DISALLOWED)
    tree, problems = go_ci.toolchain_problems()
    if tree is None:
        go_ci.summarise(summary, [title, "", "No {} on this commit: nothing to check.".format(go_ci.GO_MOD)])
        return 0
    module = module_path(go_ci.read(go_ci.GO_MOD))
    if module is None:
        problems.append("{} names no module".format(go_ci.GO_MOD))
    if problems:
        go_ci.summarise(summary, [title, ""] + ["- FAILED: " + problem for problem in problems])
        return 1
    env = go_ci.go_env(tree.get("vendored"))
    check, report = licenses_commands(bin_dir, module)
    checked = subprocess.run(check, cwd=str(GO_ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)  # noqa: S603
    listed = subprocess.run(report, cwd=str(GO_ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)  # noqa: S603
    rows = report_rows(listed.stdout.decode("utf-8", "replace"))
    lines = [title, "", "| module | licence |", "|---|---|"] + ["| `{}` | {} |".format(name, kind) for name, kind in rows]
    if not rows:
        lines.append("| (no dependency linked) | |")
    if checked.returncode or listed.returncode:
        detail = [line for line in checked.stdout.decode("utf-8", "replace").splitlines()
                  if line and not line.startswith(("W1", "I1")) and "non-Go code" not in line and not line.endswith(".s")]
        lines += ["", "- FAILED: go-licenses check exited {}, report {}".format(checked.returncode, listed.returncode)]
        lines += ["- `{}`".format(line) for line in detail[:40]]
    else:
        lines += ["", "{} linked module(s); none forbidden, restricted or unidentified (the engine's own module, {}, is "
                      "excluded)".format(len(rows), module)]
    go_ci.summarise(summary, lines)
    return 1 if checked.returncode or listed.returncode else 0


def self_test():
    assert module_path("// c\nmodule github.com/x/y/go\n\ngo 1.27.4\n") == "github.com/x/y/go"
    assert module_path("go 1.27.4\n") is None
    check, report = licenses_commands("/opt/bin", "github.com/x/y/go")
    assert check == ["/opt/bin/go-licenses", "check", "--disallowed_types=forbidden,restricted,unknown",
                     "--ignore", "github.com/x/y/go", "./..."], check
    assert report[:2] == ["/opt/bin/go-licenses", "report"] and "--ignore" in report
    csv = ("golang.org/x/crypto,https://example/LICENSE,BSD-3-Clause\n"
           "W1121 20:40:04.992593 4904 library.go:141] contains non-Go code, x, y\n"
           "golang.org/x/sys/cpu,https://example/LICENSE,BSD-3-Clause\n")
    assert report_rows(csv) == [("golang.org/x/crypto", "BSD-3-Clause"), ("golang.org/x/sys/cpu", "BSD-3-Clause")]
    assert DETERMINISM == ["go", "test", "-race", "-shuffle=on", "-count=2", "./..."]
    ok = "ok  \tgithub.com/x/a\t1.2s\n?   \tgithub.com/x/b\t[no test files]\nok  \tgithub.com/x/c\t0.3s\n"
    assert determinism_lines(ok, 0) == ["2 package(s) passed twice in shuffled order with -race"]
    bad = ok + "-test.shuffle 1732211234\n--- FAIL: TestOrder (0.00s)\nFAIL\tgithub.com/x/d\t0.1s\nFAIL\n"
    lines = determinism_lines(bad, 1)
    assert "- FAILED: `-test.shuffle 1732211234`" in lines and any("TestOrder" in line for line in lines), lines
    assert determinism_lines("", 2)[-1] == "- FAILED: go test exited 2"
    print("go_deep self-test: ok (determinism command and summary, go-licenses commands, report parsing, module path)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", nargs="?", choices=("determinism", "licenses"))
    parser.add_argument("--bin", help="directory holding the pinned go-licenses (licenses mode)")
    parser.add_argument("--summary", help="append a markdown summary here (GITHUB_STEP_SUMMARY)")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.mode == "determinism":
        return run_determinism(args.summary)
    if args.mode == "licenses" and args.bin:
        return run_licenses(args.bin, args.summary)
    parser.error("give determinism, or licenses with --bin")
    return 2


if __name__ == "__main__":
    sys.exit(main())
