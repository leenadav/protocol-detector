"""Go lint and static analysis of the engine module (the `go-lint` ci job): golangci-lint, staticcheck, gosec.

The three tools are built by the job from tools/golint/<tool>/go.mod and go.sum (each pinned by version and by
every module hash, checked against the Go checksum database), and run here with --bin pointing at them, on the
committed vendor tree with no module download (tools/go_ci.py: the pinned Go, GOFLAGS=-mod=vendor, the job sets
GOPROXY=off):

  golangci-lint run --config tools/golint/golangci.yml ./...   (the linter set and its settings are in that file)
  staticcheck ./...                                             (its default checks)
  gosec -nosec -exclude=G104,G304 ./...                         (-nosec: in-code nosec comments are ignored)

gosec's two excluded rules, with their reasons:
  G104  unhandled errors: the same check as errcheck, which golangci-lint runs with its one documented exclusion
        (writes to the CLI's output); counting each finding twice adds nothing.
  G304  file path from a variable: every path the engine opens comes from its operator (command-line flags, the
        presentation's configuration, committed fixtures), never from inspected traffic; the passive classifier
        reads no path off the wire. Culvert's security gate excludes G304 for the same class of input.

A tool that cannot analyse the tree fails the job, whatever it reports: golangci-lint or staticcheck exiting
other than 0 or 1, a staticcheck `compile` diagnostic, and any gosec "Golang errors" entry. The last guards the
silent all-clear of a gosec whose loader cannot read the compiler's export data (it reports 0 issues).

Findings are compared with tools/golint/baseline.json: today's accepted findings, each by tool, rule, file and
message with a count (line numbers are left out, so an unrelated edit does not move them). A finding beyond the
baseline fails the job; a baseline entry no longer found is listed as removable. The baseline only shrinks:
`--write-baseline` rewrites it from the current findings, a reviewed change, and rule 16 locks it with the
configuration. A commit without go/go.mod has nothing to lint and says so.

    go_lint.py --bin DIR [--summary FILE] [--write-baseline]
    go_lint.py --self-test
Standard library only; Python 3.9 syntax.
"""
import argparse
import collections
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_ci  # noqa: E402  (the pinned Go, the vendor tree, the environment)

GO_ROOT = Path("go")
CONFIG = Path("tools/golint/golangci.yml")
BASELINE = Path("tools/golint/baseline.json")
GOSEC_EXCLUDES = ("G104", "G304")
TOOLS = ("golangci-lint", "staticcheck", "gosec")


def relative(path, root):
    """A finding's file relative to go/, with forward slashes."""
    text = str(path)
    root_text = str(Path(root).resolve())
    if os.path.isabs(text) and (text == root_text or text.startswith(root_text + os.sep)):
        text = os.path.relpath(text, root_text)
    return Path(text).as_posix()


def parse_golangci(text):
    """(findings, problems) from golangci-lint's JSON output."""
    try:
        issues = json.loads(text or "{}").get("Issues") or []
    except (ValueError, AttributeError) as error:
        return [], ["golangci-lint output is not JSON: {}".format(error)]
    return [("golangci-lint", issue.get("FromLinter", ""), (issue.get("Pos") or {}).get("Filename", ""),
             issue.get("Text", "")) for issue in issues], []


def parse_staticcheck(text, root):
    """(findings, problems) from `staticcheck -f json`, one JSON object per line; `compile` is a load failure."""
    findings, problems = [], []
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError as error:
            problems.append("staticcheck output line is not JSON: {}".format(error))
            continue
        location = item.get("location") or {}
        if item.get("code") == "compile":
            problems.append("staticcheck could not load {}: {}".format(relative(location.get("file", ""), root), item.get("message")))
            continue
        findings.append(("staticcheck", item.get("code", ""), relative(location.get("file", ""), root), item.get("message", "")))
    return findings, problems


def parse_gosec(text, root):
    """(findings, problems) from `gosec -fmt=json`; any "Golang errors" entry means files went unanalysed."""
    try:
        document = json.loads(text or "{}")
    except ValueError as error:
        return [], ["gosec output is not JSON: {}".format(error)]
    problems = ["gosec could not load {}: {}".format(relative(path, root), (errors or [{}])[0].get("error", ""))
                for path, errors in sorted((document.get("Golang errors") or {}).items())]
    findings = [("gosec", issue.get("rule_id", ""), relative(issue.get("file", ""), root), issue.get("details", ""))
                for issue in document.get("Issues") or []]
    return findings, problems


def counted(findings):
    return collections.Counter(findings)


def load_baseline(text):
    """Counter of (tool, rule, file, message) from the baseline document."""
    document = json.loads(text) if text else {"findings": []}
    return collections.Counter({(item["tool"], item["rule"], item["file"], item["message"]): item["count"]
                                for item in document.get("findings") or []})


def render_baseline(counts):
    """The baseline document, one finding per line so a change reviews line by line."""
    rows = [json.dumps({"tool": tool, "rule": rule, "file": path, "message": message, "count": count}, sort_keys=True)
            for (tool, rule, path, message), count in sorted(counts.items())]
    return '{"findings": [\n' + ",\n".join(rows) + "\n]}\n" if rows else '{"findings": []}\n'


def compare(current, baseline):
    """(new, removable): findings beyond the baseline, and baseline entries (or counts) no longer found."""
    return current - baseline, baseline - current


def run_tool(command, cwd, env, accept=(0, 1)):
    """(stdout, problem or None) of one tool run; exit codes outside `accept` mean the tool itself failed."""
    result = subprocess.run(command, cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)  # noqa: S603
    if result.returncode not in accept:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()[-3:]
        return "", "{} exited {}: {}".format(Path(command[0]).name, result.returncode, " / ".join(detail))
    return result.stdout.decode("utf-8", "replace"), None


def lint(bin_dir, env, root=GO_ROOT):
    """(findings, problems) of the three tools over the module at `root`."""
    bin_dir, root = Path(bin_dir).resolve(), Path(root)
    findings, problems = [], []
    out, problem = run_tool([str(bin_dir / "golangci-lint"), "run", "--config", str(CONFIG.resolve()),
                             "--output.json.path", "stdout", "--output.text.path", "stderr", "--show-stats=false", "./..."],
                            root, env)
    found, parsed = parse_golangci(out) if problem is None else ([], [problem])
    findings, problems = findings + found, problems + parsed
    out, problem = run_tool([str(bin_dir / "staticcheck"), "-f", "json", "./..."], root, env)
    found, parsed = parse_staticcheck(out, root) if problem is None else ([], [problem])
    findings, problems = findings + found, problems + parsed
    with tempfile.TemporaryDirectory(prefix="gosec-") as scratch:
        report = Path(scratch, "gosec.json")
        _, problem = run_tool([str(bin_dir / "gosec"), "-quiet", "-nosec", "-exclude=" + ",".join(GOSEC_EXCLUDES),
                               "-fmt=json", "-out=" + str(report), "./..."], root, env)
        text = report.read_text(encoding="utf-8") if report.is_file() else ""
        found, parsed = parse_gosec(text, root) if problem is None else ([], [problem])
    return findings + found, problems + parsed


def summary_lines(current, baseline, problems, written=False):
    lines = ["### Go lint and static analysis (golangci-lint, staticcheck, gosec)", ""]
    lines += ["- FAILED: " + problem for problem in problems]
    new, removable = compare(current, baseline)
    totals = collections.Counter()
    for (tool, _, _, _), count in current.items():
        totals[tool] += count
    lines.append("| tool | findings | in baseline |")
    lines.append("|---|---|---|")
    for tool in TOOLS:
        accepted = sum(count for key, count in (current & baseline).items() if key[0] == tool)
        lines.append("| {} | {} | {} |".format(tool, totals[tool], accepted))
    if written:
        lines += ["", "Baseline rewritten: {} finding(s) in {}.".format(sum(current.values()), BASELINE)]
        return lines
    for (tool, rule, path, message), count in sorted(new.items()):
        lines.append("- FAILED: new {} {} in `{}`: {}{}".format(tool, rule, path, message, " (x{})".format(count) if count > 1 else ""))
    if removable:
        lines.append("")
        lines.append("{} baseline finding(s) no longer occur; remove them with `tools/go_lint.py --write-baseline`:".format(
            sum(removable.values())))
        lines += ["- {} {} in `{}`: {}".format(tool, rule, path, message) for (tool, rule, path, message) in sorted(removable)]
    if not new and not problems:
        lines += ["", "No finding beyond the baseline ({} accepted).".format(sum(baseline.values()))]
    return lines


def run(bin_dir, summary, write_baseline):
    title = "### Go lint and static analysis (golangci-lint, staticcheck, gosec)"
    tree, problems = go_ci.toolchain_problems()
    if tree is None:
        go_ci.summarise(summary, [title, "", "No {} on this commit: nothing to lint.".format(go_ci.GO_MOD)])
        return 0
    if problems:
        go_ci.summarise(summary, [title, ""] + ["- FAILED: " + problem for problem in problems])
        return 1
    findings, problems = lint(bin_dir, go_ci.go_env(tree.get("vendored")))
    current = counted(findings)
    if write_baseline and not problems:
        BASELINE.write_text(render_baseline(current), encoding="utf-8")
        go_ci.summarise(summary, summary_lines(current, current, [], written=True))
        return 0
    baseline = load_baseline(go_ci.read(BASELINE))
    go_ci.summarise(summary, summary_lines(current, baseline, problems))
    new, _ = compare(current, baseline)
    return 1 if problems or new else 0


def self_test():
    root = Path("/work/go")
    golangci = json.dumps({"Issues": [{"FromLinter": "errcheck", "Text": "Error return value of `f.Close` is not checked",
                                       "Pos": {"Filename": "internal/a/a.go", "Line": 3}}], "Report": {}})
    assert parse_golangci(golangci) == ([("golangci-lint", "errcheck", "internal/a/a.go",
                                          "Error return value of `f.Close` is not checked")], [])
    assert parse_golangci('{"Issues": null}') == ([], [])
    assert parse_golangci("not json")[1]
    staticcheck = "\n".join([
        json.dumps({"code": "U1000", "location": {"file": "/work/go/internal/a/a.go", "line": 9}, "message": "func f is unused"}),
        json.dumps({"code": "compile", "location": {"file": "/work/go/internal/b/b.go"}, "message": "undefined: x"})])
    found, problems = parse_staticcheck(staticcheck, root)
    assert found == [("staticcheck", "U1000", "internal/a/a.go", "func f is unused")], found
    assert problems and "could not load internal/b/b.go" in problems[0], problems
    gosec = json.dumps({"Golang errors": {}, "Issues": [{"rule_id": "G115", "file": "/work/go/internal/c/c.go", "line": "4",
                                                        "details": "integer overflow conversion int -> uint16"}]})
    assert parse_gosec(gosec, root) == ([("gosec", "G115", "internal/c/c.go", "integer overflow conversion int -> uint16")], [])
    silent = json.dumps({"Golang errors": {"/work/go/cmd/x/main.go": [{"line": 1, "error": "could not import fmt"}]},
                         "Issues": []})
    assert parse_gosec(silent, root)[1] == ["gosec could not load cmd/x/main.go: could not import fmt"]   # never an all-clear
    assert relative("/elsewhere/x.go", root) == "/elsewhere/x.go" and relative("internal/a.go", root) == "internal/a.go"
    one = ("gosec", "G115", "internal/c/c.go", "integer overflow conversion int -> uint16")
    two = ("staticcheck", "U1000", "internal/a/a.go", "func f is unused")
    baseline = load_baseline(render_baseline(counted([one, one, two])))
    assert baseline == collections.Counter({one: 2, two: 1}), baseline
    assert load_baseline(render_baseline(collections.Counter())) == collections.Counter()
    assert compare(counted([one, one, two]), baseline) == (collections.Counter(), collections.Counter())
    new, removable = compare(counted([one, one, one]), baseline)
    assert new == collections.Counter({one: 1}) and removable == collections.Counter({two: 1}), (new, removable)
    lines = summary_lines(counted([one, one, one]), baseline, [])
    assert any(line.startswith("- FAILED: new gosec G115") and "internal/c/c.go" in line for line in lines), lines
    assert any("no longer occur" in line for line in lines), lines
    assert not any("FAILED" in line for line in summary_lines(counted([one]), baseline, [])), "a fixed finding fails nothing"
    assert any("FAILED: gosec could not load" in line for line in summary_lines(counted([]), baseline, ["gosec could not load x"]))
    text = render_baseline(baseline)
    assert text.count("\n") == 4 and text == render_baseline(load_baseline(text)), text   # one line per finding, stable
    print("go_lint self-test: ok (golangci/staticcheck/gosec parsing, load-failure detection, baseline compare and render)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bin", help="directory holding the pinned golangci-lint, staticcheck and gosec")
    parser.add_argument("--summary", help="append a markdown summary here (GITHUB_STEP_SUMMARY)")
    parser.add_argument("--write-baseline", action="store_true", help="rewrite tools/golint/baseline.json from the current findings")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.bin:
        parser.error("--bin is required")
    return run(args.bin, args.summary, args.write_baseline)


if __name__ == "__main__":
    sys.exit(main())
