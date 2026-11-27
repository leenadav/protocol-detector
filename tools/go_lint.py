"""Go lint and static analysis of the engine module (the `go-lint` ci job): golangci-lint, staticcheck, gosec.

The three tools are built by the job from tools/golint/<tool>/go.mod and go.sum (each pinned by version and by
every module hash, checked against the Go checksum database), and run here with --bin pointing at them, on the
committed vendor tree with no module download (tools/go_ci.py: the pinned Go, GOFLAGS=-mod=vendor, the job sets
GOPROXY=off):

  golangci-lint run --config tools/golint/golangci.yml ./...   (the linter set and its settings are in that file)
  staticcheck ./...                                             (its default checks)
  gosec -nosec -exclude=G104,G304 ./...                         (-nosec: in-code nosec comments are ignored;
                                                                 nested modules such as go/oracle, which carry
                                                                 their own go.mod, are excluded with -exclude-dir)

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
message with a count (line numbers are left out, so an unrelated edit does not move them). A gosec finding under
internal/protocols/ or internal/decrypt/ also names its enclosing function, so fixing one finding and adding
another with the same message elsewhere in that file is a new finding (SEC-CI-A12-3). A finding beyond the
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
import re
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


# gosec findings in these trees are keyed by their enclosing function as well (SEC-CI-A12-3): they parse attacker
# bytes, and a file-wide key let a fixed G115 hide a new one with the same message elsewhere in the file.
SCOPED_GOSEC = ("internal/protocols/", "internal/decrypt/")
GO_FUNC = re.compile(r"^func\s*(?:\(\s*(?:\w+\s+)?(\*?)\s*([\w.]+)(?:\[[^\]]*\])?\s*\))?\s*(\w+)")


def enclosing_function(source, line):
    """`Name`, `T.Name` or `(*T).Name` of the top-level func declared last at or before `line` (1-based), else None.

    A top-level declaration starts in column 0 under gofmt, so a closure belongs to the func that holds it. A line
    after the closing `}` of a func at column 0 and before the next func is package scope.
    """
    current, closed = None, False
    for text in (source or "").split("\n")[:max(line, 0)]:   # gosec counts "\n" only, not every splitlines() separator
        if closed:
            current, closed = None, False
        match = GO_FUNC.match(text)
        if match:
            star, receiver, name = match.groups()
            current = name if not receiver else ("(*{}).{}".format(receiver, name) if star else "{}.{}".format(receiver, name))
            closed = text.rstrip().endswith("}")               # a one-line func ends on its own line
        elif current and text.startswith("}"):
            current = None
    return current


def gosec_scope(path, line, read_source):
    """The " [in F]" suffix for a gosec finding in SCOPED_GOSEC, or "" elsewhere."""
    if not path.startswith(SCOPED_GOSEC):
        return ""
    number = re.match(r"\d+", str(line or ""))
    function = enclosing_function(read_source(path), int(number.group(0))) if number else None
    return " [in {}]".format(function or "package scope")


def parse_gosec(text, root, read_source=None):
    """(findings, problems) from `gosec -fmt=json`; any "Golang errors" entry means files went unanalysed.

    A finding under SCOPED_GOSEC carries its enclosing function in the message, " [in (*T).F]".
    """
    if read_source is None:
        def read_source(path):
            try:
                return Path(root, path).read_text(encoding="utf-8")
            except OSError:
                return ""
    try:
        document = json.loads(text or "{}")
    except ValueError as error:
        return [], ["gosec output is not JSON: {}".format(error)]
    problems = ["gosec could not load {}: {}".format(relative(path, root), (errors or [{}])[0].get("error", ""))
                for path, errors in sorted((document.get("Golang errors") or {}).items())]
    findings = []
    for issue in document.get("Issues") or []:
        path = relative(issue.get("file", ""), root)
        findings.append(("gosec", issue.get("rule_id", ""), path,
                         issue.get("details", "") + gosec_scope(path, issue.get("line"), read_source)))
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


def nested_modules(root):
    """Directories under root (relative, sorted) that hold their own go.mod: separate modules, not the engine's.

    golangci-lint and staticcheck stop at a module boundary under ./..., but gosec walks into a nested module and
    then fails to load it with the engine's -mod=vendor (go/oracle, a test-only module with no vendor tree). Each
    such directory is excluded from gosec by name, found from the tree, so a new nested module needs no edit here.
    """
    root = Path(root)
    found = []
    for gomod in root.rglob("go.mod"):
        parts = gomod.relative_to(root).parts
        if len(parts) > 1 and "vendor" not in parts:
            found.append("/".join(parts[:-1]))
    return sorted(found)


def shadowed_packages(listed, root, nested):
    """Engine package directories (from `go list -f {{.Dir}} ./...`) whose path contains a nested module's name.

    gosec matches -exclude-dir as a pattern anywhere in a path, so excluding "oracle" would also drop an engine
    package such as internal/oracle; such a package must fail the run, never be skipped silently.
    """
    prefix = str(Path(root).resolve()).rstrip("/") + "/"
    packages = [line[len(prefix):] if line.startswith(prefix) else line for line in listed.splitlines() if line.strip()]
    return sorted(package for package in packages for name in nested if name in package)


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
        nested = nested_modules(root)
        listed, problem = run_tool(["go", "list", "-f", "{{.Dir}}", "./..."], root, env, accept=(0,))
        if problem is not None:
            return findings, problems + [problem]
        shadowed = shadowed_packages(listed, root, nested)
        if shadowed:
            return findings, problems + ["gosec -exclude-dir for a nested module would also skip engine package(s) {}"
                                         .format(", ".join(shadowed))]
        excluded = ["-exclude-dir=" + directory for directory in nested]
        _, problem = run_tool([str(bin_dir / "gosec"), "-quiet", "-nosec", "-exclude=" + ",".join(GOSEC_EXCLUDES)]
                              + excluded + ["-fmt=json", "-out=" + str(report), "./..."], root, env)
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
    with tempfile.TemporaryDirectory() as tree:
        for path in ("go.mod", "internal/a/a.go", "oracle/go.mod", "tools/x/go.mod", "vendor/m/go.mod"):
            Path(tree, path).parent.mkdir(parents=True, exist_ok=True)
            Path(tree, path).write_text("", encoding="utf-8")
        assert nested_modules(tree) == ["oracle", "tools/x"], nested_modules(tree)
    assert shadowed_packages("/r/go\n/r/go/internal/engine\n", "/r/go", ["oracle"]) == []
    assert shadowed_packages("/r/go/internal/oracle\n", "/r/go", ["oracle"]) == ["internal/oracle"]
    source = ("package p\n\nvar table = uint16(1)\n\nfunc Plain(n int) uint16 {\n\treturn uint16(n)\n}\n\n"
              "func (p *Parser) Read(n int) byte {\n\tf := func() byte { return byte(n) }\n\treturn f()\n}\n\n"
              "func (s Set[T]) Len() uint8 { return uint8(len(s)) }\nvar after = byte(2)\n")
    assert [enclosing_function(source, n) for n in (3, 6, 10, 11, 14)] == [None, "Plain", "(*Parser).Read", "(*Parser).Read",
                                                                          "Set.Len"]
    assert enclosing_function("func A() {\n\t// \x0c \u2028\n}\nfunc B() {\n\tx()\n}\n", 5) == "B", "line numbers count newlines only"
    assert enclosing_function(source, 15) is None, "a line after a one-line func is package scope"
    assert enclosing_function(source, 8) is None and enclosing_function(source, 0) is None and enclosing_function("", 4) is None

    def scoped(rule_lines, path="internal/protocols/x/x.go"):
        issues = [{"rule_id": "G115", "file": "/work/go/" + path, "line": line, "details": "integer overflow conversion int -> uint16"}
                  for line in rule_lines]
        return counted(parse_gosec(json.dumps({"Issues": issues}), root, lambda _: source)[0])
    assert list(scoped(["6"])) == [("gosec", "G115", "internal/protocols/x/x.go", "integer overflow conversion int -> uint16 [in Plain]")]
    assert list(scoped(["3"]))[0][3].endswith("[in package scope]") and list(scoped(["10-11"]))[0][3].endswith("[in (*Parser).Read]")
    assert list(scoped(["6"], "internal/decrypt/d.go"))[0][3].endswith("[in Plain]")
    assert list(scoped(["6"], "internal/engine/e.go"))[0][3] == "integer overflow conversion int -> uint16"   # other trees: by file
    # the A12-3 negative: one finding fixed in Plain, another with the same message added in Read, is new
    new, removable = compare(scoped(["10"]), scoped(["6"]))
    assert sum(new.values()) == 1 and sum(removable.values()) == 1, (new, removable)
    assert any(line.startswith("- FAILED: new gosec G115") and "[in (*Parser).Read]" in line
               for line in summary_lines(scoped(["10"]), scoped(["6"]), [])), "a moved finding must fail"
    new, _ = compare(scoped(["6", "6"]), scoped(["6"]))
    assert sum(new.values()) == 1, "a second finding in the same function is still counted"
    print("go_lint self-test: ok (gosec keyed by function under internal/protocols/ and internal/decrypt/, golangci/staticcheck/gosec parsing, load-failure detection, baseline compare and render)")
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
