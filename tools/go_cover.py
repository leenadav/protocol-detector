"""Coverage floors for the Go engine (the `go-coverage` ci job), after Culvert's coverage-floor.sh.

`go test -coverpkg=./... -coverprofile=... ./...` runs in go/ on the pinned Go and the vendored tree, with no
module download. -coverpkg counts a statement as covered by any package's tests, so a parser that the parity
replay or the engine tests exercise is credited. The profile is reduced here: a block that several test
binaries report is counted once, covered when any of them ran it. The result is deterministic: two runs on
`0081f6f` produced byte-identical profiles.

tools/golint/coverage-floors.json holds the contract:
  global    the floor for the whole module (statements covered / statements);
  packages  a floor per package; every package under internal/protocols/ (the parsers of untrusted traffic)
            must have one, so a new parser cannot land without a floor.
The job fails when the total or a listed package is below its floor, when a parser package has no floor, or
when a listed package no longer exists (a floor that no longer follows its code). Floors are set at the
measured value minus 1.0 point, rounded down to one decimal (`--write-floors`), and are raised the same way
when coverage grows. Rule 16 locks the file, so lowering a floor is a reviewed change. A commit without
go/go.mod has nothing to measure and says so.

    go_cover.py [--summary FILE] [--write-floors]
    go_cover.py --self-test
Standard library only; Python 3.9 syntax.
"""
import argparse
import collections
import json
import math
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_ci  # noqa: E402  (the pinned Go, the vendor tree, the environment)

GO_ROOT = Path("go")
FLOORS = Path("tools/golint/coverage-floors.json")
PARSERS = "internal/protocols/"
MARGIN = 1.0
BLOCK = re.compile(r"^(?P<file>.+?):(?P<range>\d+\.\d+,\d+\.\d+) (?P<statements>\d+) (?P<count>\d+)$")
MODULE = re.compile(r"^module\s+(\S+)", re.M)


def parse_profile(text, module):
    """{package: [statements, covered]} and the module total, from a coverage profile; duplicate blocks once."""
    blocks = {}
    for line in (text or "").splitlines():
        match = BLOCK.match(line)
        if not match:
            continue
        key = (match.group("file"), match.group("range"))
        statements, covered = int(match.group("statements")), int(match.group("count")) > 0
        old = blocks.get(key)
        blocks[key] = (statements, covered or (old is not None and old[1]))
    packages = collections.defaultdict(lambda: [0, 0])
    for (path, _), (statements, covered) in blocks.items():
        package = path.rsplit("/", 1)[0]
        if module and (package == module or package.startswith(module + "/")):
            package = package[len(module) + 1:] or "."
        packages[package][0] += statements
        packages[package][1] += statements if covered else 0
    total = [sum(value[0] for value in packages.values()), sum(value[1] for value in packages.values())]
    return dict(packages), total


def percent(pair):
    return 100.0 * pair[1] / pair[0] if pair[0] else 100.0


def floor_of(value):
    """The floor for a measured percentage: minus the margin, rounded down to one decimal, never below 0."""
    return max(0.0, math.floor((value - MARGIN) * 10 + 1e-9) / 10)


def problems_for(packages, total, floors):
    problems = []
    if percent(total) < floors.get("global", 0):
        problems.append("module coverage {:.1f}% is below its floor {:.1f}%".format(percent(total), floors["global"]))
    listed = floors.get("packages") or {}
    for package, floor in sorted(listed.items()):
        if package not in packages:
            problems.append("{} has a floor but no longer exists: move the floor with its code".format(package))
        elif percent(packages[package]) < floor:
            problems.append("{} coverage {:.1f}% is below its floor {:.1f}%".format(package, percent(packages[package]), floor))
    for package in sorted(packages):
        if package.startswith(PARSERS) and package not in listed:
            problems.append("{} is a parser package without a coverage floor (add it with --write-floors)".format(package))
    return problems


def floors_for(packages, total):
    return {"global": floor_of(percent(total)),
            "packages": {package: floor_of(percent(packages[package])) for package in sorted(packages) if package.startswith(PARSERS)}}


def render_floors(floors):
    return json.dumps(floors, indent=1, sort_keys=True) + "\n"


def summary_lines(packages, total, floors, problems):
    lines = ["### Go coverage floors (go test -coverpkg=./...)", "",
             "Module: {:.1f}% of {} statements (floor {:.1f}%)".format(percent(total), total[0], floors.get("global", 0)), "",
             "| package | statements | coverage | floor |", "|---|---|---|---|"]
    listed = floors.get("packages") or {}
    for package in sorted(packages):
        floor = listed.get(package)
        lines.append("| `{}` | {} | {:.1f}% | {} |".format(package, packages[package][0], percent(packages[package]),
                                                          "{:.1f}%".format(floor) if floor is not None else ""))
    lines += [""] + ["- FAILED: " + problem for problem in problems] if problems else ["", "Every floor holds."]
    return lines


def run(summary, write):
    title = "### Go coverage floors (go test -coverpkg=./...)"
    tree, problems = go_ci.toolchain_problems()
    if tree is None:
        go_ci.summarise(summary, [title, "", "No {} on this commit: nothing to measure.".format(go_ci.GO_MOD)])
        return 0
    if problems:
        go_ci.summarise(summary, [title, ""] + ["- FAILED: " + problem for problem in problems])
        return 1
    module = MODULE.search(go_ci.read(go_ci.GO_MOD) or "")
    with tempfile.TemporaryDirectory(prefix="go-cover-") as scratch:
        profile = Path(scratch, "cover.out")
        result = subprocess.run(["go", "test", "-count=1", "-coverpkg=./...", "-coverprofile=" + str(profile), "./..."],  # noqa: S603,S607
                                cwd=str(GO_ROOT), env=go_ci.go_env(tree.get("vendored")), stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, check=False)
        text = profile.read_text(encoding="utf-8") if profile.is_file() else ""
    if result.returncode or not text:
        output = result.stdout.decode("utf-8", "replace").strip().splitlines()
        print("\n".join(output))     # the whole go test output stays in the job log
        go_ci.summarise(summary, [title, "", "- FAILED: go test exited {} (no coverage is measured on failing tests)".format(
            result.returncode)] + ["- `{}`".format(line) for line in failure_lines(output)])
        return 1
    packages, total = parse_profile(text, module.group(1) if module else None)
    if write:
        FLOORS.write_text(render_floors(floors_for(packages, total)), encoding="utf-8")
        floors = json.loads(FLOORS.read_text(encoding="utf-8"))
        go_ci.summarise(summary, summary_lines(packages, total, floors, []) + ["", "Floors rewritten in {}.".format(FLOORS)])
        return 0
    floors = json.loads(go_ci.read(FLOORS) or "{}")
    problems = problems_for(packages, total, floors)
    go_ci.summarise(summary, summary_lines(packages, total, floors, problems))
    return 1 if problems else 0


FAILURE = re.compile(r"^(--- FAIL|FAIL\s|panic:|fatal error:|\s+\S+_test\.go:\d+:|# \S+|\S+\.go:\d+:\d+: )")


def failure_lines(output, limit=60):
    """The lines of `go test` output that name what failed (failed tests and packages, panics, build errors), in
    order and at most `limit`; the last 20 lines when none matches, so the summary is never empty."""
    found = [line for line in output if FAILURE.match(line)]
    return (found or output[-20:])[:limit]


def self_test():
    module = "example.com/m/go"
    profile = ("mode: set\n"
               "example.com/m/go/internal/protocols/a/a.go:1.1,2.2 6 1\n"
               "example.com/m/go/internal/protocols/a/a.go:3.1,4.2 4 0\n"
               "example.com/m/go/internal/protocols/a/a.go:3.1,4.2 4 1\n"     # another test binary covered it
               "example.com/m/go/internal/x/x.go:1.1,2.2 10 0\n"
               "example.com/m/go/internal/x/x.go:1.1,2.2 10 0\n")
    packages, total = parse_profile(profile, module)
    assert packages == {"internal/protocols/a": [10, 10], "internal/x": [10, 0]}, packages
    assert total == [20, 10] and percent(total) == 50.0
    assert floor_of(79.04) == 78.0 and floor_of(88.05) == 87.0 and floor_of(0.5) == 0.0 and floor_of(24.41) == 23.4
    floors = floors_for(packages, total)
    assert floors == {"global": 49.0, "packages": {"internal/protocols/a": 99.0}}, floors
    assert problems_for(packages, total, floors) == []
    assert any("module coverage 50.0% is below its floor 51.0%" in p for p in problems_for(packages, total, dict(floors, **{"global": 51.0})))
    dropped = {"internal/protocols/a": [10, 5], "internal/x": [10, 0]}
    assert any("internal/protocols/a coverage 50.0% is below its floor 99.0%" in p for p in problems_for(dropped, [20, 5], floors))
    added = dict(packages, **{"internal/protocols/b": [4, 4]})
    assert any("internal/protocols/b is a parser package without a coverage floor" in p for p in problems_for(added, total, floors))
    moved = {"internal/x": [10, 0]}
    assert any("has a floor but no longer exists" in p for p in problems_for(moved, [10, 0], floors))
    assert json.loads(render_floors(floors)) == floors
    lines = summary_lines(dropped, [20, 5], floors, problems_for(dropped, [20, 5], floors))
    assert any(line.startswith("- FAILED:") for line in lines) and "| `internal/protocols/a` | 10 | 50.0% | 99.0% |" in lines, lines
    assert parse_profile("mode: set\n", module) == ({}, [0, 0])
    run = ["ok  \texample.com/m/go/a\t0.1s", "--- FAIL: TestX (0.00s)", "    x_test.go:12: got 1, want 2",
           "FAIL", "FAIL\texample.com/m/go/b\t0.2s", "ok  \texample.com/m/go/c\t0.1s"]
    assert failure_lines(run) == run[1:3] + run[4:5], failure_lines(run)
    assert failure_lines(["# example.com/m/go/b", "b/b.go:3:2: undefined: y", "ok  \tx"]) == [
        "# example.com/m/go/b", "b/b.go:3:2: undefined: y"]
    assert failure_lines(["panic: boom", "goroutine 1 [running]:"]) == ["panic: boom"]
    assert failure_lines(["ok  \tx"] * 30) == ["ok  \tx"] * 20
    assert len(failure_lines(["--- FAIL: T"] * 100)) == 60
    print("go_cover self-test: ok (profile merge across test binaries, floors, below-floor, missing parser floor, moved package, "
          "failing tests named in the summary)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--summary", help="append a markdown summary here (GITHUB_STEP_SUMMARY)")
    parser.add_argument("--write-floors", action="store_true", help="rewrite the floors at the measured values minus the margin")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    return run(args.summary, args.write_floors)


if __name__ == "__main__":
    sys.exit(main())
