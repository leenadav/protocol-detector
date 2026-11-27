#!/usr/bin/env python3
"""Mutation testing of the Go protocol parsers with gremlins (PRO-126), gated on a committed baseline.

gremlins (github.com/go-gremlins/gremlins, Apache-2.0, pinned in migration/mutation/gremlins/go.mod) mutates each
parser package's source (arithmetic, comparison boundaries, negated conditions, increments, sign inversions) and
runs that package's tests against every covered mutant. A mutant the tests catch is KILLED; one they miss LIVED.
Efficacy is killed / (killed + lived), in percent.

    mutation.py run --gremlins PATH [--packages tlsx,quicx] [--out build/mutation] [--summary FILE]
        runs gremlins on each package (from go/, offline and vendored), then compares like `check`;
    mutation.py check [--results build/mutation] [--summary FILE]
        reports killed, lived, not covered and efficacy per package and fails when a package's efficacy is more
        than TOLERANCE points below migration/mutation/baseline.json, or a baseline package has no result;
    mutation.py check --write-baseline
        records the results as the new baseline (after a reviewed improvement, or for a new package);
    mutation.py survivors [--results build/mutation] [--package tlsx] [--limit 20]
        lists the surviving (LIVED) mutants, file:line:column and mutator;
    mutation.py --self-test

This is a nightly job, never a per-PR gate: one full run takes tens of minutes. The tool is test-only; nothing
from it is linked into or vendored with the shipped engine. Standard library only; Python 3.9 syntax.
"""
import argparse
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "migration/mutation/baseline.json"
PACKAGES = ("tlsx", "textroute", "quicx", "x509x", "hpack", "dnsx", "fingerprint", "heuristics", "framed")
TOLERANCE = 5.0  # efficacy points a package may fall below its baseline before the nightly run fails
TIMEOUT_SHARE = 0.25  # more timed-out mutants than this share of those tested invalidates a package's run
CASES = ROOT / "migration/fixtures/cases.json"
CASES_ENV = "PROTODETECT_CASES"  # parsertest.CasesEnv: where the package tests read the frozen parity cases from
MEMORY_MB = 4096  # address-space cap per process (gremlins, go, the compiler, each mutant's test binary)


def summarise(report):
    """killed, lived, not covered, timed out and efficacy (percent, None without killed or lived) of one report."""
    killed, lived = int(report.get("mutants_killed", 0)), int(report.get("mutants_lived", 0))
    efficacy = round(100.0 * killed / (killed + lived), 2) if killed + lived else None
    return {"killed": killed, "lived": lived, "not_covered": int(report.get("mutants_not_covered", 0)),
            "timed_out": int(report.get("mutants_timed_out", 0)), "efficacy": efficacy}


def survivors(report):
    """The LIVED mutants of one report as (file, line, column, mutator), sorted."""
    out = []
    for item in report.get("files") or []:
        for mutation in item.get("mutations") or []:
            if mutation.get("status") == "LIVED":
                out.append((item.get("file_name", "?"), int(mutation.get("line", 0)), int(mutation.get("column", 0)),
                            mutation.get("type", "?")))
    return sorted(out)


def compare(results, baseline, tolerance=TOLERANCE):
    """Problems: a baseline package with no result, or one whose efficacy fell more than `tolerance` points."""
    problems = []
    for package, base in sorted(baseline.items()):
        now = results.get(package)
        if now is None:
            problems.append("{}: no mutation result (the baseline has efficacy {})".format(package, base.get("efficacy")))
            continue
        tested = now.get("killed", 0) + now.get("lived", 0) + now.get("timed_out", 0)
        if now.get("timed_out", 0) > TIMEOUT_SHARE * tested:  # the reference test time was wrong (a cached run)
            problems.append("{}: {} of {} tested mutants timed out; the run is not a measurement".format(
                package, now["timed_out"], tested))
            continue
        if base.get("efficacy") is None:
            continue
        if now["efficacy"] is None:  # nothing covered: the tests did not run (a crash, an out-of-memory kill)
            problems.append("{}: no mutant was covered (the baseline has efficacy {:.2f}%)".format(package, base["efficacy"]))
            continue
        if now["efficacy"] < base["efficacy"] - tolerance:
            problems.append("{}: efficacy {:.2f}% is more than {} points below the baseline {:.2f}%".format(
                package, now["efficacy"], tolerance, base["efficacy"]))
    return problems


def table(results, baseline):
    lines = ["| package | killed | lived | not covered | efficacy | baseline |", "|---|---|---|---|---|---|"]
    for package in sorted(results):
        r, b = results[package], baseline.get(package, {})
        lines.append("| {} | {} | {} | {} | {} | {} |".format(
            package, r["killed"], r["lived"], r["not_covered"],
            "-" if r["efficacy"] is None else "{:.2f}%".format(r["efficacy"]),
            "-" if b.get("efficacy") is None else "{:.2f}%".format(b["efficacy"])))
    return lines


def load_results(folder):
    results = {}
    for path in sorted(Path(folder).glob("*.json")):
        results[path.stem] = summarise(json.loads(path.read_text(encoding="utf-8")))
    return results


def write_summary(path, lines):
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")


def check(folder, summary, write_baseline, only=None):
    """Compare the results with the baseline; `only` limits both to the packages a partial run asked for."""
    results = load_results(folder)
    if only is not None:
        results = {k: v for k, v in results.items() if k in only}
    if not results:
        print("mutation: no results in {}".format(folder))
        return 1
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))["packages"] if BASELINE.is_file() else {}
    if write_baseline:
        BASELINE.write_text(json.dumps({"tolerance": TOLERANCE, "tool": "github.com/go-gremlins/gremlins v0.6.0",
                                        "packages": results}, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print("mutation: baseline written for {} packages".format(len(results)))
        return 0
    if only is not None:
        baseline = {k: v for k, v in baseline.items() if k in only}
    problems = compare(results, baseline)
    lines = ["### Mutation testing (gremlins)", ""] + table(results, baseline) + [""]
    lines += ["- FAILED: " + p for p in problems] or ["- every package is within {} points of its baseline".format(TOLERANCE)]
    print("\n".join(lines))
    write_summary(summary, lines)
    return 1 if problems else 0


def tool_path(gremlins):
    """An absolute path for a gremlins binary given with a directory part: it runs from go/, not from here. A bare
    name is left to PATH."""
    return str(Path(gremlins).resolve()) if os.sep in gremlins or (os.altsep and os.altsep in gremlins) else gremlins


def address_limit(megabytes):
    """A preexec function capping the address space of gremlins and everything it starts (go, the compiler, each
    mutant's test binary). A mutant that removes an allocation bound then fails fast with "out of memory" (and counts
    as killed) instead of growing until the kernel kills a random process of the runner."""
    def limit():
        import resource  # Unix only; the nightly job runs on Linux
        resource.setrlimit(resource.RLIMIT_AS, (megabytes << 20, megabytes << 20))
    return limit


def run_env(base=None):
    """The environment gremlins and each mutant's tests run in. gremlins tests every mutant in a temporary copy of
    go/ alone, so a test's relative path up to migration/fixtures/ does not resolve there; without the absolute
    path in CASES_ENV every covered mutant of tlsx and textroute failed to load the fixtures and counted as killed
    (a false 100%, PRO-521)."""
    return dict(os.environ if base is None else base, GOFLAGS="-mod=vendor", **{CASES_ENV: str(CASES)})


def run(gremlins, packages, folder, summary, memory_mb=MEMORY_MB):
    gremlins = tool_path(gremlins)
    if not CASES.is_file():
        print("mutation: {} is missing; the package tests read it through {}".format(CASES, CASES_ENV))
        return 1
    Path(folder).mkdir(parents=True, exist_ok=True)
    env = run_env()
    for package in packages:
        out = Path(folder, package + ".json").resolve()
        if out.is_file():
            out.unlink()  # a stale report must not stand in for a failed run
        # gremlins times each mutant against its first (coverage) test run; a cached result makes that time near
        # zero, and then every mutant "times out". Clear the test cache so the reference time is a real run.
        subprocess.run(["go", "clean", "-testcache"], cwd=str(ROOT / "go"), env=env, check=True)  # noqa: S603,S607
        done = subprocess.run([gremlins, "unleash", "./internal/protocols/" + package, "--workers", "4",  # noqa: S603
                               "--timeout-coefficient", "10", "-o", str(out)], cwd=str(ROOT / "go"), env=env, check=False,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                              preexec_fn=address_limit(memory_mb))  # noqa: PLW1509 (no threads in this process)
        Path(folder, package + ".log").write_text(done.stdout, encoding="utf-8")
        if done.returncode != 0 or not out.is_file():
            print("mutation: gremlins failed on {} (exit {}): {}".format(package, done.returncode, done.stdout[-500:]))
            return 1
        print("mutation: {} {}".format(package, summarise(json.loads(out.read_text(encoding="utf-8")))))
    return check(folder, summary, False, None if set(packages) >= set(PACKAGES) else set(packages))


def self_test():
    report = {"mutants_killed": 3, "mutants_lived": 1, "mutants_not_covered": 2,
              "files": [{"file_name": "a.go", "mutations": [{"line": 9, "column": 2, "type": "CONDITIONALS_BOUNDARY", "status": "LIVED"},
                                                              {"line": 3, "column": 1, "type": "ARITHMETIC_BASE", "status": "KILLED"}]}]}
    assert summarise(report) == {"killed": 3, "lived": 1, "not_covered": 2, "timed_out": 0, "efficacy": 75.0}
    assert summarise({}) == {"killed": 0, "lived": 0, "not_covered": 0, "timed_out": 0, "efficacy": None}
    assert survivors(report) == [("a.go", 9, 2, "CONDITIONALS_BOUNDARY")]
    base = {"tlsx": {"efficacy": 80.0}, "quicx": {"efficacy": 70.0}}
    assert compare({"tlsx": {"efficacy": 75.0}, "quicx": {"efficacy": 70.0}}, base) == []        # exactly 5 below: ok
    assert compare({"tlsx": {"efficacy": 90.0}, "quicx": {"efficacy": 70.0}}, base) == []        # an improvement
    dropped = compare({"tlsx": {"efficacy": 74.99}, "quicx": {"efficacy": 70.0}}, base)
    assert len(dropped) == 1 and "tlsx" in dropped[0], dropped                                  # more than 5 below
    uncovered = compare({"tlsx": {"efficacy": None}, "quicx": {"efficacy": 70.0}}, base)
    assert len(uncovered) == 1 and "tlsx: no mutant was covered" in uncovered[0], uncovered  # tests did not run
    timed = compare({"tlsx": {"efficacy": 100.0, "killed": 8, "lived": 0, "timed_out": 340}, "quicx": {"efficacy": 70.0}}, base)
    assert len(timed) == 1 and "340 of 348 tested mutants timed out" in timed[0], timed
    assert compare({"tlsx": {"efficacy": 80.0, "killed": 90, "lived": 10, "timed_out": 9}, "quicx": {"efficacy": 70.0}}, base) == []
    missing = compare({"tlsx": {"efficacy": 80.0}}, base)
    assert len(missing) == 1 and "quicx: no mutation result" in missing[0], missing
    assert compare({"dnsx": {"efficacy": None}}, {"dnsx": {"efficacy": None}}) == []           # never covered
    env = run_env({"PATH": "/bin", CASES_ENV: "../stale.json"})
    assert env[CASES_ENV] == str(CASES) and Path(env[CASES_ENV]).is_absolute(), env               # survives a copy of go/
    assert env["GOFLAGS"] == "-mod=vendor" and env["PATH"] == "/bin", env
    assert tool_path("gremlins") == "gremlins"                                                   # left to PATH
    assert tool_path("build/mutation-bin/gremlins") == str(Path.cwd() / "build/mutation-bin/gremlins")
    with tempfile.TemporaryDirectory() as folder:
        Path(folder, "tlsx.json").write_text(json.dumps(report), encoding="utf-8")
        assert load_results(folder) == {"tlsx": summarise(report)}
        Path(folder, "tlsx.json").write_text(json.dumps({"mutants_killed": 10}), encoding="utf-8")  # 100%
        with contextlib.redirect_stdout(io.StringIO()):
            assert check(folder, None, False, {"tlsx"}) == 0       # a partial run compares only what it ran
            assert check(folder, None, False, None) == 1           # a full run misses the other baseline packages
    print("mutation self-test: ok (summary, survivors, 5-point gate, missing package, uncovered package, mostly timed out, never-covered package, absolute fixtures path, tool path, partial run)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", nargs="?", choices=("run", "check", "survivors"))
    parser.add_argument("--gremlins", help="the gremlins binary (run)")
    parser.add_argument("--packages", default=",".join(PACKAGES), help="comma-separated packages under go/internal/protocols")
    parser.add_argument("--results", "--out", dest="folder", default=str(ROOT / "build/mutation"))
    parser.add_argument("--summary", help="append the markdown table here (a CI step summary)")
    parser.add_argument("--write-baseline", action="store_true")
    parser.add_argument("--package", help="survivors: one package")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--memory-mb", type=int, default=MEMORY_MB, help="run: address-space cap per process")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.command == "run":
        if not args.gremlins:
            parser.error("run needs --gremlins")
        return run(args.gremlins, [p for p in args.packages.split(",") if p], args.folder, args.summary, args.memory_mb)
    if args.command == "check":
        return check(args.folder, args.summary, args.write_baseline)
    if args.command == "survivors":
        names = [args.package] if args.package else sorted(p.stem for p in Path(args.folder).glob("*.json"))
        for name in names:
            report = json.loads(Path(args.folder, name + ".json").read_text(encoding="utf-8"))
            for file_name, line, column, kind in survivors(report)[:args.limit]:
                print("{} {}:{}:{} {}".format(name, file_name, line, column, kind))
        return 0
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
