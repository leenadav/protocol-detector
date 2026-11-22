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
        if base.get("efficacy") is None or now["efficacy"] is None:
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


def check(folder, summary, write_baseline):
    results = load_results(folder)
    if not results:
        print("mutation: no results in {}".format(folder))
        return 1
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))["packages"] if BASELINE.is_file() else {}
    if write_baseline:
        BASELINE.write_text(json.dumps({"tolerance": TOLERANCE, "tool": "github.com/go-gremlins/gremlins v0.6.0",
                                        "packages": results}, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print("mutation: baseline written for {} packages".format(len(results)))
        return 0
    problems = compare(results, baseline)
    lines = ["### Mutation testing (gremlins)", ""] + table(results, baseline) + [""]
    lines += ["- FAILED: " + p for p in problems] or ["- every package is within {} points of its baseline".format(TOLERANCE)]
    print("\n".join(lines))
    write_summary(summary, lines)
    return 1 if problems else 0


def run(gremlins, packages, folder, summary):
    Path(folder).mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GOFLAGS="-mod=vendor")
    for package in packages:
        out = Path(folder, package + ".json").resolve()
        done = subprocess.run([gremlins, "unleash", "./internal/protocols/" + package, "--workers", "4",  # noqa: S603
                               "--timeout-coefficient", "10", "-o", str(out)], cwd=str(ROOT / "go"), env=env, check=False,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if done.returncode != 0 or not out.is_file():
            print("mutation: gremlins failed on {} (exit {}): {}".format(package, done.returncode, done.stdout[-500:]))
            return 1
        print("mutation: {} {}".format(package, summarise(json.loads(out.read_text(encoding="utf-8")))))
    return check(folder, summary, False)


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
    missing = compare({"tlsx": {"efficacy": 80.0}}, base)
    assert len(missing) == 1 and "quicx: no mutation result" in missing[0], missing
    assert compare({"tlsx": {"efficacy": None}, "quicx": {"efficacy": 70.0}}, base) == []       # nothing covered
    with tempfile.TemporaryDirectory() as folder:
        Path(folder, "tlsx.json").write_text(json.dumps(report), encoding="utf-8")
        assert load_results(folder) == {"tlsx": summarise(report)}
    print("mutation self-test: ok (summary, survivors, 5-point gate, missing package, empty package)")
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
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.command == "run":
        if not args.gremlins:
            parser.error("run needs --gremlins")
        return run(args.gremlins, [p for p in args.packages.split(",") if p], args.folder, args.summary)
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
