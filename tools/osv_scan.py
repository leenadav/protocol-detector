#!/usr/bin/env python3
"""Known vulnerabilities in every committed lockfile, from the OSV database (the `osv-scan` ci job).

osv-scanner (built by the job from tools/golint/osv-scanner/go.mod and go.sum, pinned like the lint tools) reads
every lockfile git tracks and asks api.osv.dev about each pinned package:

  Python  requirements*.txt and *.lock.txt (hash-pinned; parsed as requirements.txt)
  npm     package-lock.json
  Go      go.mod (the engine's go/go.mod, whose vendor tree it pins, and every CI tool module)

Every finding fails unless tools/osv_ignore.json names it, for that lockfile and package, with a reason and an
expiry date. Each entry needs exactly the keys id, lockfile, package, reason and expires; `expires` is a date
after today and at most MAX_DAYS ahead, so an accepted risk is looked at again. An entry that matches no finding
(fixed, or misnamed) fails too, so the list cannot go stale. osv-scanner runs with an empty config, so no
osv-scanner.toml in the tree can ignore anything on its own, and a lockfile it did not read fails the run.

govulncheck (toolchain-audit) stays the reachability check for Go: OSV reports every vulnerability in a pinned
module version, govulncheck only those whose symbols the built code calls.

    osv_scan.py --bin DIR [--summary FILE] [--today YYYY-MM-DD]
    osv_scan.py --self-test
Standard library only; Python 3.9 syntax.
"""
import argparse
import datetime
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_ci  # noqa: E402  (summarise)

IGNORE_FILE = Path("tools/osv_ignore.json")
ENTRY_KEYS = {"id", "lockfile", "package", "reason", "expires"}
MAX_DAYS = 90
MIN_REASON = 40
LOCKFILE = re.compile(r"(^|/)(requirements[^/]*\.txt|[^/]*\.lock\.txt|package-lock\.json|go\.mod)$")
SCANNED = re.compile(r"^Scanned (.+?) file and found (\d+) packages?")


def lockfiles(tracked):
    """The tracked lockfiles osv-scanner reads, never a vendored copy, sorted."""
    return sorted(path for path in tracked if LOCKFILE.search(path) and "/vendor/" not in "/" + path)


def lockfile_arg(path):
    name = path.rsplit("/", 1)[-1]
    if name.endswith(".txt") and name != "requirements.txt":
        return "requirements.txt:" + path
    return path


def scan_command(binary, config, paths):
    command = [binary, "scan", "source", "--config", config, "--format", "json"]
    for path in paths:
        command += ["-L", lockfile_arg(path)]
    return command


def entry_problems(entries, today):
    problems = []
    if not isinstance(entries, list):
        return ["{}: `entries` must be a list".format(IGNORE_FILE)]
    seen = set()
    for number, entry in enumerate(entries, 1):
        where = "{} entry {}".format(IGNORE_FILE, number)
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            problems.append("{}: needs exactly the keys {}".format(where, ", ".join(sorted(ENTRY_KEYS))))
            continue
        if any(not isinstance(entry[key], str) or not entry[key].strip() for key in ENTRY_KEYS):
            problems.append("{}: every value must be a non-empty string".format(where))
            continue
        key = (entry["id"], entry["lockfile"], entry["package"])
        if key in seen:
            problems.append("{}: duplicate of an earlier entry ({})".format(where, entry["id"]))
        seen.add(key)
        if len(entry["reason"].strip()) < MIN_REASON:
            problems.append("{} ({}): the reason must say why the risk is accepted (at least {} characters)".format(
                where, entry["id"], MIN_REASON))
        try:
            expires = datetime.date.fromisoformat(entry["expires"])
        except ValueError:
            problems.append("{} ({}): `expires` must be a date, YYYY-MM-DD".format(where, entry["id"]))
            continue
        if expires <= today:
            problems.append("{} ({}): expired on {}: fix the dependency or review the risk again".format(
                where, entry["id"], entry["expires"]))
        elif (expires - today).days > MAX_DAYS:
            problems.append("{} ({}): expires more than {} days ahead ({})".format(where, entry["id"], MAX_DAYS,
                                                                                    entry["expires"]))
    return problems


def findings(report, root):
    """(lockfile, package, version, ids) for each vulnerability group in osv-scanner's JSON report."""
    found = []
    prefix = str(root).rstrip("/") + "/"
    for result in report.get("results") or []:
        path = result["source"]["path"]
        path = path[len(prefix):] if path.startswith(prefix) else path
        for package in result.get("packages") or []:
            name, version = package["package"]["name"], package["package"].get("version", "")
            for group in package.get("groups") or []:
                ids = set(group.get("ids") or []) | set(group.get("aliases") or [])
                found.append((path, name, version, ids))
    return found


def decide(found, entries, scanned, expected):
    """Problems (each fails the run) and the accepted findings."""
    problems, accepted, used = [], [], set()
    for path in expected:
        if path not in scanned:
            problems.append("{}: osv-scanner did not read this lockfile".format(path))
    for path, name, version, ids in found:
        match = [number for number, entry in enumerate(entries)
                 if entry["lockfile"] == path and entry["package"] == name and entry["id"] in ids]
        if match:
            used.update(match)
            accepted.append((path, name, version, sorted(ids)[0]))
        else:
            problems.append("{}: {} {}: {} (not in {})".format(path, name, version, ", ".join(sorted(ids)), IGNORE_FILE))
    for number, entry in enumerate(entries):
        if number not in used:
            problems.append("{} entry {} ({}, {}): matches no finding; remove it".format(
                IGNORE_FILE, number + 1, entry["id"], entry["lockfile"]))
    return problems, accepted


def run(bin_dir, summary, today):
    title = "### Known vulnerabilities in the lockfiles (osv-scanner, OSV database)"
    root = Path.cwd()
    tracked = subprocess.run(["git", "ls-files"], stdout=subprocess.PIPE, check=True).stdout.decode().split()  # noqa: S603,S607
    paths = lockfiles(tracked)
    document = json.loads(IGNORE_FILE.read_text(encoding="utf-8"))
    entries = document.get("entries")
    problems = entry_problems(entries, today)
    if problems:
        go_ci.summarise(summary, [title, ""] + ["- FAILED: " + problem for problem in problems])
        return 1
    with tempfile.TemporaryDirectory() as scratch:
        config = Path(scratch) / "empty.toml"
        config.write_text("", encoding="utf-8")
        result = subprocess.run(scan_command(str(Path(bin_dir) / "osv-scanner"), str(config), paths),  # noqa: S603
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    log = result.stderr.decode("utf-8", "replace")
    if result.returncode not in (0, 1):
        go_ci.summarise(summary, [title, "", "- FAILED: osv-scanner exited {}".format(result.returncode)]
                        + ["- `{}`".format(line) for line in log.splitlines()[-20:]])
        return 1
    scanned = {}
    for line in log.splitlines():
        match = SCANNED.match(line.strip())
        if match:
            path = match.group(1)
            scanned[path[len(str(root)) + 1:] if path.startswith(str(root) + "/") else path] = int(match.group(2))
    found = findings(json.loads(result.stdout.decode("utf-8") or "{}"), root)
    problems, accepted = decide(found, entries, scanned, paths)
    lines = [title, "", "| lockfile | packages | findings | accepted |", "|---|---|---|---|"]
    for path in paths:
        here = [item for item in found if item[0] == path]
        lines.append("| `{}` | {} | {} | {} |".format(path, scanned.get(path, "not read"), len(here),
                                                     len([item for item in accepted if item[0] == path])))
    lines += ["", "{} lockfile(s), {} package(s), {} finding(s), {} accepted in {} (each with a reason and an "
              "expiry)".format(len(paths), sum(scanned.values()), len(found), len(accepted), IGNORE_FILE)]
    lines += ["- FAILED: " + problem for problem in problems]
    go_ci.summarise(summary, lines)
    return 1 if problems else 0


def self_test():
    tracked = ["requirements-dev.txt", "presentation/requirements-decryption.lock.txt", "go/go.mod",
               "go/vendor/golang.org/x/crypto/go.mod", "tools/ui-test-deps/package-lock.json", "README.md",
               "tools/golint/gosec/go.sum"]
    assert lockfiles(tracked) == ["go/go.mod", "presentation/requirements-decryption.lock.txt", "requirements-dev.txt",
                                  "tools/ui-test-deps/package-lock.json"], lockfiles(tracked)
    assert lockfile_arg("requirements-dev.txt") == "requirements.txt:requirements-dev.txt"
    assert lockfile_arg("a/requirements.txt") == "a/requirements.txt"
    assert lockfile_arg("go/go.mod") == "go/go.mod"
    assert scan_command("osv", "c.toml", ["go/go.mod"]) == ["osv", "scan", "source", "--config", "c.toml", "--format",
                                                            "json", "-L", "go/go.mod"]
    today = datetime.date(2026, 11, 22)
    good = {"id": "GO-1", "lockfile": "t/go.mod", "package": "x", "expires": "2026-12-22",
            "reason": "CI tool only; govulncheck finds no call to the vulnerable symbol in the built binary."}
    assert entry_problems([good], today) == []
    assert entry_problems([dict(good, expires="2026-11-22")], today)[0].endswith("review the risk again")
    assert "more than 90 days" in entry_problems([dict(good, expires="2027-06-01")], today)[0]
    assert "at least" in entry_problems([dict(good, reason="accepted")], today)[0]
    assert "exactly the keys" in entry_problems([dict(good, scope="all")], today)[0]
    assert "duplicate" in entry_problems([good, good], today)[0]
    assert "YYYY-MM-DD" in entry_problems([dict(good, expires="soon")], today)[0]
    report = {"results": [{"source": {"path": "/r/t/go.mod"}, "packages": [
        {"package": {"name": "x", "version": "1.0"}, "groups": [{"ids": ["GO-1"], "aliases": ["CVE-9", "GO-1"]}]}]}]}
    found = findings(report, "/r")
    assert found == [("t/go.mod", "x", "1.0", {"GO-1", "CVE-9"})], found
    scanned = {"t/go.mod": 3}
    assert decide(found, [good], scanned, ["t/go.mod"]) == ([], [("t/go.mod", "x", "1.0", "CVE-9")])
    by_alias = dict(good, id="CVE-9")
    assert decide(found, [by_alias], scanned, ["t/go.mod"])[0] == []
    # an entry names one lockfile and package: the same id elsewhere still fails
    elsewhere = [("go/go.mod", "x", "1.0", {"GO-1"})]
    problems = decide(elsewhere, [good], {"go/go.mod": 1}, ["go/go.mod"])[0]
    assert len(problems) == 2 and "not in" in problems[0] and "matches no finding" in problems[1], problems
    assert "did not read" in decide([], [], {}, ["go/go.mod"])[0][0]
    assert decide([], [good], scanned, ["t/go.mod"])[0][0].endswith("remove it")
    print("osv_scan self-test: ok (lockfile discovery, scan command, ignore entries, expiry, matching, stale entries)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--bin", help="directory holding the osv-scanner binary")
    parser.add_argument("--summary")
    parser.add_argument("--today", help="the date entries expire against (default: today, UTC)")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.bin:
        parser.error("--bin is required")
    today = datetime.date.fromisoformat(args.today) if args.today else datetime.datetime.now(datetime.timezone.utc).date()
    return run(args.bin, args.summary, today)


if __name__ == "__main__":
    sys.exit(main())
