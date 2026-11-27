"""Verify that every security requirement in SECURITY-REQUIREMENTS.md names a test, and that none disappears.

    check_security_requirements.py                         check the table against the lock (CI, make requirements)
    check_security_requirements.py --write-lock [--retire SR-n ...]
                                                           pin the table's id set in the lock
    check_security_requirements.py --self-test

Each requirement row has an identifier (SR-n) and a verification column that must reference an existing test
module and test function. The gate fails (SEC-PYRM-1) on:
- any line that starts a table row with `SR` but does not parse as `| SR-n | requirement | `refs` |` (free text,
  "manual review", prose after the closing backtick, a missing cell, `SR-07`): such a row used to be dropped
  silently, so its requirement lost its evidence while the gate stayed green;
- an empty reference item, a missing test module or a missing test function;
- a duplicate id (two rows claiming one requirement number);
- an id set that differs from tools/security_requirements.lock.json: a deleted row (an id in the lock that the
  table lacks), an unpinned new row (an id the lock lacks: run --write-lock and commit the lock with the row), or
  a retired id that is back in the table.

--write-lock pins the table's ids. It refuses to drop a pinned id unless that id is named with --retire, which
moves it to the lock's `retired` list for good, so removing a requirement is always a visible, reviewed change to
the lock and a retired number is never reused.
"""
import argparse
import contextlib
import io
import json
import re
import sys
import tempfile
from pathlib import Path

TABLE = "SECURITY-REQUIREMENTS.md"
LOCK = "tools/security_requirements.lock.json"

# Any table row whose first cell starts with SR (any case, any spacing) is a requirement row and must parse.
CANDIDATE = re.compile(r"^\s*\|\s*sr", re.IGNORECASE)
ROW = re.compile(r"^\|\s*(SR-[1-9]\d*)\s*\|(.*)\|\s*`([^`]+)`\s*\|\s*$")
ITEM = re.compile(r"^[A-Za-z0-9_./-]+(?:::[A-Za-z_]\w*)?$")


def id_key(identifier):
    return int(identifier.split("-", 1)[1])


def parse(text):
    """Return (rows, failures): rows are (line number, id, reference); failures are messages."""
    rows, failures = [], []
    for number, line in enumerate(text.splitlines(), 1):
        if not CANDIDATE.match(line):
            continue
        match = ROW.match(line)
        if not match:
            failures.append("line {}: unparsable requirement row (expected `| SR-n | requirement | `module::test[, "
                            "...]` |`): {}".format(number, line.strip()[:80]))
            continue
        identifier, _, reference = match.groups()
        rows.append((number, identifier, reference))
    return rows, failures


def check_references(root, rows):
    failures = []
    for _, identifier, reference in rows:
        for item in reference.split(","):
            item = item.strip()
            if not ITEM.match(item):
                failures.append("{}: malformed test reference {!r}".format(identifier, item))
                continue
            module, _, function = item.partition("::")
            path = root / (module + ".py")
            if not path.is_file():
                failures.append("{}: missing test module {}".format(identifier, module))
                continue
            if function and not re.search(r"def {}\b".format(re.escape(function)), path.read_text(encoding="utf-8")):
                failures.append("{}: missing test {} in {}".format(identifier, function, module))
    return failures


def check_duplicates(rows):
    seen, failures = {}, []
    for number, identifier, _ in rows:
        if identifier in seen:
            failures.append("{}: duplicate id on lines {} and {}".format(identifier, seen[identifier], number))
        else:
            seen[identifier] = number
    return failures


def read_lock(root):
    path = root / LOCK
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        return None, ["{}: unreadable lock ({}); run --write-lock".format(LOCK, error)]
    ids, retired = data.get("ids"), data.get("retired", [])
    if not isinstance(ids, list) or not isinstance(retired, list):
        return None, ["{}: `ids` and `retired` must be lists".format(LOCK)]
    return (set(ids), set(retired)), []


def check_lock(root, rows):
    lock, failures = read_lock(root)
    if lock is None:
        return failures
    pinned, retired = lock
    present = {identifier for _, identifier, _ in rows}
    for identifier in sorted(pinned - present, key=id_key):
        failures.append("{}: pinned in {} but missing from {} (deleted or renumbered row; retire it with "
                        "--write-lock --retire {})".format(identifier, LOCK, TABLE, identifier))
    for identifier in sorted(present - pinned - retired, key=id_key):
        failures.append("{}: not pinned in {}; run --write-lock and commit the lock with the row".format(
            identifier, LOCK))
    for identifier in sorted(present & retired, key=id_key):
        failures.append("{}: retired in {}; a retired id is never reused".format(identifier, LOCK))
    return failures


def check(root):
    path = root / TABLE
    rows, failures = parse(path.read_text(encoding="utf-8"))
    if not rows and not failures:
        print("no requirements found")
        return 1
    failures += check_duplicates(rows)
    failures += check_references(root, rows)
    failures += check_lock(root, rows)
    for failure in failures:
        print(failure)
    print("security requirements: {} rows, {} failures".format(len(rows), len(failures)))
    return 1 if failures else 0


def write_lock(root, retire):
    rows, failures = parse((root / TABLE).read_text(encoding="utf-8"))
    failures += check_duplicates(rows)
    if failures:
        for failure in failures:
            print(failure)
        print("lock not written: fix the table first")
        return 1
    present = {identifier for _, identifier, _ in rows}
    old_ids, old_retired = set(), set()
    if (root / LOCK).exists():
        lock, errors = read_lock(root)
        if lock is None:
            for error in errors:
                print(error)
            return 1
        old_ids, old_retired = lock
    retire = set(retire)
    problems = []
    for identifier in sorted(retire & present, key=id_key):
        problems.append("{}: still in {}; remove the row before retiring it".format(identifier, TABLE))
    for identifier in sorted(retire - old_ids, key=id_key):
        problems.append("{}: not pinned, nothing to retire".format(identifier))
    for identifier in sorted(old_ids - present - retire, key=id_key):
        problems.append("{}: pinned but missing from {}; restore the row or pass --retire {}".format(
            identifier, TABLE, identifier))
    for identifier in sorted(present & old_retired, key=id_key):
        problems.append("{}: retired; a retired id is never reused".format(identifier))
    if problems:
        for problem in problems:
            print(problem)
        print("lock not written")
        return 1
    data = {
        "comment": "Pinned SR ids of {}; written by tools/check_security_requirements.py --write-lock.".format(TABLE),
        "ids": sorted(present, key=id_key),
        "retired": sorted(old_retired | retire, key=id_key),
    }
    (root / LOCK).write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
    print("{}: {} ids pinned, {} retired".format(LOCK, len(data["ids"]), len(data["retired"])))
    return 0


def self_test():
    header = "| ID | Requirement | Verified by |\n|---|---|---|\n"
    good = "| SR-1 | A | `tests/test_a::test_one` |\n| SR-2 | B `x` | `tests/test_a::test_one, tests/test_a` |\n"
    cases = [
        # (name, table body, lock ids or None for "as written", lock retired, expected rc, expected substring)
        ("valid", good, None, [], 0, "2 rows, 0 failures"),
        ("free text", good + "| SR-3 | C | manual review |\n", None, [], 1, "line 5: unparsable"),
        ("prose after backtick", good + "| SR-3 | C | `tests/test_a::test_one` and more |\n", None, [], 1,
         "unparsable"),
        ("missing cell", good + "| SR-3 | `tests/test_a::test_one` |\n", None, [], 1, "unparsable"),
        ("leading zero", good + "| SR-03 | C | `tests/test_a::test_one` |\n", None, [], 1, "unparsable"),
        ("lowercase id", good + "| sr-3 | C | `tests/test_a::test_one` |\n", None, [], 1, "unparsable"),
        ("duplicate", good + "| SR-2 | C | `tests/test_a::test_one` |\n", None, [], 1, "SR-2: duplicate id"),
        ("deleted row", good, ["SR-1", "SR-2", "SR-3"], [], 1, "SR-3: pinned"),
        ("unpinned row", good, ["SR-1"], [], 1, "SR-2: not pinned"),
        ("retired reuse", good, ["SR-1"], ["SR-2"], 1, "SR-2: retired"),
        ("empty item", "| SR-1 | A | `tests/test_a::test_one, ` |\n", None, [], 1, "malformed test reference"),
        ("missing test", "| SR-1 | A | `tests/test_a::test_two` |\n", None, [], 1, "missing test test_two"),
        ("missing module", "| SR-1 | A | `tests/test_b::test_one` |\n", None, [], 1, "missing test module"),
    ]
    failed = 0
    for name, body, ids, retired, want_rc, want_text in cases:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tests").mkdir()
            (root / "tools").mkdir()
            (root / "tests" / "test_a.py").write_text("def test_one():\n    pass\n", encoding="utf-8")
            (root / TABLE).write_text(header + body, encoding="utf-8")
            if ids is None:
                ids = sorted({m.group(1) for m in map(ROW.match, body.splitlines()) if m}, key=id_key)
            (root / LOCK).write_text(json.dumps({"ids": ids, "retired": retired}), encoding="utf-8")
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                rc = check(root)
            text = buffer.getvalue()
            if rc != want_rc or want_text not in text:
                failed += 1
                print("FAIL {}: rc {} (want {}), output {!r}".format(name, rc, want_rc, text))
    failed += self_test_write_lock(header, good)
    print("security requirements self-test: {} cases, {} failed".format(len(cases) + 4, failed))
    return 1 if failed else 0


def self_test_write_lock(header, good):
    failed = 0
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "tools").mkdir()
        (root / TABLE).write_text(header + good, encoding="utf-8")
        quiet = []
        with contextlib.redirect_stdout(io.StringIO()):
            def table(body):
                (root / TABLE).write_text(header + body, encoding="utf-8")

            steps = [
                ("first write", lambda: write_lock(root, []), 0),
                ("drop without retire", lambda: (table(good.splitlines(True)[0]), write_lock(root, []))[1], 1),
                ("drop with retire", lambda: write_lock(root, ["SR-2"]), 0),
                ("reuse retired", lambda: (table(good), write_lock(root, []))[1], 1),
            ]
            for name, step, want in steps:
                rc = step()
                if rc != want:
                    failed += 1
                    quiet.append("FAIL write-lock {}: rc {} (want {})\n".format(name, rc, want))
        lock = json.loads((root / LOCK).read_text(encoding="utf-8"))
        if lock["ids"] != ["SR-1"] or lock["retired"] != ["SR-2"]:
            failed += 1
            quiet.append("FAIL write-lock final lock {!r}\n".format(lock))
    print("".join(quiet), end="")
    return failed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--write-lock", action="store_true")
    parser.add_argument("--retire", action="append", default=[], metavar="SR-n")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.retire and not args.write_lock:
        parser.error("--retire needs --write-lock")
    root = Path(".")
    if args.write_lock:
        return write_lock(root, args.retire)
    return check(root)


if __name__ == "__main__":
    sys.exit(main())
