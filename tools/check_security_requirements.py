"""Verify that every security requirement in SECURITY-REQUIREMENTS.md names a test.

Each requirement row has an identifier (SR-n) and a verification column that
must reference an existing test module and test function. The gate fails on a
requirement without an executable check or on a reference that no longer exists.
"""
import re
import sys
from pathlib import Path

ROW = re.compile(r"^\|\s*(SR-\d+)\s*\|(.*)\|\s*`([^`]+)`\s*\|\s*$")


def main():
    text = Path("SECURITY-REQUIREMENTS.md").read_text(encoding="utf-8")
    rows = [ROW.match(line) for line in text.splitlines()]
    rows = [match for match in rows if match]
    if not rows:
        print("no requirements found")
        return 1
    failures = 0
    for match in rows:
        identifier, _, reference = match.groups()
        for item in reference.split(","):
            module, _, function = item.strip().partition("::")
            path = Path(module + ".py")
            if not path.exists():
                failures += 1
                print("{}: missing test module {}".format(identifier, module))
                continue
            if function and not re.search(r"def {}\b".format(re.escape(function)), path.read_text(encoding="utf-8")):
                failures += 1
                print("{}: missing test {} in {}".format(identifier, function, module))
    print("security requirements: {} rows, {} failures".format(len(rows), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
