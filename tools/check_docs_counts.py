"""Fail when the headline numbers in the documentation drift from the code.

README.md and REVIEW-SCOPE.md state how many protocol families, automatic
families, catalog applications and tests the project has, and which version
the review scope describes. Each milestone updates them by hand, so this gate
recomputes every number from the engine, the test suite and pyproject.toml and
reports each line that disagrees. Run from the repository root.
"""
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from protocol_engine import supported_protocols  # noqa: E402
from protocol_engine.applications import APPLICATIONS  # noqa: E402


def actual():
    rows = list(supported_protocols())
    suite = unittest.defaultTestLoader.discover(ROOT, pattern="test*.py")
    with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as handle:
        version = re.search(r'^version = "([^"]+)"', handle.read(), re.M).group(1)
    return {"families": len(rows), "automatic": sum(1 for row in rows if not row.requires_hint),
            "applications": len(APPLICATIONS), "tests": suite.countTestCases(), "version": version}


def expectations(readme, scope):
    """(label, documented value, actual key) triples read from the two documents."""
    found = []
    match = re.search(r"\| Protocol profiles \| (\d+) families \((\d+) automatic", readme)
    if match:
        found += [("README families", int(match.group(1)), "families"), ("README automatic families", int(match.group(2)), "automatic")]
    match = re.search(r"(\d+) catalog applications with category", readme)
    if match:
        found.append(("README catalog applications", int(match.group(1)), "applications"))
    match = re.search(r"budgets everywhere, (\d+) tests,", readme)
    if match:
        found.append(("README test count", int(match.group(1)), "tests"))
    match = re.search(r"^# Review scope: protocol detector v(\S+)", scope, re.M)
    if match:
        found.append(("REVIEW-SCOPE version", match.group(1), "version"))
    match = re.search(r"classification: (\d+) families, (\d+) automatic", scope)
    if match:
        found += [("REVIEW-SCOPE families", int(match.group(1)), "families"), ("REVIEW-SCOPE automatic families", int(match.group(2)), "automatic")]
    match = re.search(r"(\d+) tests pass", scope)
    if match:
        found.append(("REVIEW-SCOPE test count (new focus)", int(match.group(1)), "tests"))
    return found


def main():
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as handle:
        readme = handle.read()
    with open(os.path.join(ROOT, "REVIEW-SCOPE.md"), encoding="utf-8") as handle:
        scope = handle.read()
    numbers = actual()
    rows = expectations(readme, scope)
    if len(rows) < 8:
        print("docs counts: could not locate every documented number ({} of 8 found)".format(len(rows)))
        return 1
    failures = 0
    for label, documented, key in rows:
        if key == "version":
            # REVIEW-SCOPE names the milestone (0.53); pyproject carries the full version (0.53.0).
            if documented == numbers[key] or numbers[key].startswith(documented + "."):
                continue
        if documented != numbers[key]:
            failures += 1
            print("{}: documented {} but the tree has {}".format(label, documented, numbers[key]))
    summary = ", ".join("{} {}".format(key, value) for key, value in numbers.items())
    print("docs counts:", ("ok" if not failures else "{} stale".format(failures)) + " (" + summary + ")")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
