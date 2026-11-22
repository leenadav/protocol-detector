"""Keep SSDLC.md's required-checks tables equal to the ci and codeql jobs that exist.

Branch protection matches status checks by job name (the `name:` of each job). SSDLC.md lists those names in
two tables ("Recommended required checks" and the jobs the ci gate covers), and a job that is added or renamed
without its row leaves the documented contract wrong: PR #30's `go-vendor` job was missing for a while.
This check fails when a ci.yml or codeql.yml job name (each matrix value expanded) has no row in a
`| ci |` or `| codeql |` table line, or when such a line names a job that no longer exists.

    check_required_checks.py [--self-test]
Standard library only; Python 3.9 syntax.
"""
import re
import sys
from pathlib import Path

WORKFLOWS = {"ci": Path(".github/workflows/ci.yml"), "codeql": Path(".github/workflows/codeql.yml")}
DOC = Path("SSDLC.md")
JOB = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
NAME = re.compile(r"^    name:\s*(.+?)\s*$")
MATRIX = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_]+)\s*\}\}")
MATRIX_VALUES = re.compile(r"^\s{8}([A-Za-z0-9_]+):\s*\[(.*)\]\s*$")
ROW = re.compile(r"^\| (ci|codeql) \| (.+?) \|")


def job_names(text):
    """Every job's `name:` in a workflow, with `${{ matrix.KEY }}` expanded over that job's matrix list."""
    names, block, inside = [], [], False
    for line in (text or "").splitlines() + ["  end-of-jobs:"]:
        if line.startswith("jobs:"):
            inside = True
            continue
        if not inside:
            continue
        if JOB.match(line):
            names += expand(block)
            block = []
        block.append(line)
    return names


def expand(block):
    name = next((match.group(1).strip("\"'") for match in map(NAME.match, block) if match), None)
    if name is None:
        return []
    key = MATRIX.search(name)
    if key is None:
        return [name]
    values = next((match.group(2) for match in map(MATRIX_VALUES.match, block) if match and match.group(1) == key.group(1)), "")
    return [MATRIX.sub(value.strip().strip("\"'"), name) for value in values.split(",") if value.strip()]


def documented(text):
    """{(workflow, job name)} from SSDLC.md's `| ci |` and `| codeql |` table lines (backticked names)."""
    rows = set()
    for line in (text or "").splitlines():
        match = ROW.match(line)
        if match:
            rows |= {(match.group(1), name) for name in re.findall(r"`([^`]+)`", match.group(2))}
    return rows


def problems(workflow_texts, doc_text):
    jobs = {(workflow, name) for workflow, text in workflow_texts.items() for name in job_names(text)}
    rows = documented(doc_text)
    return (["{}: job `{}` has no row in {}'s required-checks tables".format(w, n, DOC) for w, n in sorted(jobs - rows)]
            + ["{}: {} lists `{}`, which is no {} job".format(DOC, w, n, w) for w, n in sorted(rows - jobs)])


def self_test():
    ci = ("name: ci\non:\n  push:\njobs:\n  verify:\n    name: tests (python ${{ matrix.python }})\n    strategy:\n"
          "      matrix:\n        python: [\"3.9\", \"3.13\"]\n    steps:\n      - name: not a job name\n"
          "  gate:\n    name: ci gate (all jobs)\n")
    assert job_names(ci) == ["tests (python 3.9)", "tests (python 3.13)", "ci gate (all jobs)"], job_names(ci)
    doc = "| ci | `ci gate (all jobs)` | x |\n| ci | `tests (python 3.9)`, `tests (python 3.13)` | y |\n"
    assert problems({"ci": ci}, doc) == []
    missing = problems({"ci": ci}, doc.replace("`tests (python 3.13)`", "")).pop()
    assert "job `tests (python 3.13)` has no row" in missing, missing
    stale = problems({"ci": ci}, doc + "| ci | `retired job` | z |\n")
    assert stale == ["SSDLC.md: ci lists `retired job`, which is no ci job"], stale
    assert problems({"codeql": "jobs:\n  a:\n    name: CodeQL (x)\n"}, "") == [
        "codeql: job `CodeQL (x)` has no row in SSDLC.md's required-checks tables"]
    print("check_required_checks self-test: ok (matrix expansion, step names ignored, missing row, stale row)")
    return 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
    found = problems({w: p.read_text(encoding="utf-8") for w, p in WORKFLOWS.items()}, DOC.read_text(encoding="utf-8"))
    for problem in found:
        print("required checks:", problem)
    print("required checks: {}".format("ok" if not found else "{} problem(s)".format(len(found))))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
