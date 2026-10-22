"""Workflow policy gate: structural rules the workflows must keep as they change.

1. Aggregate gate (`ci.yml`): the `gate` job must list every other ci job in its `needs`
   and no job that does not exist. `toJSON(needs)` only sees direct dependencies, so a
   job missing from the list could fail while `ci gate (all jobs)` still succeeds.
2. Drift coverage (`supply-chain-drift.yml`): its push and pull_request path filters must
   match every workflow file that `tools/check_pin_drift.py .github/workflows` scans, plus
   the checker and requirements-dev.txt, so a pull request that edits any pinned action
   runs the live tag-to-SHA verification before merge, not only on the weekly schedule.

Standard library only; the parser understands the block layout these workflows use
(two-space indentation, `needs:` as a flow list or a block list, `paths:` as a block list)
and fails closed on anything it cannot read. Usage:
  check_workflow_policy.py [--root DIR] [--self-test]
"""
import contextlib
import fnmatch
import io
import re
import sys
import tempfile
from pathlib import Path

JOB = re.compile(r"^  ([A-Za-z0-9_-]+):\s*(#.*)?$")
KEY = re.compile(r"^(\s*)([A-Za-z0-9_-]+):\s*(.*?)\s*(#.*)?$")
ITEM = re.compile(r"^(\s*)-\s*(.+?)\s*(#.*)?$")
DRIFT_INPUTS = ["tools/check_pin_drift.py", "requirements-dev.txt"]


def strip_quotes(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def jobs_block(lines):
    """Lines of the top-level `jobs:` mapping, or raise if absent."""
    for index, line in enumerate(lines):
        if re.match(r"^jobs:\s*(#.*)?$", line):
            end = next((j for j in range(index + 1, len(lines)) if re.match(r"^\S", lines[j])), len(lines))
            return lines[index + 1:end]
    raise ValueError("no top-level jobs: mapping")


def job_ids_and_needs(text):
    """({job id, ...}, {job id: [needs ids]})."""
    lines = text.splitlines()
    block = jobs_block(lines)
    ids, needs, current = [], {}, None
    index = 0
    while index < len(block):
        line = block[index]
        match = JOB.match(line)
        if match:
            current = match.group(1)
            ids.append(current)
            needs[current] = []
        elif current is not None:
            key = KEY.match(line)
            if key and len(key.group(1)) == 4 and key.group(2) == "needs":
                value = key.group(3)
                if value.startswith("["):
                    if not value.endswith("]"):
                        raise ValueError("job {}: multi-line flow list in needs is not supported".format(current))
                    needs[current] = [strip_quotes(item) for item in value[1:-1].split(",") if item.strip()]
                elif value:
                    needs[current] = [strip_quotes(value)]
                else:
                    while index + 1 < len(block) and ITEM.match(block[index + 1]) and len(ITEM.match(block[index + 1]).group(1)) > 4:
                        index += 1
                        needs[current].append(strip_quotes(ITEM.match(block[index]).group(2)))
        index += 1
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate job ids")
    return ids, needs


def check_gate(text, gate="gate"):
    ids, needs = job_ids_and_needs(text)
    if gate not in ids:
        return ["ci.yml has no `{}` job".format(gate)]
    expected = set(ids) - {gate}
    listed = needs[gate]
    problems = []
    missing = sorted(expected - set(listed))
    stale = sorted(set(listed) - set(ids))
    if missing:
        problems.append("gate.needs is missing job(s): {}".format(", ".join(missing)))
    if stale:
        problems.append("gate.needs names job(s) that do not exist: {}".format(", ".join(stale)))
    if len(listed) != len(set(listed)):
        problems.append("gate.needs lists a job twice")
    return problems


def trigger_paths(text, event):
    """Block-list `paths:` under `on: <event>:`; None when the event has no path filter."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if re.match(r"^on:\s*(#.*)?$", line)), None)
    if start is None:
        raise ValueError("no top-level on: mapping")
    end = next((j for j in range(start + 1, len(lines)) if re.match(r"^\S", lines[j])), len(lines))
    block = lines[start + 1:end]
    for index, line in enumerate(block):
        key = KEY.match(line)
        if key and len(key.group(1)) == 2 and key.group(2) == event:
            stop = next((j for j in range(index + 1, len(block)) if KEY.match(block[j]) and len(KEY.match(block[j]).group(1)) <= 2), len(block))
            for inner in range(index + 1, stop):
                sub = KEY.match(block[inner])
                if sub and len(sub.group(1)) == 4 and sub.group(2) == "paths":
                    paths = []
                    for item in block[inner + 1:stop]:
                        found = ITEM.match(item)
                        if not found or len(found.group(1)) <= 4:
                            break
                        paths.append(strip_quotes(found.group(2)))
                    return paths
            return None
    raise ValueError("on: has no `{}` trigger".format(event))


def check_drift_paths(drift_text, workflow_files):
    problems = []
    targets = ["{}".format(name) for name in workflow_files] + DRIFT_INPUTS
    for event in ("push", "pull_request"):
        patterns = trigger_paths(drift_text, event)
        if patterns is None:
            continue   # no path filter: every change runs the drift gate
        for target in targets:
            if not any(fnmatch.fnmatchcase(target, pattern) for pattern in patterns):
                problems.append("supply-chain-drift {} paths do not cover {}".format(event, target))
    return problems


def main(root):
    root = Path(root)
    workflows = root / ".github" / "workflows"
    files = sorted(p.relative_to(root).as_posix() for p in list(workflows.glob("*.yml")) + list(workflows.glob("*.yaml")))
    problems = []
    try:
        problems += check_gate((workflows / "ci.yml").read_text(encoding="utf-8"))
        problems += check_drift_paths((workflows / "supply-chain-drift.yml").read_text(encoding="utf-8"), files)
    except (OSError, ValueError) as error:
        problems.append("cannot read the workflows: {}".format(error))
    for problem in problems:
        print("workflow policy:", problem)
    print("workflow policy: {} ({} workflow files)".format("ok" if not problems else "{} problem(s)".format(len(problems)), len(files)))
    return 1 if problems else 0


SELF_TEST_CI = """name: ci
on:
  push:
jobs:
  verify:
    runs-on: x
  lint:
    name: lint
    needs: verify
  extra:
    needs:
      - verify
      - lint
  gate:
    if: always()
    needs: [verify, lint{extra}]
"""

SELF_TEST_DRIFT = """name: drift
on:
  schedule:
    - cron: "1 1 * * 1"
  push:
    paths:
      - "{push}"
      - "tools/check_pin_drift.py"
      - "requirements-dev.txt"
  pull_request:
    paths:
      - ".github/workflows/**"
      - "tools/check_pin_drift.py"
      - "requirements-dev.txt"
jobs:
  a:
    runs-on: x
"""


def self_test():
    assert check_gate(SELF_TEST_CI.replace("{extra}", ", extra")) == []
    problems = check_gate(SELF_TEST_CI.replace("{extra}", ""))
    assert problems == ["gate.needs is missing job(s): extra"], problems
    problems = check_gate(SELF_TEST_CI.replace("{extra}", ", extra, gone"))
    assert problems == ["gate.needs names job(s) that do not exist: gone"], problems
    assert job_ids_and_needs(SELF_TEST_CI.replace("{extra}", ""))[1]["extra"] == ["verify", "lint"]
    assert check_gate("jobs:\n  a:\n    x: 1\n") == ["ci.yml has no `gate` job"]
    files = [".github/workflows/ci.yml", ".github/workflows/release.yml"]
    assert check_drift_paths(SELF_TEST_DRIFT.replace("{push}", ".github/workflows/**"), files) == []
    problems = check_drift_paths(SELF_TEST_DRIFT.replace("{push}", ".github/workflows/ci.yml"), files)
    assert problems == ["supply-chain-drift push paths do not cover .github/workflows/release.yml"], problems
    try:
        trigger_paths("name: x\n", "push")
        raise AssertionError("missing on: must fail closed")
    except ValueError:
        pass
    with tempfile.TemporaryDirectory() as directory:
        workflows = Path(directory) / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(SELF_TEST_CI.replace("{extra}", ""), encoding="utf-8")
        (workflows / "supply-chain-drift.yml").write_text(SELF_TEST_DRIFT.replace("{push}", ".github/workflows/ci.yml"), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            assert main(directory) == 1   # the deliberately broken tree must fail
    print("check_workflow_policy self-test: ok")
    return 0


if __name__ == "__main__":
    arguments = sys.argv[1:]
    if "--self-test" in arguments:
        sys.exit(self_test())
    root = arguments[arguments.index("--root") + 1] if "--root" in arguments else "."
    sys.exit(main(root))
