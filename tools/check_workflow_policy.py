"""Workflow policy gate: structural rules the workflows must keep as they change.

1. Aggregate gate (`ci.yml`): the `gate` job must list every other ci job in its `needs`
   and no job that does not exist. `toJSON(needs)` only sees direct dependencies, so a
   job missing from the list could fail while `ci gate (all jobs)` still succeeds.
2. Drift coverage (`supply-chain-drift.yml`): its push and pull_request path filters must
   match every workflow file that `tools/check_pin_drift.py .github/workflows` scans, plus
   the checker and requirements-dev.txt, so a pull request that edits any pinned action
   runs the live tag-to-SHA verification before merge, not only on the weekly schedule.
3. Release serialization (`release.yml`): the concurrency group that governs the `publish`
   job (its own, else the workflow's) must resolve to the same group for two different
   `v*` tags and must not cancel in progress, so releases of different tags never publish
   at the same time; the workflow-level group must stay per ref for branch dry runs.

Standard library only; the parser understands the block layout these workflows use
(two-space indentation, `needs:` as a flow list or a block list, `paths:` as a block list,
`concurrency:` as a mapping; keys plain or quoted) and fails closed on anything it cannot
read: every entry of the `jobs:` mapping must be a block-style job key, so a job spelled
another way (inline flow mapping, alias, explicit `?` key, merge key, tab indentation)
fails the check instead of being left out of the gate comparison, and so does a
concurrency expression other than a plain `github.*` context reference. Usage:
  check_workflow_policy.py [--root DIR] [--self-test]
"""
import contextlib
import fnmatch
import io
import re
import sys
import tempfile
from pathlib import Path

KEY = re.compile(r"""^( *)("[^"]*"|'[^']*'|[A-Za-z0-9_-]+):(?:\s+(.*?))?\s*(#.*)?$""")
ITEM = re.compile(r"^(\s*)-\s*(.+?)\s*(#.*)?$")
DRIFT_INPUTS = ["tools/check_pin_drift.py", "requirements-dev.txt"]


def strip_quotes(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def key_of(line, indent=None):
    """(indent, unquoted key, value) of a `key: value` line, or None."""
    match = KEY.match(line)
    if not match or (indent is not None and len(match.group(1)) != indent):
        return None
    return len(match.group(1)), strip_quotes(match.group(2)), match.group(3) or ""


def jobs_block(lines):
    """Lines of the top-level `jobs:` mapping, or raise if absent."""
    for index, line in enumerate(lines):
        if re.match(r"^jobs:\s*(#.*)?$", line):
            end = next((j for j in range(index + 1, len(lines)) if re.match(r"^\S", lines[j])), len(lines))
            return lines[index + 1:end]
    raise ValueError("no top-level jobs: mapping")


def job_starts(block):
    """[(line index, job id)] of the `jobs:` mapping; any entry that is not a block-style
    job key raises, so no job can hide from the gate comparison by its spelling."""
    starts = []
    for index, line in enumerate(block):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if line.startswith("\t") or line[:len(line) - len(line.lstrip(" \t"))].count("\t"):
            raise ValueError("jobs: tab indentation is not supported: {!r}".format(line))
        indent = len(line) - len(line.lstrip(" "))
        if indent >= 4:
            if not starts:
                raise ValueError("jobs: content before the first job key: {!r}".format(line))
            continue
        key = key_of(line, indent=2)
        if key is None or key[2]:
            raise ValueError("jobs: cannot read job entry {!r}; only block-style `  <id>:` job keys are supported".format(line))
        starts.append((index, key[1]))
    return starts


def job_ids_and_needs(text):
    """({job id, ...}, {job id: [needs ids]})."""
    lines = text.splitlines()
    block = jobs_block(lines)
    starts = dict(job_starts(block))
    ids, needs, current = [], {}, None
    index = 0
    while index < len(block):
        line = block[index]
        if index in starts:
            current = starts[index]
            ids.append(current)
            needs[current] = []
        elif current is not None:
            key = key_of(line, indent=4)
            if key and key[1] == "needs":
                value = key[2]
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
        key = key_of(line, indent=2)
        if key and key[1] == event:
            stop = next((j for j in range(index + 1, len(block)) if key_of(block[j]) and key_of(block[j])[0] <= 2), len(block))
            for inner in range(index + 1, stop):
                sub = key_of(block[inner], indent=4)
                if sub and sub[1] == "paths":
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


EXPRESSION = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
TAG_RUNS = [
    {"github.ref": "refs/tags/v0.57.0", "github.ref_name": "v0.57.0", "github.ref_type": "tag",
     "github.event_name": "push", "github.sha": "a" * 40, "github.run_id": "1", "github.workflow": "release"},
    {"github.ref": "refs/tags/v0.57.1", "github.ref_name": "v0.57.1", "github.ref_type": "tag",
     "github.event_name": "push", "github.sha": "b" * 40, "github.run_id": "2", "github.workflow": "release"},
]
BRANCH_RUNS = [
    {"github.ref": "refs/heads/claude/cicd", "github.ref_name": "claude/cicd", "github.ref_type": "branch",
     "github.event_name": "push", "github.sha": "c" * 40, "github.run_id": "3", "github.workflow": "release"},
    {"github.ref": "refs/heads/main", "github.ref_name": "main", "github.ref_type": "branch",
     "github.event_name": "push", "github.sha": "d" * 40, "github.run_id": "4", "github.workflow": "release"},
]


def concurrency_in(lines, indent):
    """{'group': ..., 'cancel-in-progress': ...} of the `concurrency:` key at `indent`, or None."""
    for index, line in enumerate(lines):
        key = key_of(line, indent=indent)
        if not key or key[1] != "concurrency":
            continue
        if key[2]:
            return {"group": strip_quotes(key[2])}
        found = {}
        for inner in lines[index + 1:]:
            sub = key_of(inner)
            if not inner.strip() or inner.strip().startswith("#"):
                continue
            if not sub or sub[0] <= indent:
                break
            if sub[0] == indent + 2:
                found[sub[1]] = strip_quotes(sub[2])
        if "group" not in found:
            raise ValueError("concurrency at indent {} has no group".format(indent))
        return found
    return None


def job_lines(text, job):
    block = jobs_block(text.splitlines())
    starts = job_starts(block)
    position = next((n for n, (_, name) in enumerate(starts) if name == job), None)
    if position is None:
        raise ValueError("no `{}` job".format(job))
    start = starts[position][0]
    end = starts[position + 1][0] if position + 1 < len(starts) else len(block)
    return block[start + 1:end]


def resolve(value, context):
    """Substitute plain `${{ github.* }}` references; anything else fails closed."""
    def substitute(match):
        name = match.group(1)
        if name not in context:
            raise ValueError("cannot resolve concurrency expression `${{{{ {} }}}}`".format(name))
        return context[name]
    return EXPRESSION.sub(substitute, value)


def check_release_concurrency(text, publish="publish"):
    problems = []
    workflow = concurrency_in(text.splitlines(), 0)
    job = concurrency_in(job_lines(text, publish), 4)
    governing = job or workflow
    if governing is None:
        return ["release.yml: the {} job has no concurrency group".format(publish)]
    groups = [resolve(governing["group"], run) for run in TAG_RUNS]
    if groups[0] != groups[1]:
        problems.append("release.yml: publishes of {} and {} resolve to different concurrency groups ({} / {})".format(
            TAG_RUNS[0]["github.ref"], TAG_RUNS[1]["github.ref"], groups[0], groups[1]))
    for scope, found in (("workflow", workflow), ("{} job".format(publish), job)):
        if found is not None and found.get("cancel-in-progress", "false") != "false":
            problems.append("release.yml: {} concurrency must not cancel a release in progress".format(scope))
    if workflow is None:
        problems.append("release.yml: no workflow-level concurrency group for dry runs")
    elif len({resolve(workflow["group"], run) for run in BRANCH_RUNS}) != len(BRANCH_RUNS):
        problems.append("release.yml: the workflow-level group is not per ref, so dry runs of different branches block each other")
    return problems


def main(root):
    root = Path(root)
    workflows = root / ".github" / "workflows"
    files = sorted(p.relative_to(root).as_posix() for p in list(workflows.glob("*.yml")) + list(workflows.glob("*.yaml")))
    problems = []
    try:
        problems += check_gate((workflows / "ci.yml").read_text(encoding="utf-8"))
        problems += check_drift_paths((workflows / "supply-chain-drift.yml").read_text(encoding="utf-8"), files)
        problems += check_release_concurrency((workflows / "release.yml").read_text(encoding="utf-8"))
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

SELF_TEST_RELEASE = """name: release
on:
  push:
    tags: ["v*"]
concurrency:
  group: {workflow_group}
  cancel-in-progress: false   # comment
jobs:
  build:
    runs-on: x
  publish:
    needs: build
{publish_concurrency}    runs-on: x
"""
PUBLISH_CONCURRENCY = """    concurrency:
      group: {group}
      cancel-in-progress: {cancel}
"""


def release(workflow_group="release-${{ github.ref }}", group=None, cancel="false"):
    job = PUBLISH_CONCURRENCY.format(group=group, cancel=cancel) if group else ""
    return SELF_TEST_RELEASE.format(workflow_group=workflow_group, publish_concurrency=job)


def self_test():
    assert check_gate(SELF_TEST_CI.replace("{extra}", ", extra")) == []
    problems = check_gate(SELF_TEST_CI.replace("{extra}", ""))
    assert problems == ["gate.needs is missing job(s): extra"], problems
    problems = check_gate(SELF_TEST_CI.replace("{extra}", ", extra, gone"))
    assert problems == ["gate.needs names job(s) that do not exist: gone"], problems
    assert job_ids_and_needs(SELF_TEST_CI.replace("{extra}", ""))[1]["extra"] == ["verify", "lint"]
    assert check_gate("jobs:\n  a:\n    x: 1\n") == ["ci.yml has no `gate` job"]
    # PR #6 round 2: a job key spelled other than `  plain-id:` must not drop out of the comparison.
    gate_tail = "  gate:\n    if: always()\n    needs: [verify]\n"
    for spelling in ('"new-check"', "'new-check'"):
        quoted = "jobs:\n  verify:\n    runs-on: x\n  {}:  # added later\n    runs-on: x\n".format(spelling) + gate_tail
        assert check_gate(quoted) == ["gate.needs is missing job(s): new-check"], check_gate(quoted)
        assert check_gate(quoted.replace("needs: [verify]", "needs: [verify, {}]".format(spelling))) == []
    assert job_ids_and_needs('jobs:\n  a:\n    "needs": [b]\n  b:\n    x: 1\n')[1]["a"] == ["b"]
    for unreadable in ("  new-check: {runs-on: x}\n",          # inline flow mapping
                       "  new-check: *template\n",              # alias
                       "  ? new-check\n  : runs-on: x\n",       # explicit key
                       "  <<: *defaults\n",                     # merge key
                       "  new.check:\n    runs-on: x\n",      # outside the job-id alphabet
                       "\tnew-check:\n    runs-on: x\n",      # tab indentation
                       " new-check:\n    runs-on: x\n"):       # off-grid indentation
        text = "jobs:\n  verify:\n    runs-on: x\n" + unreadable + gate_tail
        try:
            check_gate(text)
            raise AssertionError("must fail closed: {!r}".format(unreadable))
        except ValueError:
            pass
    files = [".github/workflows/ci.yml", ".github/workflows/release.yml"]
    assert check_drift_paths(SELF_TEST_DRIFT.replace("{push}", ".github/workflows/**"), files) == []
    problems = check_drift_paths(SELF_TEST_DRIFT.replace("{push}", ".github/workflows/ci.yml"), files)
    assert problems == ["supply-chain-drift push paths do not cover .github/workflows/release.yml"], problems
    try:
        trigger_paths("name: x\n", "push")
        raise AssertionError("missing on: must fail closed")
    except ValueError:
        pass
    assert check_release_concurrency(release(group="release-publish")) == []
    assert check_release_concurrency(release(group="'release-publish'")) == []
    problems = check_release_concurrency(release())   # the PR #9 layout: one group per tag
    assert problems == ["release.yml: publishes of refs/tags/v0.57.0 and refs/tags/v0.57.1 resolve to different "
                        "concurrency groups (release-refs/tags/v0.57.0 / release-refs/tags/v0.57.1)"], problems
    problems = check_release_concurrency(release(group="publish-${{ github.ref_name }}"))
    assert len(problems) == 1 and "different concurrency groups" in problems[0], problems
    problems = check_release_concurrency(release(group="release-publish", cancel="true"))
    assert problems == ["release.yml: publish job concurrency must not cancel a release in progress"], problems
    problems = check_release_concurrency(release(workflow_group="release"))
    assert problems == ["release.yml: the workflow-level group is not per ref, so dry runs of different branches block each other"], problems
    assert check_release_concurrency(release(workflow_group="release-${{ github.ref }}-${{ github.run_id }}", group="release-publish")) == []
    for unreadable in ("${{ github.ref_type == 'tag' && 'tags' || github.ref }}", "${{ inputs.x }}"):
        try:
            check_release_concurrency(release(group=unreadable))
            raise AssertionError("an expression outside plain github.* references must fail closed")
        except ValueError:
            pass
    with tempfile.TemporaryDirectory() as directory:
        workflows = Path(directory) / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(SELF_TEST_CI.replace("{extra}", ""), encoding="utf-8")
        (workflows / "supply-chain-drift.yml").write_text(SELF_TEST_DRIFT.replace("{push}", ".github/workflows/ci.yml"), encoding="utf-8")
        (workflows / "release.yml").write_text(release(), encoding="utf-8")
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
