"""Workflow policy gate: structural rules the workflows must keep as they change.

1. Aggregate gate (`ci.yml`): the `gate` job must list every other ci job in its `needs`
   and no job that does not exist. `toJSON(needs)` only sees direct dependencies, so a
   job missing from the list could fail while `ci gate (all jobs)` still succeeds.
2. Drift coverage (`supply-chain-drift.yml`): its push and pull_request path filters must
   match every workflow file that `tools/check_pin_drift.py .github/workflows` scans, plus
   the checker and requirements-dev.txt, so a pull request that edits any pinned action
   runs the live tag-to-SHA verification before merge, not only on the weekly schedule.
3. Release serialization (`publish-release.yml`): the concurrency group that governs the `publish`
   job (its own, else the workflow's) must resolve to the same group for two different
   `v*` tags and must not cancel in progress, so releases of different tags never publish
   at the same time; the workflow-level group must stay per ref for branch dry runs.
4. Release provenance (`publish-release.yml`): a job the `publish` job needs, with no job-level
   `if:` or `continue-on-error`, must contain the pinned provenance step: exactly the keys
   `name`, `env` and `run`, the env mapping in PROVENANCE_ENV and the run lines in
   PROVENANCE_RUN (self-test, compare status, the decision with REF_TYPE, SHA and STATUS),
   and likewise the pinned release-checks step (CHECKS_RUN: the tagged commit's workflow runs
   from the Actions API, the ci and codeql workflows, by path and push event, required by
   `tools/check_release_checks.py`).
   The publish job's `if:` must be exactly PUBLISH_CONDITION, so no status-check function
   (success(), always(), failure(), cancelled(), in any case or spacing) can let it run
   after the provenance job failed. So a tag on a commit that is not on main never reaches
   the publish job (tag protection is not enforceable on this plan), and a mention, a
   self-test alone, hard-coded inputs or a masked exit code cannot stand in for the check.
5. Tag triggers: only `publish-release.yml` may run on `push: tags`, and the legacy path
   `.github/workflows/release.yml` must not exist. A tag push runs the workflow file at the
   tagged commit, so every older commit's unguarded release.yml stays reachable until that
   path is disabled in the repository's Actions settings; keeping the path free means
   disabling it never disables the guarded controller. `tools/check_release_exposure.py`
   reports which workflows a tag on any given commit would run.
6. Shell: every workflow sets top-level `defaults: run: shell: bash`, and no job or step
   overrides the shell. The unspecified default is `bash -e {0}` without pipefail, so a
   failing check piped into `tee` (the job-summary idiom used throughout) would pass.
7. Action consistency: every action repository (`owner/repo`, sub-actions included) is pinned
   to one commit SHA and one `# vX.Y.Z` tag comment across all workflows, and
   `actions/upload-artifact` and `actions/download-artifact`, which hand the release files
   from the build job to the publish job, share a major version. A partial bump (one file,
   one job, or one half of the artifact pair; Dependabot PR #8 was computed before the
   release split and would have moved only the upload side to v7) fails here instead of
   surfacing as a broken release. `owner/repo` is compared case-insensitively, as GitHub
   resolves it. A remote `uses:` without a full SHA and a tag comment fails closed.

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
        return ["publish-release.yml: the {} job has no concurrency group".format(publish)]
    groups = [resolve(governing["group"], run) for run in TAG_RUNS]
    if groups[0] != groups[1]:
        problems.append("publish-release.yml: publishes of {} and {} resolve to different concurrency groups ({} / {})".format(
            TAG_RUNS[0]["github.ref"], TAG_RUNS[1]["github.ref"], groups[0], groups[1]))
    for scope, found in (("workflow", workflow), ("{} job".format(publish), job)):
        if found is not None and found.get("cancel-in-progress", "false") != "false":
            problems.append("publish-release.yml: {} concurrency must not cancel a release in progress".format(scope))
    if workflow is None:
        problems.append("publish-release.yml: no workflow-level concurrency group for dry runs")
    elif len({resolve(workflow["group"], run) for run in BRANCH_RUNS}) != len(BRANCH_RUNS):
        problems.append("publish-release.yml: the workflow-level group is not per ref, so dry runs of different branches block each other")
    return problems


PROVENANCE = "tools/check_release_ref.py"
# The provenance step is pinned: a mention, a self-test alone, a hard-coded ref type or SHA,
# a dropped status or an alternate command must not satisfy the rule (PR review of milestone 1).
PROVENANCE_ENV = {
    "GH_TOKEN": "${{ github.token }}",
    "GH_REPO": "${{ github.repository }}",
    "REF_TYPE": "${{ github.ref_type }}",
    "SHA": "${{ github.event.pull_request.head.sha || github.sha }}",
}
PROVENANCE_RUN = [
    'python -B tools/check_release_ref.py --self-test',
    'STATUS=$(gh api "repos/${GH_REPO}/compare/${SHA}...main" --jq .status) || STATUS="api-error"',
    'python -B tools/check_release_ref.py --ref-type "${REF_TYPE}" --sha "${SHA}" --status "${STATUS}"'
    ' --summary "${GITHUB_STEP_SUMMARY}"',
]
CHECKS = "tools/check_release_checks.py"
CHECKS_RUN = [
    'python -B tools/check_release_checks.py --self-test',
    'gh api --paginate "repos/${GH_REPO}/actions/runs?head_sha=${SHA}&per_page=100" --jq \'.workflow_runs[] | {path, name,'
    ' event, status, conclusion, head_sha, updated_at}\' > "${RUNNER_TEMP}/workflow-runs.jsonl"'
    ' || echo "api-error" > "${RUNNER_TEMP}/workflow-runs.jsonl"',
    'python -B tools/check_release_checks.py --ref-type "${REF_TYPE}" --sha "${SHA}" --runs "${RUNNER_TEMP}/workflow-runs.jsonl"'
    ' --summary "${GITHUB_STEP_SUMMARY}"',
]
# (label, helper, env, run lines): each must appear, exactly, in a job the publish job needs.
PINNED_STEPS = [
    ("provenance", PROVENANCE, PROVENANCE_ENV, PROVENANCE_RUN),
    ("release checks", CHECKS, PROVENANCE_ENV, CHECKS_RUN),
]
PUBLISH_CONDITION = "github.event_name == 'push' && github.ref_type == 'tag'"
RELEASE_WORKFLOW = ".github/workflows/publish-release.yml"
LEGACY_RELEASE = ".github/workflows/release.yml"


def steps_of(job_block):
    """[[lines of one step]] of a job's `steps:` list (items at indent 6)."""
    steps, current = [], None
    for line in job_block:
        item = ITEM.match(line)
        if item and len(item.group(1)) == 6:
            current = [line]
            steps.append(current)
        elif current is not None and (not line.strip() or len(line) - len(line.lstrip(" ")) > 6):
            current.append(line)
        else:
            current = None
    return steps


def step_fields(step):
    """{key: value} at the step's top level, plus `env` as a dict and `run` as its lines."""
    lines = [" " * 8 + step[0].split("-", 1)[1].lstrip()] + step[1:]
    fields, index = {}, 0
    while index < len(lines):
        line = lines[index]
        if not line.strip() or line.strip().startswith("#"):
            index += 1
            continue
        key = key_of(line, indent=8)
        if key is None:
            raise ValueError("publish-release.yml: cannot read step line {!r}".format(line))
        name, value = key[1], key[2]
        body = []
        while index + 1 < len(lines) and (not lines[index + 1].strip() or len(lines[index + 1]) - len(lines[index + 1].lstrip(" ")) > 8):
            index += 1
            body.append(lines[index])
        if name == "env" and not value:
            env = {}
            for entry in body:
                if not entry.strip() or entry.strip().startswith("#"):
                    continue
                pair = key_of(entry, indent=10)
                if pair is None:
                    raise ValueError("publish-release.yml: cannot read env line {!r}".format(entry))
                env[pair[1]] = strip_quotes(pair[2])
            fields[name] = env
        elif name == "run" and value in ("|", "|-"):
            fields[name] = [entry.strip() for entry in body if entry.strip() and not entry.strip().startswith("#")]
        else:
            fields[name] = value if not body else None
        index += 1
    return fields


def check_release_provenance(text, publish="publish"):
    ids, needs = job_ids_and_needs(text)
    if publish not in ids:
        return ["publish-release.yml has no `{}` job".format(publish)]
    problems = []
    condition = next((key_of(line, indent=4)[2] for line in job_lines(text, publish)
                      if key_of(line, indent=4) and key_of(line, indent=4)[1] == "if"), "")
    if " ".join(strip_quotes(condition).split()) != PUBLISH_CONDITION:
        problems.append("publish-release.yml: the {} job's if: must be exactly `{}` (no status-check function "
                        "may let it run after a needed job failed)".format(publish, PUBLISH_CONDITION))
    for label, helper, env, run in PINNED_STEPS:
        guarded = []
        for job in needs[publish]:
            block = job_lines(text, job)
            job_keys = {key_of(line, indent=4)[1] for line in block if key_of(line, indent=4)}
            if job_keys & {"if", "continue-on-error"}:
                continue
            for step in steps_of(block):
                if not any(helper in line for line in step):
                    continue
                fields = step_fields(step)
                if set(fields) == {"name", "env", "run"} and fields["env"] == env and fields["run"] == run:
                    guarded.append(job)
        if guarded:
            continue
        if label == "provenance":
            problems.append("publish-release.yml: no job the {} job needs runs the pinned provenance step ({} with the "
                            "compare status, REF_TYPE and SHA, unconditionally)".format(publish, PROVENANCE))
        else:
            problems.append("publish-release.yml: no job the {} job needs runs the pinned {} step ({}, "
                            "unconditionally)".format(publish, label, helper))
    return problems


def tag_trigger(text):
    """True when `on: push:` lists `tags` (a flow list, a block list or a scalar)."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if re.match(r"^on:\s*(#.*)?$", line)), None)
    if start is None:
        if re.search(r"^on:\s*\S", text, re.M):
            raise ValueError("on: in flow or scalar form is not supported")
        raise ValueError("no top-level on: mapping")
    end = next((j for j in range(start + 1, len(lines)) if re.match(r"^\S", lines[j])), len(lines))
    block = lines[start + 1:end]
    for index, line in enumerate(block):
        key = key_of(line, indent=2)
        if key and key[1] == "push":
            stop = next((j for j in range(index + 1, len(block)) if key_of(block[j]) and key_of(block[j])[0] <= 2), len(block))
            return any(key_of(inner, indent=4) and key_of(inner, indent=4)[1] in ("tags", "tags-ignore")
                       for inner in block[index + 1:stop])
    return False


def check_tag_triggers(workflows):
    """`workflows`: {repository path: text}."""
    problems = []
    if LEGACY_RELEASE in workflows:
        problems.append("{} must not exist: it is the legacy, unguarded release path to be disabled in the "
                        "Actions settings, and the guarded controller lives at {}".format(LEGACY_RELEASE, RELEASE_WORKFLOW))
    for path, text in sorted(workflows.items()):
        if path != RELEASE_WORKFLOW and tag_trigger(text):
            problems.append("{} runs on tag pushes; only {} may".format(path, RELEASE_WORKFLOW))
    if RELEASE_WORKFLOW not in workflows:
        problems.append("{} is missing".format(RELEASE_WORKFLOW))
    return problems


def check_shell(path, text):
    lines = text.splitlines()
    problems = []
    start = next((i for i, line in enumerate(lines) if re.match(r"^defaults:\s*(#.*)?$", line)), None)
    pinned = False
    if start is not None:
        end = next((j for j in range(start + 1, len(lines)) if re.match(r"^\S", lines[j])), len(lines))
        body = [line for line in lines[start + 1:end] if line.strip() and not line.strip().startswith("#")]
        pinned = (len(body) == 2 and key_of(body[0], indent=2) == (2, "run", "")
                  and key_of(body[1], indent=4) is not None and key_of(body[1], indent=4)[1:] == ("shell", "bash"))
    if not pinned:
        problems.append("{}: top-level `defaults: run: shell: bash` is required (pipefail)".format(path))
    for number, line in enumerate(lines, 1):
        key = key_of(line)
        if key is None or (start is not None and start < number - 1 <= start + 2):
            continue
        if key[1] == "shell" or (key[1] == "defaults" and key[0] > 0):
            problems.append("{}:{}: overrides the shell; only the top-level bash default is allowed".format(path, number))
    return problems


USES = re.compile(r"""^\s*(?:-\s+)?(?:uses|"uses"|'uses'):\s+("[^"\s]+"|'[^'\s]+'|[^\s"'#{}\[\],&*!|>]+)\s*(#.*)?$""")
USES_KEY = re.compile(r"""(?:^|[\s{,\-])["']?uses["']?\s*:""")
PINNED = re.compile(r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(/[^@]*)?@([0-9a-f]{40})$")
TAG = re.compile(r"^#\s*v(\d+)(?:\.\d+)*\s*$")
ARTIFACT_PAIR = ("actions/upload-artifact", "actions/download-artifact")


def check_action_consistency(workflows):
    """`workflows`: {repository path: text}."""
    problems, pins, majors = [], {}, {}
    for path, text in sorted(workflows.items()):
        for number, line in enumerate(text.splitlines(), 1):
            if line.strip().startswith("#") or not USES_KEY.search(line):
                continue
            found = USES.match(line)
            if not found:
                problems.append("{}:{}: cannot read this `uses` entry; only the block form "
                                "`uses: owner/repo@<sha> # vX.Y.Z` (key and value optionally quoted) is supported".format(path, number))
                continue
            reference = strip_quotes(found.group(1))
            if reference.startswith(("./", "docker://")):
                continue
            pinned = PINNED.match(reference)
            tag = TAG.match(found.group(2) or "")
            if not pinned or not tag:
                problems.append("{}:{}: `{}` is not pinned to a full SHA with a `# vX.Y.Z` comment".format(
                    path, number, reference))
                continue
            # GitHub resolves owner/repo case-insensitively; the path inside the repository is case-sensitive.
            repository = pinned.group(1).lower()
            action = repository + (pinned.group(2) or "")
            pins.setdefault(repository, set()).add((pinned.group(3), (found.group(2) or "").strip()))
            majors.setdefault(action, set()).add(int(tag.group(1)))
    for repository, seen in sorted(pins.items()):
        if len(seen) > 1:
            problems.append("{} is pinned {} different ways: {}".format(
                repository, len(seen), "; ".join("{} {}".format(sha[:12], comment) for sha, comment in sorted(seen))))
    upload, download = (majors.get(name, set()) for name in ARTIFACT_PAIR)
    if upload and download and upload != download:
        problems.append("{} (v{}) and {} (v{}) must share a major version".format(
            ARTIFACT_PAIR[0], "/v".join(map(str, sorted(upload))), ARTIFACT_PAIR[1], "/v".join(map(str, sorted(download)))))
    return problems


def main(root):
    root = Path(root)
    workflows = root / ".github" / "workflows"
    files = sorted(p.relative_to(root).as_posix() for p in list(workflows.glob("*.yml")) + list(workflows.glob("*.yaml")))
    problems = []
    try:
        problems += check_gate((workflows / "ci.yml").read_text(encoding="utf-8"))
        problems += check_drift_paths((workflows / "supply-chain-drift.yml").read_text(encoding="utf-8"), files)
        texts = {name: (root / name).read_text(encoding="utf-8") for name in files}
        problems += check_tag_triggers(texts)
        for name in files:
            problems += check_shell(name, texts[name])
        problems += check_action_consistency(texts)
        if RELEASE_WORKFLOW in texts:
            problems += check_release_concurrency(texts[RELEASE_WORKFLOW])
            problems += check_release_provenance(texts[RELEASE_WORKFLOW])
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
    assert problems == ["publish-release.yml: publishes of refs/tags/v0.57.0 and refs/tags/v0.57.1 resolve to different "
                        "concurrency groups (release-refs/tags/v0.57.0 / release-refs/tags/v0.57.1)"], problems
    problems = check_release_concurrency(release(group="publish-${{ github.ref_name }}"))
    assert len(problems) == 1 and "different concurrency groups" in problems[0], problems
    problems = check_release_concurrency(release(group="release-publish", cancel="true"))
    assert problems == ["publish-release.yml: publish job concurrency must not cancel a release in progress"], problems
    problems = check_release_concurrency(release(workflow_group="release"))
    assert problems == ["publish-release.yml: the workflow-level group is not per ref, so dry runs of different branches block each other"], problems
    assert check_release_concurrency(release(workflow_group="release-${{ github.ref }}-${{ github.run_id }}", group="release-publish")) == []
    for unreadable in ("${{ github.ref_type == 'tag' && 'tags' || github.ref }}", "${{ inputs.x }}"):
        try:
            check_release_concurrency(release(group=unreadable))
            raise AssertionError("an expression outside plain github.* references must fail closed")
        except ValueError:
            pass
    provenance = """jobs:
  build:
    runs-on: x
{job_extra}    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000
      - name: provenance
{step_extra}        env:
          GH_TOKEN: ${{{{ github.token }}}}
          GH_REPO: ${{{{ github.repository }}}}
          REF_TYPE: ${{{{ github.ref_type }}}}
          SHA: ${{{{ github.event.pull_request.head.sha || github.sha }}}}
        # comment lines are ignored
        run: |
          python -B tools/check_release_ref.py --self-test
          STATUS=$(gh api "repos/${{GH_REPO}}/compare/${{SHA}}...main" --jq .status) || STATUS="api-error"
          python -B tools/check_release_ref.py --ref-type "${{REF_TYPE}}" --sha "${{SHA}}" --status "${{STATUS}}" --summary "${{GITHUB_STEP_SUMMARY}}"
  other:
    steps:
      - run: echo
  publish:
{publish_extra}    needs: {needs}
"""

    checks_step = ("      - name: release checks\n        env:\n"
                   + "".join("          {}: {}\n".format(k, v) for k, v in PROVENANCE_ENV.items())
                   + "        run: |\n" + "".join("          {}\n".format(line) for line in CHECKS_RUN))

    def prov(job_extra="", step_extra="", needs="build", publish_extra="    if: github.event_name == 'push' && github.ref_type == 'tag'\n"):
        text = provenance.format(job_extra=job_extra, step_extra=step_extra, needs=needs, publish_extra=publish_extra)
        return text.replace("  other:\n", checks_step + "  other:\n", 1)
    good = prov()
    assert check_release_provenance(good) == [], check_release_provenance(good)
    assert check_release_provenance(prov(needs="[build, other]")) == []
    missing = ["publish-release.yml: no job the publish job needs runs the pinned provenance step (tools/check_release_ref.py "
               "with the compare status, REF_TYPE and SHA, unconditionally)"]
    final = 'python -B tools/check_release_ref.py --ref-type "${REF_TYPE}" --sha "${SHA}" --status "${STATUS}" --summary "${GITHUB_STEP_SUMMARY}"'
    bypasses = {
        "not needed": prov(needs="other"),
        "step if": prov(step_extra="        if: github.ref_type == 'branch'\n"),
        "step continue-on-error": prov(step_extra="        continue-on-error: true\n"),
        "step shell": prov(step_extra="        shell: sh {0}\n"),
        "step working-directory": prov(step_extra="        working-directory: /tmp\n"),
        "job continue-on-error": prov(job_extra="    continue-on-error: true\n"),
        "job if": prov(job_extra="    if: github.ref_type != 'tag'\n"),
        "mention only": good.replace(final, "echo tools/check_release_ref.py"),
        "self-test only": good.replace(final, "python -B tools/check_release_ref.py --self-test"),
        "hard-coded ref type": good.replace('--ref-type "${REF_TYPE}"', "--ref-type branch"),
        "hard-coded sha": good.replace('--sha "${SHA}"', "--sha 0123456789abcdef0123456789abcdef01234567"),
        "missing status": good.replace(' --status "${STATUS}"', ""),
        "hard-coded status": good.replace('--status "${STATUS}"', "--status ahead"),
        "masked exit": good.replace(final, final + " || true"),
        "extra line": good.replace(final, final + "\n          exit 0"),
        "alternate command": good.replace(final, final.replace("python -B", "python3 -B")),
        "commented out": good.replace("          " + final, "          # " + final),
        "status not from compare": good.replace("compare/${SHA}...main", "compare/main...${SHA}"),
        "ref type from input": good.replace("REF_TYPE: ${{ github.ref_type }}", "REF_TYPE: branch"),
        "sha from input": good.replace("SHA: ${{ github.event.pull_request.head.sha || github.sha }}", "SHA: ${{ inputs.sha }}"),
        "env dropped": good.replace("          GH_REPO: ${{ github.repository }}\n", ""),
    }
    for label, text in bypasses.items():
        assert text != good, label
        found = check_release_provenance(text)
        # job-level bypasses unguard both pinned steps; step-level ones only the provenance step
        assert found[0] == missing[0] and len(found) <= 2, (label, found)
    condition = ["publish-release.yml: the publish job's if: must be exactly `{}` (no status-check function may let "
                 "it run after a needed job failed)".format(PUBLISH_CONDITION)]
    checks_missing = ["publish-release.yml: no job the publish job needs runs the pinned release checks step "
                      "(tools/check_release_checks.py, unconditionally)"]
    final_checks = CHECKS_RUN[-1]
    for label, text in {
        "checks step dropped": good.replace(checks_step, ""),
        "checks hard-coded ref type": good.replace(final_checks, final_checks.replace('--ref-type "${REF_TYPE}"', "--ref-type branch")),
        "checks self-test only": good.replace("          " + final_checks + "\n", ""),
        "checks masked": good.replace(final_checks, final_checks + " || true"),
        "checks runs from elsewhere": good.replace(final_checks, final_checks.replace('--runs "${RUNNER_TEMP}/workflow-runs.jsonl"', "--runs /dev/null")),
        "checks api swallowed": good.replace(CHECKS_RUN[1], 'echo "" > "${RUNNER_TEMP}/workflow-runs.jsonl"'),
        "checks from check runs by name": good.replace(CHECKS_RUN[1], CHECKS_RUN[1].replace("actions/runs?head_sha=${SHA}&per_page=100", "commits/${SHA}/check-runs?per_page=100")),
    }.items():
        assert text != good, label
        assert check_release_provenance(text) == checks_missing, (label, check_release_provenance(text))
    for override in ("    if: success() || github.ref_type == 'tag'\n",          # milestone 1 round 2
                     "    if: SUCCESS ( ) || github.ref_type == 'tag'\n",
                     "    if: Success() || github.event_name == 'push' && github.ref_type == 'tag'\n",
                     "    if: always() && github.ref_type == 'tag'\n",
                     "    if: ${{ !cancelled() && github.ref_type == 'tag' }}\n",
                     "    if: failure() || github.ref_type == 'tag'\n",
                     "    if: github.ref_type == 'tag'\n",                       # also publishes on workflow_dispatch tags
                     ""):                                                       # no condition: publishes on every event
        assert check_release_provenance(prov(publish_extra=override)) == condition, (override, check_release_provenance(prov(publish_extra=override)))
    assert check_release_provenance(prov(publish_extra="    if:   github.event_name == 'push'   &&  github.ref_type == 'tag'\n")) == []
    assert check_release_provenance(prov(publish_extra='    if: "github.event_name == \'push\' && github.ref_type == \'tag\'"\n')) == []
    legacy_workflow = "name: release\non:\n  push:\n    tags: [\"v*\"]\njobs:\n  build:\n    runs-on: x\n"
    other = "name: ci\non:\n  push:\n    branches: [\"**\"]\njobs:\n  a:\n    runs-on: x\n"
    tagged = "name: other\non:\n  push:\n    tags:\n      - \"v*\"\njobs:\n  a:\n    runs-on: x\n"
    assert check_tag_triggers({RELEASE_WORKFLOW: legacy_workflow, ".github/workflows/ci.yml": other}) == []
    assert check_tag_triggers({RELEASE_WORKFLOW: legacy_workflow, LEGACY_RELEASE: legacy_workflow}) == [
        "{} must not exist: it is the legacy, unguarded release path to be disabled in the Actions settings, and the "
        "guarded controller lives at {}".format(LEGACY_RELEASE, RELEASE_WORKFLOW),
        "{} runs on tag pushes; only {} may".format(LEGACY_RELEASE, RELEASE_WORKFLOW)]
    assert check_tag_triggers({RELEASE_WORKFLOW: legacy_workflow, ".github/workflows/x.yml": tagged}) == [
        ".github/workflows/x.yml runs on tag pushes; only {} may".format(RELEASE_WORKFLOW)]
    assert check_tag_triggers({".github/workflows/ci.yml": other}) == ["{} is missing".format(RELEASE_WORKFLOW)]
    assert tag_trigger(tagged.replace("    tags:\n      - \"v*\"\n", "    tags-ignore: [\"x\"]\n"))
    try:
        tag_trigger("name: x\non: [push]\njobs: {}\n")
        raise AssertionError("a flow-form on: must fail closed")
    except ValueError:
        pass
    assert check_release_provenance(good.replace("  publish:\n", "  release:\n")) == ["publish-release.yml has no `publish` job"]
    shell_ok = "name: x\non:\n  push:\ndefaults:\n  run:\n    shell: bash   # pipefail\njobs:\n  a:\n    steps:\n      - run: x | tee y\n"
    assert check_shell("w.yml", shell_ok) == []
    required = ["w.yml: top-level `defaults: run: shell: bash` is required (pipefail)"]
    assert check_shell("w.yml", shell_ok.replace("defaults:\n  run:\n    shell: bash   # pipefail\n", "")) == required
    assert check_shell("w.yml", shell_ok.replace("shell: bash", "shell: sh")) == required
    assert check_shell("w.yml", shell_ok.replace("shell: bash", "shell: bash -e {0}")) == required
    assert check_shell("w.yml", shell_ok.replace("      - run: x | tee y\n", "      - run: x | tee y\n        shell: sh\n")) == [
        "w.yml:11: overrides the shell; only the top-level bash default is allowed"]
    assert check_shell("w.yml", shell_ok.replace("  a:\n", "  a:\n    defaults:\n      run:\n        shell: sh\n")) == [
        "w.yml:9: overrides the shell; only the top-level bash default is allowed",
        "w.yml:11: overrides the shell; only the top-level bash default is allowed"]
    up4 = "      - uses: actions/upload-artifact@" + "e" * 40 + " # v4.6.2\n"
    down4 = "      - uses: actions/download-artifact@" + "d" * 40 + " # v4.3.0\n"
    up7 = "      - uses: actions/upload-artifact@" + "c" * 40 + " # v7.0.2\n"
    co = "      - uses: actions/checkout@" + "1" * 40 + " # v4.2.2\n"
    init = "        uses: github/codeql-action/init@" + "f" * 40 + " # v3.28.18\n"
    analyze = "        uses: github/codeql-action/analyze@" + "f" * 40 + " # v3.28.18\n"
    consistent = {"a.yml": co + up4 + init + analyze + "      - uses: ./local-action\n", "b.yml": co + down4}
    assert check_action_consistency(consistent) == []
    assert check_action_consistency({"a.yml": co + up7, "b.yml": co + down4}) == [
        "actions/upload-artifact (v7) and actions/download-artifact (v4) must share a major version"]
    assert check_action_consistency({"a.yml": co + up7 + up4, "b.yml": down4})[0].startswith(
        "actions/upload-artifact is pinned 2 different ways")
    partial = {"a.yml": co, "b.yml": co.replace("1" * 40, "2" * 40).replace("v4.2.2", "v4.3.0")}
    assert check_action_consistency(partial) == [
        "actions/checkout is pinned 2 different ways: {} # v4.2.2; {} # v4.3.0".format("1" * 12, "2" * 12)]
    same_sha_other_comment = {"a.yml": co, "b.yml": co.replace("v4.2.2", "v4.2.3")}
    assert len(check_action_consistency(same_sha_other_comment)) == 1
    codeql_split = {"a.yml": init + analyze.replace("f" * 40, "9" * 40)}
    assert check_action_consistency(codeql_split)[0].startswith("github/codeql-action is pinned 2 different ways")
    for bad in ("      - uses: actions/checkout@v4\n", "      - uses: actions/checkout@" + "1" * 40 + "\n",
                "      - uses: actions/checkout@" + "1" * 39 + " # v4.2.2\n", "      - uses: actions/checkout@main # v4\n"):
        found = check_action_consistency({"a.yml": bad})
        assert len(found) == 1 and "is not pinned to a full SHA" in found[0], (bad, found)
    # milestone 3 round 1: quoted keys and values are read; other spellings fail closed
    quoted = {"a.yml": co + up7.replace("- uses:", '- "uses":'), "b.yml": co + down4}
    assert check_action_consistency(quoted) == [
        "actions/upload-artifact (v7) and actions/download-artifact (v4) must share a major version"], check_action_consistency(quoted)
    single = {"a.yml": co + up7.replace("- uses: ", "- 'uses': '").replace(" # v7", "' # v7"), "b.yml": co + down4}
    assert check_action_consistency(single) == [
        "actions/upload-artifact (v7) and actions/download-artifact (v4) must share a major version"], check_action_consistency(single)
    assert check_action_consistency({"a.yml": co + up4.replace("- uses: ", '- uses: "').replace(" # v4", '" # v4'), "b.yml": down4}) == []
    unreadable = ["      - {uses: actions/upload-artifact@" + "c" * 40 + "}  # v7.0.2\n",                       # flow mapping
                  "      - name: x\n        uses:\n          actions/upload-artifact@" + "c" * 40 + "\n",      # value on next line
                  "      - uses: >-\n          actions/upload-artifact@" + "c" * 40 + "\n",                   # folded scalar
                  "      - uses: *upload\n",                                                                 # alias
                  "      - \"uses\" : actions/upload-artifact@" + "c" * 40 + " # v7.0.2\n",                   # space before colon
                  "      - name: x\n        with: {uses: y}\n"]                                               # nested flow
    for bad in unreadable:
        found = check_action_consistency({"a.yml": co + bad, "b.yml": down4})
        assert any("cannot read this `uses` entry" in problem for problem in found), (bad, found)
    assert check_action_consistency({"a.yml": "      # uses: anything goes in a comment\n" + co}) == []
    # milestone 3 round 2: owner/repo is case-insensitive on GitHub, so case must not split identities
    mixed7 = up7.replace("actions/upload-artifact", "Actions/Upload-Artifact")
    assert check_action_consistency({"a.yml": co + mixed7, "b.yml": co + down4}) == [
        "actions/upload-artifact (v7) and actions/download-artifact (v4) must share a major version"]
    found = check_action_consistency({"a.yml": co + up4 + mixed7, "b.yml": down4})
    assert found[0].startswith("actions/upload-artifact is pinned 2 different ways") and len(found) == 2, found
    assert check_action_consistency({"a.yml": co + up4.replace("actions/upload-artifact", "ACTIONS/UPLOAD-ARTIFACT"),
                                     "b.yml": down4.replace("actions/download", "Actions/Download")}) == []
    found = check_action_consistency({"a.yml": co + co.replace("actions/checkout", "Actions/Checkout").replace("1" * 40, "2" * 40)})
    assert len(found) == 1 and found[0].startswith("actions/checkout is pinned 2 different ways"), found
    with tempfile.TemporaryDirectory() as directory:
        workflows = Path(directory) / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text(SELF_TEST_CI.replace("{extra}", ""), encoding="utf-8")
        (workflows / "supply-chain-drift.yml").write_text(SELF_TEST_DRIFT.replace("{push}", ".github/workflows/ci.yml"), encoding="utf-8")
        (workflows / "release.yml").write_text(release(), encoding="utf-8")   # legacy path and an unguarded release
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
