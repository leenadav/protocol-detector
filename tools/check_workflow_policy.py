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
   disabling it never disables the guarded controller. No workflow may authenticate with a
   stored credential: outside comments, the words `secrets` and `vars` may appear only as the
   exact `${{ secrets.GITHUB_TOKEN }}` (and in one job name), a word ban that no expression
   grammar (quoted `}}` in `format()` strings, multi-line expressions, `secrets: inherit`,
   `if:` conditions) can route around; the controller keeps rule 8's stricter line ban. No other workflow may hold
   `contents`, `id-token`, `attestations`, `packages`, `actions`, `deployments` or
   `statuses: write`, or `write-all`, so none can publish on another trigger (CodeQL keeps
   `security-events: write` for its SARIF upload). `tools/check_release_exposure.py`
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
8. Attestation verification (`publish-release.yml`): the publish job is an allowlist,
   exactly PUBLISH_STEPS in order (harden-runner, download, checksum check, attest, the
   pinned `gh attestation verify` of every file bound to this controller workflow, the tag
   ref, the commit and a GitHub-hosted runner, then the one `gh release create`), each
   pinned by action identity or exact env and run lines, with no job-level env, services,
   container or other keys. Only the publish job may hold a write permission, workflow
   permissions stay `contents: read`, the workflow env may only set the two Python
   variables (no BASH_ENV), and no `secrets`, `vars`, `inputs` or `client_payload` context is
   referenced in any syntax or case, so no credential but the job's own GITHUB_TOKEN can
   authenticate. So nothing can publish before the attestations are verified.
9. Encoding: outside literal block scalars (`run: |` bodies, where YAML decodes nothing), no
   workflow may contain a backslash (double-quoted escapes such as `\u0073ecrets`, escaped
   line breaks) or start a value or flow item with a tag (`!`), an anchor (`&`) or an alias
   (`*`, including `<<: *x`). With those excluded, the decoded YAML equals the source text,
   so the line-based rules above (credential contexts, `tags:` triggers, pins, pinned steps)
   cannot be bypassed by an encoding YAML undoes before GitHub reads the workflow
   (milestone 4 round 3, carried as CI/CD task 5). Flow collections can also hold structure
   on one line that the line-based parsers never read (`push: {? tags: ["v*"]}`, task 5
   round 1), so outside block scalars and `${{ }}` expressions no flow mapping (`{`, `}`)
   is allowed at all, and a flow sequence must be one line of plain or quoted scalars: no
   nested collection, no `key: value` pair, no explicit key, tag, anchor or alias.
10. Release audit (`release-audit.yml`): the detective control exists, keeps its daily
   `schedule:` trigger (scheduled runs always use the default branch's copy, which no tag can
   swap), and its `audit` job, with no job-level `if:` or `continue-on-error`, holds the pinned
   gather-and-decide step (AUDIT_ENV / AUDIT_RUN: every `v*` tag compared with main and
   resolved to its commit, every published release resolved and downloaded, and every file
   found, hidden ones included, verified against publish-release.yml for that tag and commit,
   then `tools/release_audit.py`).
11. Parser cross-check (`ci.yml`): the `workflow-lint` job, with no job-level `if:` or
   `continue-on-error`, holds the pinned step that installs the hash-pinned toolchain and runs
   `tools/check_workflow_yaml.py` (self-test, then the check, under pipefail), so the PyYAML
   second opinion cannot be dropped or masked while the gate stays green. `make check` does
   not run it because it needs the dev toolchain; `make workflow-lint` does.
12. CodeQL (`codeql.yml`): it keeps its `push` trigger on every branch (the release checks gate
   requires its push run), and both analyses exist, `analyze` (python) and `analyze-actions`
   (the workflows), each with no job-level `if:` or `continue-on-error` and with, in order,
   the pinned `init` (language, security-extended and security-and-quality suites), `analyze`
   (category, `upload: never`, output directory) and error-level gate steps, so neither
   analysis can be dropped, narrowed or masked while the workflow stays green.
13. No masked ci job (`ci.yml`): the gate only means something if every job it needs can fail.
   No job or step may set `continue-on-error`; no run line may use `|| true`, `|| :` or
   `set +e`; no job other than the gate may set `if:`, and the gate's is exactly `always()`;
   only the steps in CONDITIONAL_STEPS (the three pull-request-only behaviour-diff base steps,
   pinned by job and every field) may be conditional; and the
   gate's decision step is pinned (GATE_ENV / GATE_RUN), so a job cannot be skipped or
   allowed to fail while `ci gate (all jobs)` stays green.

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
            raise ValueError("workflow step: cannot read step line {!r}".format(line))
        name, value = key[1], key[2]
        body = []
        while index + 1 < len(lines) and (not lines[index + 1].strip() or len(lines[index + 1]) - len(lines[index + 1].lstrip(" ")) > 8):
            index += 1
            body.append(lines[index])
        if name in ("env", "with") and not value:
            env, inner = {}, 0
            while inner < len(body):
                entry = body[inner]
                inner += 1
                if not entry.strip() or entry.strip().startswith("#"):
                    continue
                pair = key_of(entry, indent=10)
                if pair is None:
                    raise ValueError("workflow step: cannot read {} line {!r}".format(name, entry))
                if pair[2] in ("|", "|-", ">", ">-"):
                    # a block scalar value: its lines are the deeper-indented ones that follow
                    text = []
                    while inner < len(body) and (not body[inner].strip() or len(body[inner]) - len(body[inner].lstrip(" ")) > 10):
                        text.append(body[inner].strip())
                        inner += 1
                    joined = "\n" if pair[2].startswith("|") else " "
                    env[pair[1]] = joined.join(line for line in text if line)
                else:
                    env[pair[1]] = strip_quotes(pair[2])
            fields[name] = env
        elif name == "run" and value in ("|", "|-"):
            # `#` lines in the block are script content (comments or here-document data), so they count
            fields[name] = [entry.strip() for entry in body if entry.strip()]
        else:
            fields[name] = value if not any(entry.strip() for entry in body) else None
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


VERIFY_ENV = {"GH_TOKEN": "${{ github.token }}", "GH_REPO": "${{ github.repository }}"}
VERIFY_RUN = [
    "for file in dist/*; do",
    'gh attestation verify "$file" --repo "$GH_REPO" --signer-workflow "$GH_REPO/.github/workflows/publish-release.yml"'
    ' --source-ref "$GITHUB_REF" --source-digest "$GITHUB_SHA" --deny-self-hosted-runners',
    "done",
]


# The publish job is an allowlist, not a denylist of publishing commands: exactly these steps,
# in this order, each pinned by action identity (version consistency is rule 7) or by its exact
# env and run lines, so no `gh api`, `gh release upload`, curl or other step can publish before
# the attestations are verified (milestone 4 round 1).
PUBLISH_STEPS = [
    {"uses": "step-security/harden-runner", "with": {"egress-policy": "audit"}},
    {"uses": "actions/download-artifact", "with": {"name": "release-dist-${{ github.sha }}", "path": "dist"}},
    {"run": ["(cd dist && sha256sum -c SHA256SUMS)"]},
    {"uses": "actions/attest-build-provenance", "with": {"subject-path": "dist/*"}},
    {"env": VERIFY_ENV, "run": VERIFY_RUN},
    {"env": dict(VERIFY_ENV, TAG="${{ github.ref_name }}"),
     "run": ['gh release create "$TAG" --verify-tag --title "$TAG" --generate-notes dist/*']},
]
PUBLISH_JOB_KEYS = {"name", "if", "needs", "concurrency", "runs-on", "timeout-minutes", "permissions", "steps"}
PUBLISH_PERMISSIONS = {"contents": "write", "id-token": "write", "attestations": "write"}
WORKFLOW_PERMISSIONS = {"contents": "read"}
WORKFLOW_ENV = {"PYTHONDONTWRITEBYTECODE", "PIP_DISABLE_PIP_VERSION_CHECK"}
# Any credential other than the job's own GITHUB_TOKEN could let a read-only job write. These
# contexts are banned outright, in any syntax (`secrets.X`, `secrets['X']`, `toJSON(secrets)`,
# any case), not only as the literal `secrets.` (milestone 4 round 2).
CREDENTIAL_CONTEXTS = re.compile(r"\b(secrets|vars|inputs|client_payload)\b", re.I)


def mapping_at(lines, indent, key):
    """The `key:` mapping at `indent` as {k: v}, its scalar value as a str, or None when absent."""
    for index, line in enumerate(lines):
        found = key_of(line, indent=indent)
        if not found or found[1] != key:
            continue
        if found[2]:
            return found[2]
        result = {}
        for entry in lines[index + 1:]:
            if not entry.strip() or entry.strip().startswith("#"):
                continue
            if len(entry) - len(entry.lstrip(" ")) <= indent:
                break
            pair = key_of(entry, indent=indent + 2)
            if pair is None:
                raise ValueError("cannot read {} entry {!r}".format(key, entry))
            result[pair[1]] = strip_quotes(pair[2])
        return result
    return None


def step_matches(fields, spec):
    if set(fields) != {"name"} | set(spec):
        return False
    for key, expected in spec.items():
        value = fields[key]
        if key == "uses":
            if not isinstance(value, str) or strip_quotes(value).split("@", 1)[0].lower() != expected:
                return False
        elif key == "run":
            if (value if isinstance(value, list) else [value]) != expected:
                return False
        elif value != expected:
            return False
    return True


def check_attestation_verify(text, publish="publish"):
    """Rule 8: the publish job is exactly PUBLISH_STEPS, and nothing else in the controller can write."""
    problems = []
    lines = text.splitlines()
    block = job_lines(text, publish)
    extra = {key_of(line, indent=4)[1] for line in block if key_of(line, indent=4)} - PUBLISH_JOB_KEYS
    if extra:
        problems.append("publish-release.yml: the {} job may not set {}".format(publish, ", ".join(sorted(extra))))
    steps = steps_of(block)
    if len(steps) != len(PUBLISH_STEPS):
        problems.append("publish-release.yml: the {} job must be exactly {} pinned steps (attest, verify, then publish); "
                        "found {}".format(publish, len(PUBLISH_STEPS), len(steps)))
    for number, (step, spec) in enumerate(zip(steps, PUBLISH_STEPS), 1):
        try:
            fields = step_fields(step)
        except ValueError as error:
            problems.append("publish-release.yml: {} step {}: {}".format(publish, number, error))
            continue
        if not step_matches(fields, spec):
            problems.append("publish-release.yml: {} step {} ({}) is not the pinned form".format(
                publish, number, fields.get("name", "unnamed")))
    if mapping_at(block, 4, "permissions") != PUBLISH_PERMISSIONS:
        problems.append("publish-release.yml: the {} job's permissions must be exactly {}".format(publish, PUBLISH_PERMISSIONS))
    if mapping_at(lines, 0, "permissions") != WORKFLOW_PERMISSIONS:
        problems.append("publish-release.yml: workflow permissions must be exactly {}".format(WORKFLOW_PERMISSIONS))
    for job in job_ids_and_needs(text)[0]:
        if job == publish:
            continue
        granted = mapping_at(job_lines(text, job), 4, "permissions")
        if isinstance(granted, str) or (granted and any(value != "read" for value in granted.values())):
            problems.append("publish-release.yml: only the {} job may hold a write permission ({} has {})".format(publish, job, granted))
    workflow_env = mapping_at(lines, 0, "env")
    if isinstance(workflow_env, str) or set(workflow_env or {}) - WORKFLOW_ENV:
        problems.append("publish-release.yml: workflow env may only set {}".format(", ".join(sorted(WORKFLOW_ENV))))
    for number, line in enumerate(lines, 1):
        found = CREDENTIAL_CONTEXTS.search(line)   # comment lines too: in a run block they are data
        if found:
            problems.append("publish-release.yml:{}: the controller may not reference `{}` (only the job's own "
                            "GITHUB_TOKEN may authenticate)".format(number, found.group(1)))
    return problems


STORED_CREDENTIAL = re.compile(r"\b(secrets|vars)\b", re.I)
# The only places the words may appear: the built-in token, written exactly, and one job name.
CREDENTIAL_ALLOWED = ("${{ secrets.GITHUB_TOKEN }}", "static analysis (ruff, bandit, secrets)")


def check_credentials(path, text):
    """Stored credentials (any secret but GITHUB_TOKEN, any variable) are banned in every workflow.

    A word ban, not an expression parser: after removing the exact allowed strings, any `secrets`
    or `vars` word on any line, comments included, fails, wherever it sits (inside `${{ }}`, a quoted
    `format('{{x}}')` string that would end a naive `}}` scan, a key such as `secrets: inherit`,
    an `if:` condition or a run block). Rule 9 excludes the YAML escapes and folds that could
    disguise the word, and GitHub resolves contexts only by identifier, so a context reference
    always contains the word (CI/CD task 6, from the task-5 round-3 finding).
    """
    problems = []
    # Every line, comments included: inside a `run: |` block a `#` line is script data (a
    # here-document line Actions interpolates and the shell can read), not a YAML comment.
    for number, line in enumerate(text.splitlines(), 1):
        visible = line
        for allowed in CREDENTIAL_ALLOWED:
            visible = visible.replace(allowed, "")
        found = STORED_CREDENTIAL.search(visible)
        if found:
            problems.append("{}:{}: `{}` may only appear as `${{{{ secrets.GITHUB_TOKEN }}}}` (stored credentials "
                            "are not allowed)".format(path, number, found.group(1)))
    return problems


RELEASE_SCOPES = {"contents", "id-token", "attestations", "packages", "actions", "deployments", "statuses"}


AUDIT_WORKFLOW = ".github/workflows/release-audit.yml"
AUDIT_ENV = {"GH_TOKEN": "${{ github.token }}", "GH_REPO": "${{ github.repository }}"}
AUDIT_RUN = [
    'python -B tools/release_audit.py --self-test',
    'facts="$RUNNER_TEMP/facts.jsonl"',
    ': > "$facts"',
    'gh api --paginate "repos/${GH_REPO}/git/matching-refs/tags/v" --jq \'.[].ref\' > "$RUNNER_TEMP/tags.txt"',
    'while IFS= read -r ref; do',
    'tag="${ref#refs/tags/}"',
    'status=$(gh api "repos/${GH_REPO}/compare/${tag}...main" --jq .status) || status="api-error"',
    'commit=$(gh api "repos/${GH_REPO}/commits/${ref}" --jq .sha) || commit="api-error"',
    'jq -nc --arg tag "$tag" --arg compare "$status" --arg commit "$commit" \'{kind: "tag", tag: $tag, compare: $compare, commit: $commit}\' >> "$facts"',
    'done < "$RUNNER_TEMP/tags.txt"',
    'gh api --paginate "repos/${GH_REPO}/releases?per_page=100" --jq \'.[] | select(.draft | not) | .tag_name\' > "$RUNNER_TEMP/releases.txt"',
    'while IFS= read -r tag; do',
    'commit=$(gh api "repos/${GH_REPO}/commits/refs/tags/${tag}" --jq .sha) || commit="api-error"',
    'dir=$(mktemp -d "$RUNNER_TEMP/assets.XXXXXX")',
    'if gh release download "$tag" --dir "$dir"; then download=ok; else download=error; fi',
    'count=$(find "$dir" -type f | wc -l)',
    'jq -nc --arg tag "$tag" --arg commit "$commit" --arg download "$download" --argjson assets "$count" \'{kind: "release", tag: $tag, commit: $commit, assets: $assets, download: $download}\' >> "$facts"',
    "while IFS= read -r -d '' file; do",
    'if gh attestation verify "$file" --repo "$GH_REPO" --signer-workflow "$GH_REPO/.github/workflows/publish-release.yml" --source-ref "refs/tags/$tag" --source-digest "$commit" --deny-self-hosted-runners > /dev/null; then verified=true; else verified=false; fi',
    'jq -nc --arg tag "$tag" --arg asset "$(basename "$file")" --argjson verified "$verified" \'{kind: "asset", tag: $tag, asset: $asset, verified: $verified}\' >> "$facts"',
    'done < <(find "$dir" -type f -print0)',
    'done < "$RUNNER_TEMP/releases.txt"',
    'python -B tools/release_audit.py --facts "$facts" --summary "$GITHUB_STEP_SUMMARY"',
]


def check_release_audit(workflows):
    if AUDIT_WORKFLOW not in workflows:
        return ["{} is missing (the scheduled release audit)".format(AUDIT_WORKFLOW)]
    text = workflows[AUDIT_WORKFLOW]
    problems = []
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if re.match(r"^on:\s*(#.*)?$", line)), None)
    end = next((j for j in range(start + 1, len(lines)) if re.match(r"^\S", lines[j])), len(lines)) if start is not None else 0
    if start is None or not any(key_of(line, indent=2) and key_of(line, indent=2)[1] == "schedule" for line in lines[start + 1:end]):
        problems.append("{}: the audit must keep its `schedule:` trigger".format(AUDIT_WORKFLOW))
    try:
        block = job_lines(text, "audit")
    except ValueError as error:
        return problems + ["{}: {}".format(AUDIT_WORKFLOW, error)]
    if {key_of(line, indent=4)[1] for line in block if key_of(line, indent=4)} & {"if", "continue-on-error"}:
        problems.append("{}: the audit job may not be conditional or allowed to fail".format(AUDIT_WORKFLOW))
    pinned = [step for step in steps_of(block) if any("tools/release_audit.py" in line for line in step)]
    if not any(set(fields) == {"name", "env", "run"} and fields["env"] == AUDIT_ENV and fields["run"] == AUDIT_RUN
               for fields in (step_fields(step) for step in pinned)):
        problems.append("{}: the audit job must run the pinned gather-and-decide step".format(AUDIT_WORKFLOW))
    return problems


CROSS_CHECK_RUN = [
    "python -m pip install --require-hashes -r requirements-dev.txt > /dev/null",
    "python -B tools/check_workflow_yaml.py --self-test",
    'python -B tools/check_workflow_yaml.py | tee -a "$GITHUB_STEP_SUMMARY"',
]


def check_cross_check(workflows, path=".github/workflows/ci.yml", job="workflow-lint"):
    if path not in workflows:
        return ["{} is missing".format(path)]
    text = workflows[path]
    try:
        block = job_lines(text, job)
    except ValueError as error:
        return ["{}: {}".format(path, error)]
    problems = []
    if {key_of(line, indent=4)[1] for line in block if key_of(line, indent=4)} & {"if", "continue-on-error"}:
        problems.append("{}: the {} job may not be conditional or allowed to fail".format(path, job))
    steps = [step_fields(step) for step in steps_of(block) if any("check_workflow_yaml.py" in line for line in step)]
    if not any(set(fields) == {"name", "run"} and fields["run"] == CROSS_CHECK_RUN for fields in steps):
        problems.append("{}: the {} job must run the pinned PyYAML cross-check step".format(path, job))
    return problems


CODEQL_WORKFLOW = ".github/workflows/codeql.yml"
CODEQL_JOBS = {"analyze": ("python", "codeql-results"), "analyze-actions": ("actions", "codeql-actions-results")}
CODEQL_SUITES = "security-extended,security-and-quality"


def check_codeql(workflows):
    if CODEQL_WORKFLOW not in workflows:
        return ["{} is missing".format(CODEQL_WORKFLOW)]
    text = workflows[CODEQL_WORKFLOW]
    problems = []
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if re.match(r"^on:\s*(#.*)?$", line)), None)
    end = next((j for j in range(start + 1, len(lines)) if re.match(r"^\S", lines[j])), len(lines)) if start is not None else 0
    on_block = lines[start + 1:end] if start is not None else []
    push = next((i for i, line in enumerate(on_block) if key_of(line, indent=2) and key_of(line, indent=2)[1] == "push"), None)
    branches = [key_of(line, indent=4)[2] for line in on_block[push + 1:] if key_of(line, indent=4)][:1] if push is not None else []
    if push is None or branches != ['["**"]']:
        problems.append("{}: CodeQL must keep `push: branches: [\"**\"]` (the release checks gate needs its push run)".format(CODEQL_WORKFLOW))
    for job, (language, output) in CODEQL_JOBS.items():
        try:
            block = job_lines(text, job)
        except ValueError:
            problems.append("{}: the `{}` ({}) analysis is missing".format(CODEQL_WORKFLOW, job, language))
            continue
        if {key_of(line, indent=4)[1] for line in block if key_of(line, indent=4)} & {"if", "continue-on-error"}:
            problems.append("{}: the `{}` job may not be conditional or allowed to fail".format(CODEQL_WORKFLOW, job))
        expected = [
            ({"uses", "with"}, "github/codeql-action/init", {"languages": language, "queries": CODEQL_SUITES}, None),
            ({"uses", "with"}, "github/codeql-action/analyze", {"category": "/language:" + language, "upload": "never", "output": output}, None),
            ({"name", "run"}, None, None, ["python3 -B tools/codeql_gate.py " + output]),
        ]
        position = -1
        for keys, action, with_, run in expected:
            found = None
            for index, step in enumerate(steps_of(block)):
                fields = step_fields(step)
                if index <= position or set(fields) != keys:
                    continue
                if action and (strip_quotes(fields.get("uses") or "").split("@", 1)[0].lower() != action or fields.get("with") != with_):
                    continue
                if run and (fields.get("run") if isinstance(fields.get("run"), list) else [fields.get("run")]) != run:
                    continue
                found = index
                break
            if found is None:
                problems.append("{}: the `{}` job lacks the pinned {} step (in order: init, analyze, gate)".format(
                    CODEQL_WORKFLOW, job, action.rsplit("/", 1)[1] if action else "error-level gate"))
                break
            position = found
    return problems


# The only ci steps that may be conditional: the three pull-request-only behaviour-diff base steps,
# pinned by job, every field and action identity (version consistency is rule 7), so the condition
# cannot be moved onto a test, lint or policy step, nor a critical step renamed into an exception.
CONDITIONAL_STEPS = {
    "behaviour-diff": [
        {'name': 'Check out the pull request base (the first checkout drops its credentials, so git fetch cannot)', 'if': "github.event_name == 'pull_request'", 'uses': 'actions/checkout', 'with': {'persist-credentials': 'false', 'fetch-depth': '1', 'ref': '${{ github.event.pull_request.base.sha }}', 'path': 'pr-base'}},
        {'name': 'Compare with the pull request base as well (whole change, when the base carries the engine)', 'if': "github.event_name == 'pull_request'", 'env': {'BASE_SHA': '${{ github.event.pull_request.base.sha }}', 'SEED': '${{ github.run_id }}'}, 'run': ['if [ -f pr-base/protocol_engine/engine.py ]; then', 'python -B tools/compare_engine.py pr-base --iterations 300 --seed "$SEED" --report behaviour-diff-base.md --report-only', 'else', 'printf \'# Engine behaviour diff\\n\\nThe pull request base %s has no engine to compare with.\\n\' "$BASE_SHA" > behaviour-diff-base.md', 'fi', 'head -60 behaviour-diff-base.md', '{', 'echo "### Behaviour diff against the pull request base"', 'echo', 'head -40 behaviour-diff-base.md', '} >> "$GITHUB_STEP_SUMMARY"']},
        {'name': 'Upload the pull request base diff report', 'if': "github.event_name == 'pull_request'", 'uses': 'actions/upload-artifact', 'with': {'name': 'behaviour-diff-base-${{ github.sha }}', 'path': 'behaviour-diff-base.md', 'retention-days': '30'}},
    ],
}
GATE_ENV = {"RESULTS": "${{ toJSON(needs) }}"}
GATE_RUN = [
    'echo "$RESULTS" | jq -r \'to_entries[] | "\\(.key): \\(.value.result)"\' | tee gate.txt',
    '{',
    'echo "### ci gate"',
    'echo',
    "echo '```'",
    'cat gate.txt',
    "echo '```'",
    '} >> "$GITHUB_STEP_SUMMARY"',
    'echo "$RESULTS" | jq -e \'all(.[]; .result == "success")\' > /dev/null',
]
MASKING = re.compile(r"\|\|\s*(true|:)\b|\|\|\s*:\s*$|\bset\s+\+e\b")
# Shell that can swallow a failing status, checked on every ci run line (expressions removed). There
# is no general way to prove a script fails when its check fails, so this is an allowlist of exact
# lines for `||`, `&&` and `if`, and the constructs in SHELL_BANNED are not allowed at all.
# `||` is allowed only on these exact lines (CI/CD task 11, from the item-10 round-3 finding: a
# pattern for "a handler that fails again" was satisfied by `cmd || echo ignored || (... && exit 1)`,
# whose middle handler short-circuits). Two fail again; the bandit one only picks summary text.
SHELL_ALLOWED_OR = {
    'grep -q \'^dependencies = \\[\\]\' pyproject.toml || (echo "runtime dependencies are not allowed" && exit 1)',
    'python -B -m unittest discover -q 2> test-output.txt || (cat test-output.txt && exit 1)',
    "grep -A 12 '^Run metrics:' bandit.txt || tail -n 15 bandit.txt",
}
SHELL_ALLOWED_IF = {
    'if [ -f pr-base/protocol_engine/engine.py ]; then',
    'if git rev-parse --verify -q HEAD~1 >/dev/null && git cat-file -e HEAD~1:protocol_engine/engine.py 2>/dev/null; then',
}
# Under `bash -e` a failing command on the left of `&&` does not stop the script, so `&&` is allowed
# only on the SHELL_ALLOWED_OR lines (inside their handlers), in an allowed `if` condition, or in these
# subshells, whose status is their last command's.
SHELL_ALLOWED_AND = {
    '(cd /tmp && /tmp/wheel-env/bin/python "$GITHUB_WORKSPACE/tools/wheel_smoke.py") | tee -a "$GITHUB_STEP_SUMMARY"',
    '(cd /tmp && /tmp/wheel-env39/bin/python "$GITHUB_WORKSPACE/tools/wheel_smoke.py") | tee -a "$GITHUB_STEP_SUMMARY"',
}
SHELL_BANNED = re.compile(r"\bexit\s+0\b|\breturn\b|\bset\s+\+|\btrap\b|(^|[;&|(]\s*)!\s|\b(while|until)\b|(^|[^&])&\s*$")


def shell_problem(line):
    code = EXPRESSION_SPAN.sub("EXPR", line).strip()
    if line.strip() in SHELL_ALLOWED_OR:
        return None
    if SHELL_BANNED.search(code):
        return "`{}` can swallow a failing status".format(SHELL_BANNED.search(code).group(0).strip())
    if "||" in code:
        return "`||` outside the exact lines in SHELL_ALLOWED_OR"
    if re.search(r"\bif\b", code) and line not in SHELL_ALLOWED_IF:
        return "`if` with a condition outside SHELL_ALLOWED_IF (a check inside a condition cannot fail the step)"
    if "&&" in code and line not in SHELL_ALLOWED_IF and line.strip() not in SHELL_ALLOWED_AND:
        return "`&&` outside the allowed lines (under bash -e a failure on its left does not stop the script)"
    return None


def check_ci_masking(workflows, path=".github/workflows/ci.yml", gate="gate"):
    if path not in workflows:
        return ["{} is missing".format(path)]
    text = workflows[path]
    problems = []
    for number, line in enumerate(text.splitlines(), 1):
        key = key_of(line)
        if key and key[1] == "continue-on-error":
            problems.append("{}:{}: continue-on-error would let a job the gate needs fail unseen".format(path, number))
        if MASKING.search(line):
            problems.append("{}:{}: `{}` masks a failing command".format(path, number, MASKING.search(line).group(0).strip()))
    ids, _ = job_ids_and_needs(text)
    for job in ids:
        block = job_lines(text, job)
        condition = next((key_of(line, indent=4)[2] for line in block if key_of(line, indent=4) and key_of(line, indent=4)[1] == "if"), None)
        if job == gate:
            if strip_quotes(condition or "") != "always()":
                problems.append("{}: the {} job's if: must be exactly always()".format(path, gate))
            steps = [step_fields(step) for step in steps_of(block)]
            if not any(set(fields) == {"name", "env", "run"} and fields["env"] == GATE_ENV and fields["run"] == GATE_RUN
                       for fields in steps):
                problems.append("{}: the {} job must run the pinned all-jobs decision step".format(path, gate))
            continue
        if condition is not None:
            problems.append("{}: job {} may not set if: (the gate would see it skipped only if it is listed)".format(path, job))
        for step in steps_of(block):
            run = step_fields(step).get("run")
            for line in (run if isinstance(run, list) else [run] if run else []):
                reason = shell_problem(line)
                if reason:
                    problems.append("{}: job {}: {}: {}".format(path, job, line.strip()[:60], reason))
        for step in steps_of(block):
            fields = step_fields(step)
            if "if" not in fields:
                continue
            normalized = dict(fields)
            if "uses" in normalized:
                normalized["uses"] = strip_quotes(normalized["uses"] or "").split("@", 1)[0].lower()
            if normalized not in CONDITIONAL_STEPS.get(job, []):
                problems.append("{}: job {}: step `{}` may not be conditional (only the pinned pull-request-only "
                                "behaviour-diff base steps may)".format(path, job, fields.get("name", "unnamed")))
    return problems


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
    # A workflow outside the controller holding a release-relevant write scope could publish on
    # any trigger, tag or not; only security-events (CodeQL's SARIF upload) may be written elsewhere.
    for path, text in sorted(workflows.items()):
        if path == RELEASE_WORKFLOW:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if line.strip().startswith("#"):
                continue
            key = key_of(line)
            if key and key[1] == "permissions" and strip_quotes(key[2]).replace(" ", "") in ("write-all",):
                problems.append("{}:{}: write-all outside {}".format(path, number, RELEASE_WORKFLOW))
            elif key and strip_quotes(key[2]) == "write" and key[1] in RELEASE_SCOPES:
                problems.append("{}:{}: `{}: write` outside {}".format(path, number, key[1], RELEASE_WORKFLOW))
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


BLOCK_SCALAR = re.compile(r":\s*[|>][-+0-9]*\s*(#.*)?$")
EXPRESSION_SPAN = re.compile(r"\$\{\{.*?\}\}")


def flow_items(text):
    """Comma-separated items of a flow sequence body, quote-aware; None when unreadable."""
    items, current, quote = [], "", None
    for char in text:
        if quote:
            current += char
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
            current += char
        elif char == ",":
            items.append(current.strip())
            current = ""
        else:
            current += char
    if quote:
        return None
    items.append(current.strip())
    return items


def mask_quotes(line):
    """The line without its comment, each quoted string replaced by `"Q"`; None on an open quote."""
    out, quote = "", None
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = None
                out += 'Q"'
        elif char in "\"'" and (out.rstrip()[-1:] in ("", ":", "-", "[", ",", "{")):
            # a quote opens a quoted scalar only where a scalar starts; `job's` is plain text
            quote = char
            out += '"'
        elif char == "#" and (index == 0 or line[index - 1] in " \t"):
            break
        else:
            out += char
    return None if quote else out


def flow_problem(line):
    """Why a non-block line's flow collections are not allowed, or None."""
    code = mask_quotes(EXPRESSION_SPAN.sub("EXPR", line))
    if code is None:
        return "unterminated quote"
    if "{" in code or "}" in code:
        return "flow mapping (only `${{ }}` expressions may contain braces)"
    if "[" not in code and "]" not in code:
        return None
    start, end = code.find("["), code.rfind("]")
    if start < 0 or end < start or code.count("[") != 1 or code.count("]") != 1:
        return "flow sequence must be a single, non-nested `[...]` on one line"
    items = flow_items(code[start + 1:end])
    if items is None:
        return "unterminated quote in a flow sequence"
    for item in items:
        if item.startswith(("?", "&", "*", "!", "-")):
            return "flow sequence item `{}` is not a plain scalar".format(item)
        unquoted = item if not item[:1] in "\"'" else ""
        if ": " in unquoted or unquoted.endswith(":"):
            return "flow sequence item `{}` is a mapping".format(item)
    return None
FLOW_NODE = re.compile(r"[\[{,]\s*[&*!]")


def check_encoding(path, text):
    problems = []
    block_indent = None
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if block_indent is not None:
            if not stripped or indent > block_indent:
                continue          # literal or folded block content: YAML decodes no escapes here
            block_indent = None
        if not stripped or stripped.startswith("#"):
            continue
        if "\\" in line:
            problems.append("{}:{}: backslash outside a block scalar (YAML escapes are not allowed)".format(path, number))
        key, item = KEY.match(line), ITEM.match(line)
        value = (key.group(3) or "") if key else (item.group(2) if item else "")
        if stripped.startswith(("<<", "&", "*", "!", "? ")):
            problems.append("{}:{}: YAML merge key, explicit key, tag, anchor or alias".format(path, number))
        elif value.startswith(("&", "*", "!")):
            problems.append("{}:{}: YAML tag, anchor or alias `{}`".format(path, number, value))
        else:
            reason = flow_problem(line)
            if reason:
                problems.append("{}:{}: {}".format(path, number, reason))
        if BLOCK_SCALAR.search(line):
            block_indent = indent
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
        problems += check_release_audit(texts)
        problems += check_cross_check(texts)
        problems += check_codeql(texts)
        problems += check_ci_masking(texts)
        for name in files:
            problems += check_encoding(name, texts[name])
            problems += check_credentials(name, texts[name])
        if RELEASE_WORKFLOW in texts:
            problems += check_release_concurrency(texts[RELEASE_WORKFLOW])
            problems += check_release_provenance(texts[RELEASE_WORKFLOW])
            problems += check_attestation_verify(texts[RELEASE_WORKFLOW])
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
    writer = other + "    permissions:\n      contents: write\n"
    assert check_tag_triggers({RELEASE_WORKFLOW: legacy_workflow, ".github/workflows/w.yml": writer}) == [
        ".github/workflows/w.yml:9: `contents: write` outside {}".format(RELEASE_WORKFLOW)]
    for scope in ("id-token", "attestations", "packages"):
        assert check_tag_triggers({RELEASE_WORKFLOW: legacy_workflow, "w.yml": writer.replace("contents", scope)}), scope
    assert check_tag_triggers({RELEASE_WORKFLOW: legacy_workflow, "w.yml": other + "permissions: write-all\n"})
    assert check_tag_triggers({RELEASE_WORKFLOW: legacy_workflow, "w.yml": writer.replace("contents", "security-events")}) == []
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
    with open(RELEASE_WORKFLOW, encoding="utf-8") as handle:
        controller = handle.read()
    assert check_attestation_verify(controller) == [], check_attestation_verify(controller)
    verify_line = VERIFY_RUN[1]
    attest_block = controller[controller.index("      - name: Attest build provenance"):controller.index("      - name: Every file's attestation")]
    verify_block = controller[controller.index("      - name: Every file's attestation"):controller.index("      - name: Publish the release")]
    publish_block = controller[controller.index("      - name: Publish the release"):]
    verify_name = "      - name: Every file's attestation must verify before anything is published\n"
    early = ('      - name: Create the release early\n        env:\n          GH_TOKEN: ${{ github.token }}\n'
             '        run: |\n          gh api "repos/$GITHUB_REPOSITORY/releases" -f tag_name="$GITHUB_REF_NAME"\n'
             '          gh release upload "$GITHUB_REF_NAME" dist/*\n')
    cases = {
        # milestone 4 round 1: an unrecognized publisher before verification
        "gh api release + upload before verify": controller.replace(verify_block, early + verify_block),
        "gh release upload after attest": controller.replace(verify_block, early.replace(
            '          gh api "repos/$GITHUB_REPOSITORY/releases" -f tag_name="$GITHUB_REF_NAME"\n', "") + verify_block),
        "curl upload": controller.replace(verify_block, "      - run: curl -X POST https://uploads.github.com/x\n" + verify_block),
        "verify dropped": controller.replace(verify_block, ""),
        "verify after publish": controller.replace(verify_block, "").replace(publish_block, publish_block + verify_block),
        "attest dropped": controller.replace(attest_block, ""),
        "verify masked": controller.replace(verify_line, verify_line + " || true"),
        "verify conditional": controller.replace(verify_name, verify_name + "        if: false\n"),
        "verify continue-on-error": controller.replace(verify_name, verify_name + "        continue-on-error: true\n"),
        "signer workflow dropped": controller.replace(' --signer-workflow "$GH_REPO/.github/workflows/publish-release.yml"', ""),
        "source ref dropped": controller.replace(' --source-ref "$GITHUB_REF"', ""),
        "self-hosted allowed": controller.replace(" --deny-self-hosted-runners", ""),
        "one file only": controller.replace("for file in dist/*; do", "for file in dist/*.whl; do"),
        "second publisher": controller + "      - run: gh release create again\n",
        "attest subject narrowed": controller.replace('          subject-path: "dist/*"', '          subject-path: "dist/*.whl"'),
        "other artifact": controller.replace("          name: release-dist-${{ github.sha }}\n          path: dist",
                                             "          name: something-else\n          path: dist"),
        "attest replaced": controller.replace("uses: actions/attest-build-provenance@", "uses: someone/attest-build-provenance@"),
        "publish job env": controller.replace("    timeout-minutes: 10\n    permissions:\n      contents: write",
                                              "    timeout-minutes: 10\n    env:\n      BASH_ENV: ./x.sh\n    permissions:\n      contents: write"),
        "workflow BASH_ENV": controller.replace('  PIP_DISABLE_PIP_VERSION_CHECK: "1"\n', '  PIP_DISABLE_PIP_VERSION_CHECK: "1"\n  BASH_ENV: ./x.sh\n', 1),
        "build job writes": controller.replace("      contents: read   # checkout", "      contents: write   # checkout"),
        "workflow writes": controller.replace("permissions:\n  contents: read\n", "permissions:\n  contents: write\n", 1),
        "write-all": controller.replace("permissions:\n  contents: read\n", "permissions: write-all\n", 1),
        "publish extra permission": controller.replace("      attestations: write   # attest", "      packages: write\n      attestations: write   # attest"),
        "secret": controller.replace("          GH_TOKEN: ${{ github.token }}\n          GH_REPO: ${{ github.repository }}\n          TAG:",
                                     "          GH_TOKEN: ${{ secrets.RELEASE_PAT }}\n          GH_REPO: ${{ github.repository }}\n          TAG:"),
    }
    build_env = "          GH_TOKEN: ${{ github.token }}\n          GH_REPO: ${{ github.repository }}\n          REF_TYPE:"
    for label, token in {"secrets index": "${{ secrets['RELEASE_PAT'] }}", "secrets index spaced": '${{ secrets [ "RELEASE_PAT" ] }}',
                         "secrets json": "${{ fromJSON(toJSON(secrets)).RELEASE_PAT }}", "secrets upper": "${{ SECRETS.RELEASE_PAT }}",
                         "vars": "${{ vars.RELEASE_PAT }}", "inputs": "${{ inputs.token }}",
                         "event inputs": "${{ github.event.inputs.token }}", "dispatch payload": "${{ github.event.client_payload.token }}"}.items():
        cases["build job " + label] = controller.replace(build_env, build_env.replace("${{ github.token }}", token), 1)
    for label, text in cases.items():
        assert text != controller, label
        assert check_attestation_verify(text), label
    assert any("may not reference `secrets`" in problem for problem in check_attestation_verify(cases["build job secrets index"]))
    # comment lines are scanned too (task 6 round 1: in a run block a `#` line is data)
    assert check_attestation_verify(controller.replace("    steps:\n", "    # no secrets, vars or inputs are used here\n    steps:\n", 1))
    # CI/CD task 5 (milestone 4 round 3): encodings YAML undoes before GitHub reads the file
    plain = ("on:\n  push:\n    tags: [\"v*\"]\njobs:\n  a:\n    steps:\n      - run: |\n          echo \"a\\\\b\" && x\n"
             "      - env:\n          T: ${{ github.token }}\n        run: echo ok && true\n      - run: >-\n          x \\\\\n"
             "    # comment with \\\\ and *alias\n")
    assert check_encoding("w.yml", plain) == [], check_encoding("w.yml", plain)
    fine = ('    needs: [verify, behaviour-diff]\n    python: ["3.9", "3.11"]\n    tags: ["v*"]  # a comment, with: [x]\n'
            "    group: ${{ github.ref_type == 'tag' && 'a' || format('b-{0}', github.ref) }}\n    name: \"a: b, c\"\n"
            "      - name: Fetch the build job's files\n      - name: \"quoted {braces} and [brackets]\"\n")
    assert check_encoding("w.yml", fine) == [], check_encoding("w.yml", fine)
    tag_trick = 'on:\n  push: {? tags: ["v*"]}\njobs:\n  a:\n    runs-on: x\n'
    assert not tag_trigger(tag_trick)        # what the line parser sees; rule 9 is what rejects it
    assert check_encoding("x.yml", tag_trick) == ["x.yml:2: flow mapping (only `${{ }}` expressions may contain braces)"]
    for label, line in {"unicode escape": '          GH_TOKEN: "${{ \\u0073ecrets.RELEASE_PAT }}"\n',
                        "hex escape": '          GH_TOKEN: "${{ \\x73ecrets.RELEASE_PAT }}"\n',
                        "escaped key": '    "t\\u0061gs": ["v*"]\n',
                        "escaped line break": '          GH_TOKEN: "${{ sec\\\n            rets.RELEASE_PAT }}"\n',
                        "anchor": "          GH_TOKEN: &tok ${{ github.token }}\n",
                        "alias": "          GH_TOKEN: *tok\n",
                        "tag": "          GH_TOKEN: !!str ${{ github.token }}\n",
                        "merge key": "        <<: *defaults\n",
                        "flow alias": "    tags: [*v]\n",
                        "list alias": "      - *step\n",
                        "explicit key": "    ? secrets\n",
                        "anchored mapping": "    &defaults\n",
                        # task 5 round 1: flow collections hiding structure from the line parsers
                        "flow explicit key": '  push: {? tags: ["v*"]}\n',
                        "flow mapping": '  push: {tags: ["v*"]}\n',
                        "flow mapping value": "    with: {subject-path: dist/*}\n",
                        "nested flow": '    tags: [["v*"]]\n',
                        "flow pair": '    needs: [build: x]\n',
                        "flow pair end": '    needs: [build:]\n',
                        "flow explicit item": '    needs: [? build]\n',
                        "multi-line flow": '    needs: [build,\n',
                        "unterminated quote": '    tags: ["v*]\n',
                        "quoted item then pair": '    needs: ["a", b: c]\n'}.items():
        found = check_encoding("w.yml", plain + "jobs2:\n  b:\n    x:\n" + line)
        assert found, (label, found)
    # task 5 round 2 and CI/CD task 6: a read-only workflow authenticating with a stored PAT
    pat_job = ("jobs:\n  a:\n    permissions:\n      contents: read\n    steps:\n      - env:\n"
               "          GH_TOKEN: {value}\n        run: gh release create \"$GITHUB_REF_NAME\" dist/*\n")
    assert check_credentials("w.yml", pat_job.format(value="${{ secrets.GITHUB_TOKEN }}")) == []
    assert check_credentials("w.yml", pat_job.format(value="${{ github.token }}")) == []
    assert check_credentials("w.yml", "    name: static analysis (ruff, bandit, secrets)\n") == []
    # task 6 round 1: a `#` line inside a run block is here-document data, not a YAML comment
    heredoc = ("      - run: |\n          TOKEN=$(sed -n 's/^#//p' <<'DATA'\n          #${{ secrets.RELEASE_PAT }}\n"
               "          DATA\n          )\n          GH_TOKEN=\"$TOKEN\" gh release create v0 dist/*\n")
    assert check_credentials("w.yml", heredoc), "heredoc data line"
    assert check_credentials("w.yml", "      # secrets and vars in a YAML comment are rejected too\n")
    assert check_credentials("w.yml", "      - run: |\n          # ${{ vars.RELEASE_PAT }}\n")
    for value in ("${{ secrets.RELEASE_PAT }}", "${{ secrets['RELEASE_PAT'] }}", "${{ SECRETS.release_pat }}",
                  "${{ vars.RELEASE_PAT }}", "${{ fromJSON(toJSON(secrets)).RELEASE_PAT }}",
                  "${{ secrets.GITHUB_TOKEN || secrets.RELEASE_PAT }}", "${{secrets.GITHUB_TOKEN}}",
                  # task 5 round 3: `}}` inside a quoted format() string ended the old expression scan
                  '"${{ false && format(\'{{x}}\') || secrets.RELEASE_PAT }}"',
                  "\"${{ false && format('{{{0}}}', 'a') || vars.RELEASE_PAT }}\"",
                  "\"${{ format('it''s }}') && secrets.RELEASE_PAT }}\""):
        found = check_credentials("w.yml", pat_job.format(value=value))
        assert len(found) == 1 and "may only appear as" in found[0], (value, found)
    two_lines = pat_job.format(value="${{\n            secrets.RELEASE_PAT }}")
    assert len(check_credentials("w.yml", two_lines)) == 1
    assert check_credentials("w.yml", "    uses: ./.github/workflows/x.yml\n    secrets: inherit\n")
    assert check_credentials("w.yml", "    if: secrets.RELEASE_PAT != ''\n")
    assert check_credentials("w.yml", "      - run: |\n          echo ${{ secrets.RELEASE_PAT }}\n")
    assert check_credentials("w.yml", "    name: static analysis (ruff, bandit, secrets) ${{ secrets.X }}\n")
    # the task-5 round-3 workflow, run through the full policy over a copy of the real tree
    adversarial = ("name: bypass\non:\n  push:\n    branches: [\"main\"]\npermissions:\n  contents: read\n"
                   "defaults:\n  run:\n    shell: bash\njobs:\n  publish:\n    runs-on: ubuntu-24.04\n    steps:\n"
                   "      - name: Publish outside the controller\n        env:\n"
                   "          GH_TOKEN: \"${{ false && format('{{x}}') || secrets.RELEASE_PAT }}\"\n"
                   "        run: gh release create \"v0.0.0-bypass\" --generate-notes\n")
    with open(AUDIT_WORKFLOW, encoding="utf-8") as handle:
        audit_text = handle.read()
    assert check_release_audit({AUDIT_WORKFLOW: audit_text}) == [], check_release_audit({AUDIT_WORKFLOW: audit_text})
    decide = "python -B tools/release_audit.py --facts \"$facts\" --summary \"$GITHUB_STEP_SUMMARY\""
    verify_flag = ' --signer-workflow "$GH_REPO/.github/workflows/publish-release.yml"'
    for label, text in {
        "schedule dropped": audit_text.replace('  schedule:\n    - cron: "37 6 * * *"\n', ""),
        "decision masked": audit_text.replace(decide, decide + " || true"),
        "signer dropped": audit_text.replace(verify_flag, ""),
        "source digest dropped": audit_text.replace(' --source-digest "$commit"', ""),
        "glob instead of find": audit_text.replace('done < <(find "$dir" -type f -print0)', 'done < <(printf "%s\\0" "$dir"/*)'),
        "tags skipped": audit_text.replace("tags/v\" --jq", "tags/none\" --jq"),
        "job conditional": audit_text.replace("    timeout-minutes: 30\n", "    timeout-minutes: 30\n    if: false\n"),
        "job allowed to fail": audit_text.replace("    timeout-minutes: 30\n", "    timeout-minutes: 30\n    continue-on-error: true\n"),
        "step allowed to fail": audit_text.replace("      - name: Gather facts", "      - continue-on-error: true\n        name: Gather facts"),
    }.items():
        assert text != audit_text, label
        assert check_release_audit({AUDIT_WORKFLOW: text}), label
    assert check_release_audit({}) == ["{} is missing (the scheduled release audit)".format(AUDIT_WORKFLOW)]
    # CI/CD item 10: no ci job the gate needs can be masked
    with open(".github/workflows/ci.yml", encoding="utf-8") as handle:
        ci_text_for_masking = handle.read()
    ci_ok = {".github/workflows/ci.yml": ci_text_for_masking}
    assert check_ci_masking(ci_ok) == [], check_ci_masking(ci_ok)
    decision = GATE_RUN[-1]
    for label, text in {
        "job continue-on-error": ci_text_for_masking.replace("    name: workflow lint (actionlint, zizmor)\n",
                                                           "    name: workflow lint (actionlint, zizmor)\n    continue-on-error: true\n"),
        "step continue-on-error": ci_text_for_masking.replace("      - name: Every ci job must have succeeded\n",
                                                            "      - name: Every ci job must have succeeded\n        continue-on-error: true\n"),
        "or true": ci_text_for_masking.replace("          ruff check --output-format github .\n", "          ruff check --output-format github . || true\n", 1),
        "or colon": ci_text_for_masking.replace("          ruff check --output-format github .\n", "          ruff check --output-format github . || :\n", 1),
        "set +e": ci_text_for_masking.replace("          ruff check --output-format github .\n", "          set +e\n          ruff check --output-format github .\n", 1),
        "job skipped": ci_text_for_masking.replace("    name: workflow lint (actionlint, zizmor)\n",
                                                 "    name: workflow lint (actionlint, zizmor)\n    if: false\n"),
        "step skipped": ci_text_for_masking.replace("        if: github.event_name == 'pull_request'\n", "        if: false\n", 1),
        # item 10 round 1: the pull-request-only condition moved onto critical steps
        "tests skipped on push": ci_text_for_masking.replace("      - name: Compile every module (syntax gate, no runtime dependencies allowed)\n",
            "      - name: Compile every module (syntax gate, no runtime dependencies allowed)\n        if: github.event_name == 'pull_request'\n", 1),
        "lint skipped on push": ci_text_for_masking.replace("      - name: Workflow policy (gate covers every ci job",
            "      - if: github.event_name == 'pull_request'\n        name: Workflow policy (gate covers every ci job", 1),
        "behaviour diff skipped on push": ci_text_for_masking.replace("      - name: Compare every fixture, truncation and seeded mutation with the parent commit\n",
            "      - name: Compare every fixture, truncation and seeded mutation with the parent commit\n        if: github.event_name == 'pull_request'\n", 1),
        "critical step renamed into an exception": ci_text_for_masking.replace(
            "      - name: Compare every fixture, truncation and seeded mutation with the parent commit\n",
            "      - name: Upload the pull request base diff report\n        if: github.event_name == 'pull_request'\n", 1),
        # item 10 round 2: generic handlers and other ways to swallow a status
        "or echo": ci_text_for_masking.replace("          ruff check --output-format github .\n", "          ruff check --output-format github . || echo ignored\n", 1),
        "or exit 0": ci_text_for_masking.replace("          ruff check --output-format github .\n", "          ruff check --output-format github . || exit 0\n", 1),
        "or subshell without refail": ci_text_for_masking.replace("          ruff check --output-format github .\n", "          ruff check --output-format github . || (echo failed)\n", 1),
        "refail exit 0": ci_text_for_masking.replace("|| (echo \"runtime dependencies are not allowed\" && exit 1)", "|| (echo \"runtime dependencies are not allowed\" && exit 0)", 1),
        "negated": ci_text_for_masking.replace("          ruff check --output-format github .\n", "          ! ruff check --output-format github .\n", 1),
        "inside if": ci_text_for_masking.replace("          ruff check --output-format github .\n", "          if ruff check --output-format github .; then echo ok; fi\n", 1),
        "until loop": ci_text_for_masking.replace("          ruff check --output-format github .\n", "          until ruff check --output-format github .; do break; done\n", 1),
        "trap": ci_text_for_masking.replace("          ruff check --output-format github .\n", "          trap 'exit 0' ERR\n          ruff check --output-format github .\n", 1),
        "set +o": ci_text_for_masking.replace("          ruff check --output-format github .\n", "          set +o errexit\n          ruff check --output-format github .\n", 1),
        "background": ci_text_for_masking.replace("          ruff check --output-format github .\n", "          ruff check --output-format github . &\n", 1),
        # task 11 (item 10 round 3): an earlier handler short-circuits a final re-fail suffix
        "chained handler": ci_text_for_masking.replace("          ruff check --output-format github .\n",
            "          ruff check --output-format github . || echo ignored || (echo failed && exit 1)\n", 1),
        "new re-fail line": ci_text_for_masking.replace("          ruff check --output-format github .\n",
            "          ruff check --output-format github . || (echo failed && exit 1)\n", 1),
        "allowed line extended": ci_text_for_masking.replace("|| (cat test-output.txt && exit 1)", "|| true || (cat test-output.txt && exit 1)", 1),
        "and-list masks": ci_text_for_masking.replace("          ruff check --output-format github .\n", "          ruff check --output-format github . && echo checked\n", 1),
        "explicit exit 0": ci_text_for_masking.replace("          ruff check --output-format github .\n", "          ruff check --output-format github .; exit 0\n", 1),
        "exception step body changed": ci_text_for_masking.replace("--iterations 300 --seed \"$SEED\" --report behaviour-diff-base.md --report-only",
                                                                  "--iterations 1 --seed \"$SEED\" --report behaviour-diff-base.md --report-only"),
        "gate condition changed": ci_text_for_masking.replace("    if: always()\n", "    if: success()\n"),
        "gate decision masked": ci_text_for_masking.replace(decision, decision + " || echo ignored"),
        "gate decision dropped": ci_text_for_masking.replace("          " + decision + "\n", ""),
    }.items():
        assert text != ci_text_for_masking, label
        assert check_ci_masking({".github/workflows/ci.yml": text}), label
    # item 9 round 1: both CodeQL analyses are pinned
    with open(CODEQL_WORKFLOW, encoding="utf-8") as handle:
        codeql_text = handle.read()
    assert check_codeql({CODEQL_WORKFLOW: codeql_text}) == [], check_codeql({CODEQL_WORKFLOW: codeql_text})
    actions_job = codeql_text[codeql_text.index("  analyze-actions:\n"):]
    for label, text in {
        "actions job removed": codeql_text.replace(actions_job, ""),
        "python job renamed": codeql_text.replace("  analyze:\n", "  analyse:\n", 1),
        "actions language changed": codeql_text.replace("          languages: actions\n", "          languages: python\n"),
        "suites narrowed": codeql_text.replace("queries: security-extended,security-and-quality", "queries: security-extended", 1),
        "gate masked": codeql_text.replace("run: python3 -B tools/codeql_gate.py codeql-actions-results",
                                           "run: python3 -B tools/codeql_gate.py codeql-actions-results || true"),
        "gate dropped": codeql_text.replace("      - name: Fail on error-level CodeQL findings (summary table of packs, rules and findings)\n"
                                            "        run: python3 -B tools/codeql_gate.py codeql-actions-results\n", ""),
        "gate pointed elsewhere": codeql_text.replace("tools/codeql_gate.py codeql-actions-results", "tools/codeql_gate.py codeql-results"),
        "analysis output changed": codeql_text.replace("output: codeql-actions-results", "output: elsewhere"),
        "job allowed to fail": codeql_text.replace("    name: CodeQL (actions, security-extended)\n",
                                                   "    name: CodeQL (actions, security-extended)\n    continue-on-error: true\n"),
        "job conditional": codeql_text.replace("    name: CodeQL (actions, security-extended)\n",
                                               "    name: CodeQL (actions, security-extended)\n    if: false\n"),
        "init allowed to fail": codeql_text.replace("      - uses: github/codeql-action/init@", "      - continue-on-error: true\n        uses: github/codeql-action/init@", 1),
        "push trigger narrowed": codeql_text.replace('  push:\n    branches: ["**"]\n', '  push:\n    branches: ["main"]\n'),
    }.items():
        assert text != codeql_text, label
        assert check_codeql({CODEQL_WORKFLOW: text}), label
    # item 8 round 1: the cross-check step itself is pinned
    with open(".github/workflows/ci.yml", encoding="utf-8") as handle:
        ci_text = handle.read()
    ci = {".github/workflows/ci.yml": ci_text}
    assert check_cross_check(ci) == [], check_cross_check(ci)
    check_line = 'python -B tools/check_workflow_yaml.py | tee -a "$GITHUB_STEP_SUMMARY"'
    cross_name = "      - name: Cross-check the workflow policy parser against PyYAML"
    for label, text in {
        "step removed": ci_text.replace("          " + check_line + "\n", "").replace(
            "          python -B tools/check_workflow_yaml.py --self-test\n", ""),
        "check masked": ci_text.replace(check_line, check_line + " || true"),
        "self-test only": ci_text.replace("          " + check_line + "\n", ""),
        "install dropped": ci_text.replace("          python -m pip install --require-hashes -r requirements-dev.txt > /dev/null\n"
                                           "          python -B tools/check_workflow_yaml.py --self-test", "          python -B tools/check_workflow_yaml.py --self-test"),
        "step conditional": ci_text.replace(cross_name, "      - if: false\n        name: Cross-check the workflow policy parser against PyYAML"),
        "step allowed to fail": ci_text.replace(cross_name, "      - continue-on-error: true\n        name: Cross-check the workflow policy parser against PyYAML"),
        "job allowed to fail": ci_text.replace("    name: workflow lint (actionlint, zizmor)\n",
                                               "    name: workflow lint (actionlint, zizmor)\n    continue-on-error: true\n"),
    }.items():
        assert text != ci_text, label
        assert check_cross_check({".github/workflows/ci.yml": text}), label
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / ".github" / "workflows"
        target.mkdir(parents=True)
        for source in Path(".github/workflows").glob("*.yml"):
            (target / source.name).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            assert main(directory) == 0
        (target / "bypass.yml").write_text(adversarial, encoding="utf-8")
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            assert main(directory) == 1
        assert "bypass.yml:16: `secrets` may only appear as" in captured.getvalue(), captured.getvalue()
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
