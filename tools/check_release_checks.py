"""Release checks gate: a `v*` tag may publish only a commit whose ci and CodeQL workflows passed.

Required status checks are not enforceable on this repository's plan (SSDLC.md, "Enforced
controls"), and the release build re-runs the test gate but not CodeQL. The release-gate
job lists the tagged commit's workflow runs with the read-only `actions: read` token
(`gh api --paginate .../actions/runs?head_sha=<sha>`, one JSON object per line) and passes
them here.

Results are bound to the workflow's identity, not to a job or check name that any other
workflow could reuse: only runs of the workflow file at REQUIRED's path, triggered by a
`push` of that exact commit, count. A push run executes the commit's own copy of the file,
and the `ci` run succeeds only when its `ci gate (all jobs)` job, which needs every other ci
job, succeeds. For each required workflow at least one such run must have completed, and the
most recently updated completed one must have succeeded. A run still shown in progress
neither passes nor blocks (GitHub has been seen to leave a job `in_progress` after its run
completed; a re-run in flight does not undo an earlier success, while a later completed
failure does). A missing, only-pending, failed or unreadable result fails closed on a tag;
branch, pull-request and manual dry runs only report. Standard library only. Usage:
  check_release_checks.py --ref-type TYPE --sha SHA --runs FILE [--summary FILE]
  check_release_checks.py --self-test
"""
import json
import sys

REQUIRED = {
    ".github/workflows/ci.yml": "ci (its `ci gate (all jobs)` covers every ci job)",
    ".github/workflows/codeql.yml": "codeql (CodeQL python, security-extended)",
}
EVENT = "push"


def read_runs(text):
    """Workflow runs from JSON lines; raises ValueError on anything else."""
    runs = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            run = json.loads(line)
        except ValueError as error:
            raise ValueError("line {} is not JSON: {}".format(number, error))
        if not isinstance(run, dict):
            raise ValueError("line {} is not a workflow run object".format(number))
        runs.append(run)
    return runs


def verdicts(runs, sha):
    """{required workflow path: (ok, reason)}."""
    found = {}
    for path in REQUIRED:
        mine = [run for run in runs if run.get("path") == path and run.get("event") == EVENT and run.get("head_sha") == sha]
        if not mine:
            found[path] = (False, "no {} run of this workflow on this commit".format(EVENT))
            continue
        completed = [run for run in mine if run.get("status") == "completed"]
        if not completed:
            found[path] = (False, "still running, no completed run yet")
            continue
        latest = max(completed, key=lambda run: run.get("updated_at") or "")
        conclusion = latest.get("conclusion")
        found[path] = (conclusion == "success", "latest completed run concluded {}".format(conclusion))
    return found


def decide(ref_type, sha, runs_text):
    """(exit code, [message lines])."""
    try:
        results = verdicts(read_runs(runs_text), sha)
    except ValueError as error:
        results = {path: (False, "workflow runs unreadable ({})".format(error)) for path in REQUIRED}
    lines = ["  {} [{}]: {} ({})".format(path, REQUIRED[path], "ok" if ok else "NOT OK", reason)
             for path, (ok, reason) in results.items()]
    passed = all(ok for ok, _ in results.values())
    if ref_type != "tag":
        head = "release checks (dry run, {} ref, report only) for {}:".format(ref_type or "unknown", sha)
        return 0, [head] + lines
    if passed:
        return 0, ["release checks: required workflows passed on {}:".format(sha)] + lines
    return 1, ["release checks: refusing the tag: required workflows have not all passed on {}; wait for them "
               "(or fix them) and re-run this workflow:".format(sha)] + lines


def self_test():
    sha, other = "a" * 40, "b" * 40
    ci, codeql = REQUIRED

    def run(path, conclusion="success", status="completed", event=EVENT, head=sha, at="2026-10-22T10:00:00Z", name=None):
        return json.dumps({"path": path, "name": name or path.rsplit("/", 1)[-1][:-4], "event": event,
                           "status": status, "conclusion": conclusion if status == "completed" else None,
                           "head_sha": head, "updated_at": at})
    green = "\n".join([run(ci), run(codeql), run(".github/workflows/supply-chain-drift.yml")])
    assert decide("tag", sha, green)[0] == 0
    cases = {
        "codeql missing": run(ci),
        "codeql failed": "\n".join([run(ci), run(codeql, "failure")]),
        "codeql only running": "\n".join([run(ci), run(codeql, None, "in_progress")]),
        "ci cancelled": "\n".join([run(ci, "cancelled"), run(codeql)]),
        "ci skipped": "\n".join([run(ci, "skipped"), run(codeql)]),
        # milestone 2 round 1: another workflow on the same commit reusing the names must not count
        "same names, other workflow": "\n".join([run(".github/workflows/ci.yml", "failure"), run(codeql, "failure"),
                                                 run(".github/workflows/impostor.yml", name="ci"),
                                                 run(".github/workflows/impostor-codeql.yml", name="codeql")]),
        "impostor only": "\n".join([run(".github/workflows/impostor.yml", name="ci"), run("dynamic/x/codeql", name="codeql")]),
        "path with prefix": "\n".join([run("x/.github/workflows/ci.yml"), run(codeql)]),
        "pull_request run only": "\n".join([run(ci, event="pull_request"), run(codeql)]),
        "workflow_dispatch run only": "\n".join([run(ci), run(codeql, event="workflow_dispatch")]),
        "other commit": "\n".join([run(ci, head=other), run(codeql)]),
        "latest completed failed": "\n".join([run(ci), run(ci, "failure", at="2026-10-22T11:00:00Z"), run(codeql)]),
        "unreadable": "api-error",
        "not an object": "[]",
        "empty": "",
    }
    for label, text in cases.items():
        assert decide("tag", sha, text)[0] == 1, label
        code, lines = decide("branch", sha, text)
        assert code == 0 and "report only" in lines[0], label
    # A stale or in-flight run beside a completed success does not block (the 6e1cd61 case).
    assert decide("tag", sha, "\n".join([run(ci), run(codeql), run(codeql, None, "in_progress")]))[0] == 0
    # A later successful run replaces an earlier failure; extra runs of other workflows are ignored.
    assert decide("tag", sha, "\n".join([run(ci, "failure"), run(ci, at="2026-10-22T11:00:00Z"), run(codeql),
                                         run(".github/workflows/impostor.yml", "failure", name="ci")]))[0] == 0
    print("check_release_checks self-test: ok")
    return 0


def main(arguments):
    if "--self-test" in arguments:
        return self_test()
    values = {}
    for name in ("--ref-type", "--sha", "--runs"):
        if name not in arguments or arguments.index(name) + 1 >= len(arguments):
            print("usage: check_release_checks.py --ref-type TYPE --sha SHA --runs FILE [--summary FILE]", file=sys.stderr)
            return 2
        values[name] = arguments[arguments.index(name) + 1]
    try:
        with open(values["--runs"], encoding="utf-8") as handle:
            text = handle.read()
    except OSError as error:
        text = "unreadable: {}".format(error)
    code, lines = decide(values["--ref-type"], values["--sha"], text)
    print("\n".join(lines))
    if "--summary" in arguments and arguments.index("--summary") + 1 < len(arguments):
        with open(arguments[arguments.index("--summary") + 1], "a", encoding="utf-8") as summary:
            summary.write("\n".join(lines) + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
