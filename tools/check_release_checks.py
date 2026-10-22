"""Release checks gate: a `v*` tag may publish only a commit whose CI gate and CodeQL passed.

Required status checks are not enforceable on this repository's plan (SSDLC.md, "Enforced
controls"), and the release build re-runs the test gate but not CodeQL. The release build
job lists the tagged commit's check runs with the read-only `checks: read` token
(`gh api --paginate .../commits/<sha>/check-runs`, one JSON object per line) and passes
them here. For each required check name, only runs that GitHub Actions created for that
exact commit count; the most recently completed one must have succeeded and none may still
be running. A missing, pending, failed or unreadable check fails closed on a tag; branch,
pull-request and manual dry runs only report. Standard library only. Usage:
  check_release_checks.py --ref-type TYPE --sha SHA --runs FILE [--summary FILE]
  check_release_checks.py --self-test
"""
import json
import sys

REQUIRED = ("ci gate (all jobs)", "CodeQL (python, security-extended)")
APP = "github-actions"


def read_runs(text):
    """Check runs from JSON lines; raises ValueError on anything else."""
    runs = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            run = json.loads(line)
        except ValueError as error:
            raise ValueError("line {} is not JSON: {}".format(number, error))
        if not isinstance(run, dict):
            raise ValueError("line {} is not a check run object".format(number))
        runs.append(run)
    return runs


def verdicts(runs, sha):
    """{required name: (ok, reason)}."""
    found = {}
    for name in REQUIRED:
        mine = [run for run in runs if run.get("name") == name and run.get("app") == APP and run.get("head_sha") == sha]
        if not mine:
            found[name] = (False, "no run by {} on this commit".format(APP))
            continue
        if any(run.get("status") != "completed" for run in mine):
            found[name] = (False, "still running")
            continue
        latest = max(mine, key=lambda run: run.get("completed_at") or "")
        conclusion = latest.get("conclusion")
        found[name] = (conclusion == "success", "latest run concluded {}".format(conclusion))
    return found


def decide(ref_type, sha, runs_text):
    """(exit code, [message lines])."""
    try:
        results = verdicts(read_runs(runs_text), sha)
    except ValueError as error:
        results = {name: (False, "check runs unreadable ({})".format(error)) for name in REQUIRED}
    lines = ["  {}: {} ({})".format(name, "ok" if ok else "NOT OK", reason) for name, (ok, reason) in results.items()]
    passed = all(ok for ok, _ in results.values())
    if ref_type != "tag":
        head = "release checks (dry run, {} ref, report only) for {}:".format(ref_type or "unknown", sha)
        return 0, [head] + lines
    if passed:
        return 0, ["release checks: required checks passed on {}:".format(sha)] + lines
    return 1, ["release checks: refusing the tag: required checks have not all passed on {}; wait for them "
               "(or fix them) and re-run this workflow:".format(sha)] + lines


def self_test():
    sha, other = "a" * 40, "b" * 40

    def run(name, conclusion="success", status="completed", app=APP, head=sha, at="2026-10-22T10:00:00Z"):
        return json.dumps({"name": name, "status": status, "conclusion": conclusion, "app": app,
                           "head_sha": head, "completed_at": at if status == "completed" else None})
    ci, codeql = REQUIRED
    green = "\n".join([run(ci), run(codeql), run("tests (python 3.9)")])
    assert decide("tag", sha, green)[0] == 0
    cases = {
        "codeql missing": run(ci),
        "codeql failed": "\n".join([run(ci), run(codeql, "failure")]),
        "codeql running": "\n".join([run(ci), run(codeql, None, "in_progress")]),
        "ci gate cancelled": "\n".join([run(ci, "cancelled"), run(codeql)]),
        "ci gate skipped": "\n".join([run(ci, "skipped"), run(codeql)]),
        "spoofed app": "\n".join([run(ci, app="some-other-app"), run(codeql)]),
        "other commit": "\n".join([run(ci, head=other), run(codeql)]),
        "latest re-run failed": "\n".join([run(ci), run(ci, "failure", at="2026-10-22T11:00:00Z"), run(codeql)]),
        "a re-run still running": "\n".join([run(ci), run(ci, None, "queued"), run(codeql)]),
        "unreadable": "not json",
        "not an object": "[]",
        "empty": "",
    }
    for label, text in cases.items():
        assert decide("tag", sha, text)[0] == 1, label
        code, lines = decide("branch", sha, text)
        assert code == 0 and "report only" in lines[0], label
    # A later successful re-run replaces an earlier failure.
    assert decide("tag", sha, "\n".join([run(ci, "failure"), run(ci, at="2026-10-22T11:00:00Z"), run(codeql)]))[0] == 0
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
