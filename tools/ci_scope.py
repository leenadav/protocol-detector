"""Docs-only fast path for the heavy Go ci jobs (PRO-202 step 3): decide, from git alone, whether a pull
request changes nothing those jobs read.

A commit that touches only Markdown or research data used to re-run the ten-minute Go gate. ci.yml may not
skip a job with `if:` (workflow policy rule 13: the gate would see it skipped), so the job still runs and
reports success, and this tool decides whether its checks have anything to look at. The decision fails
closed: anything it cannot prove means the full job runs.

    ci_scope.py [--explain]   print the decision for this checkout (exit 0 either way)
    ci_scope.py --self-test

Imported by tools/go_ci.py (`go` and `minimum` modes) and tools/go_deep.py (`determinism`) behind their
`--docs-only-fast-path` flag, which only the ci.yml Go jobs pass.

Decision, in order (every "full" means the job runs all of its checks):
- the event is not `pull_request` (GITHUB_EVENT_NAME): full. A push to `main`, the weekly schedule and a
  dispatched run always check everything, so every `main` commit keeps a complete gate result;
- HEAD is not a two-parent merge commit (the `refs/pull/N/merge` commit GitHub builds for a pull request;
  the job's checkout needs `fetch-depth: 2` to hold both parents): full;
- `git diff --name-only --no-renames -z HEAD^1 HEAD` (the change the merge makes to the base, renames
  listed as a deletion and an addition, so both paths count) fails or is empty: full;
- any changed path is outside DOCS_ONLY: full;
- otherwise docs-only, and the job's summary lists every changed path.
DOCS_ONLY is `*.md` anywhere, plus `research/` outside `research/tools/`. Nothing the Go jobs run reads
either: the Go engine embeds only go/internal/content's JSON, and the parity, fuzz and race targets read
go/, migration/, protocol_engine/, tools/ and the Makefile. A change to this tool, a workflow or the
Makefile is never docs-only, so a pull request cannot widen DOCS_ONLY and use it in the same run.
The Python test, documentation, security and supply-chain jobs do not use this path; they run in full on
every change. Standard library only; Python 3.9 syntax.
"""
import argparse
import os
import subprocess  # noqa: S404 - fixed git argv, no shell
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def docs_only_path(path):
    """True for a path no heavy Go job reads: Markdown anywhere, research data outside research/tools/."""
    if not path or path.startswith("/") or "\\" in path or any(part in ("", ".", "..") for part in path.split("/")):
        return False
    if path.endswith(".md"):
        return True
    return path.startswith("research/") and not path.startswith("research/tools/")


def git(args, root):
    """git's stdout, or None when it fails."""
    result = subprocess.run(["git", "-C", str(root)] + args, capture_output=True, check=False)  # noqa: S603, S607
    return result.stdout.decode("utf-8", "surrogateescape") if result.returncode == 0 else None


def changed_paths(root):
    """(paths, reason): the paths the pull request merge commit changes, or (None, why not)."""
    parents = git(["rev-list", "--parents", "-n", "1", "HEAD"], root)
    if parents is None or len(parents.split()) != 3:
        return None, "HEAD is not the two-parent pull request merge commit (checkout needs fetch-depth: 2)"
    diff = git(["diff", "--name-only", "--no-renames", "-z", "HEAD^1", "HEAD"], root)
    if diff is None:
        return None, "git diff against the base parent failed"
    paths = [path for path in diff.split("\0") if path]
    if not paths:
        return None, "the merge commit changes no path"
    return paths, ""


def decide(env=None, root=ROOT, paths_of=changed_paths):
    """(docs_only, reason, paths). docs_only is True only when every check above passes."""
    env = os.environ if env is None else env
    event = env.get("GITHUB_EVENT_NAME", "")
    if event != "pull_request":
        return False, "event `{}` is not pull_request: every check runs".format(event or "none"), []
    paths, why = paths_of(root)
    if paths is None:
        return False, why + ": every check runs", []
    others = [path for path in paths if not docs_only_path(path)]
    if others:
        return False, "{} of {} changed paths are not docs-only (first: {}): every check runs".format(
            len(others), len(paths), others[0]), paths
    return True, "docs-only pull request: all {} changed paths are Markdown or research data".format(len(paths)), paths


def summary_lines(title, reason, paths, limit=40):
    """The job summary for a docs-only skip: the decision and every changed path (up to limit)."""
    lines = [title, "", "{}. This job's checks read none of them, so there is nothing to check; the push to "
                        "`main` after the merge runs them in full (tools/ci_scope.py).".format(reason), ""]
    lines += ["- `{}`".format(path) for path in paths[:limit]]
    if len(paths) > limit:
        lines.append("- ... and {} more".format(len(paths) - limit))
    return lines


def self_test():
    for path in ("README.md", "migration/STATUS.md", "docs/LANE-BRIEF-platform.md", "go/oracle/README.md",
                 "research/live-results-2026-11-20.tsv", "research/apps/zoom.md", "research/app-domains.json"):
        assert docs_only_path(path), path
    for path in ("tools/ci_scope.py", "research/tools/rank_domains.py", "research/tools/README.txt", "Makefile",
                 ".github/workflows/ci.yml", "go/main.go", "go/internal/content/pack.json", "README.md.go",
                 "migration/fixtures/cases.json", "research", "research/../go/x.go", "/README.md", "",
                 "docs/./x.md", "docs//x.md", "docs\\x.md"):
        assert not docs_only_path(path), path
    pr = {"GITHUB_EVENT_NAME": "pull_request"}
    docs = lambda root: (["migration/STATUS.md", "research/live-hosts.txt"], "")  # noqa: E731
    assert decide(pr, paths_of=docs)[0] is True
    for event in ("push", "schedule", "workflow_dispatch", ""):
        assert decide({"GITHUB_EVENT_NAME": event}, paths_of=docs)[0] is False, event
    assert decide({}, paths_of=docs)[0] is False
    mixed = lambda root: (["migration/STATUS.md", "go/main.go"], "")  # noqa: E731
    assert decide(pr, paths_of=mixed)[:2] == (False, "1 of 2 changed paths are not docs-only (first: go/main.go): every check runs")
    assert decide(pr, paths_of=lambda root: (None, "no merge"))[0] is False
    # git itself: a real two-parent merge, a single-parent commit, and a rename out of docs
    import shutil
    import tempfile
    root = Path(tempfile.mkdtemp())
    try:
        def run(*args):
            subprocess.run(["git", "-C", str(root)] + list(args), check=True, capture_output=True)  # noqa: S603, S607
        run("init", "-q", "-b", "base")
        run("config", "user.email", "ci@example.invalid")
        run("config", "user.name", "ci")
        (root / "go").mkdir()
        (root / "go" / "main.go").write_text("package main\n", encoding="utf-8")
        (root / "notes.md").write_text("a\n", encoding="utf-8")
        run("add", ".")
        run("commit", "-q", "-m", "base")
        assert changed_paths(root)[0] is None                            # one parent: full
        run("checkout", "-q", "-b", "head")
        (root / "notes.md").write_text("b\n", encoding="utf-8")
        run("commit", "-q", "-am", "docs")
        run("checkout", "-q", "base")
        run("merge", "-q", "--no-ff", "-m", "merge", "head")
        assert changed_paths(root) == (["notes.md"], "")
        assert decide(pr, root)[0] is True
        run("checkout", "-q", "head")
        run("mv", "go/main.go", "go/main.md")                            # a rename out of go/ lists go/main.go
        run("commit", "-q", "-m", "rename")
        run("checkout", "-q", "base")
        run("merge", "-q", "--no-ff", "-m", "merge 2", "head")
        assert sorted(changed_paths(root)[0]) == ["go/main.go", "go/main.md"]
        assert decide(pr, root)[0] is False
    finally:
        shutil.rmtree(str(root), ignore_errors=True)
    lines = summary_lines("### t", "r", ["a.md"] * 3, limit=2)
    assert lines[-1] == "- ... and 1 more" and lines[-2] == "- `a.md`"
    print("ci_scope self-test: ok")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--explain", action="store_true", help="print the decision for this checkout")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    docs_only, reason, paths = decide()
    print("ci_scope: {}".format(reason))
    if args.explain:
        for path in paths:
            print("  " + path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
