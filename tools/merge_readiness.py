"""Daily merge-readiness report (merge-readiness.yml): would the Go migration merge into main cleanly?

A trial merge inside the runner, nothing else: `git merge-tree --write-tree` (git 2.38+) computes the merge of
two commits without a working tree, an index or a ref, and lists the files that conflict. Its only side
effect is new objects in the local object database, which the runner discards. The tool never checks out,
commits, pushes, comments or opens anything, and the workflow holds `contents: read` only.

The report (job summary and stdout) names both commits, their merge base, how many commits each side is
ahead, and either "clean" with the number of files the merge would bring in, or "conflicting" with every
conflicting file. A conflict is the report's subject, not a failure of the job: it is raised as a warning
annotation and the job passes, so a long-lived branch does not mail a red run every day. A missing branch, a
git older than 2.38 or a failing git command exits 2.

Refs are full names only (`refs/remotes/origin/main`, `refs/heads/x`) or a 40-hex commit: git resolves a
short name such as `origin/main` through refs/tags/ before refs/remotes/, so a tag named `origin/main`
would silently replace the branch (SEC-CI-1, policy rule 17).

    merge_readiness.py [--base REF] [--head REF] [--summary FILE]
    merge_readiness.py --self-test
Standard library only; Python 3.9 syntax.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

BASE = "refs/remotes/origin/main"
HEAD = "refs/remotes/origin/claude/go-migration"
REF = re.compile(r"^(?:refs/[A-Za-z0-9][A-Za-z0-9._/-]{0,194}|[0-9a-f]{40})$")


class GitError(RuntimeError):
    pass


def git(args, cwd=None, ok=(0,)):
    result = subprocess.run(["git"] + args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,  # noqa: S603,S607
                            check=False)
    if result.returncode not in ok:
        raise GitError("git {} failed ({}): {}".format(" ".join(args), result.returncode,
                                                         result.stderr.decode("utf-8", "replace").strip()[:300]))
    return result.returncode, result.stdout.decode("utf-8", "replace")


def git_version(cwd=None):
    _, out = git(["version"], cwd)
    match = re.search(r"(\d+)\.(\d+)", out)
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def resolve(ref, cwd=None):
    if not REF.match(ref) or ".." in ref:
        raise GitError("{!r} is not a full ref name (refs/...) or a commit SHA".format(ref))
    code, out = git(["rev-parse", "--verify", "--quiet", ref + "^{commit}"], cwd, ok=(0, 1))
    if code != 0:
        raise GitError("{} does not exist in this clone (fetch it first)".format(ref))
    return out.strip()


def assess(base, head, cwd=None):
    """{"base", "head", "merge_base", "behind", "ahead", "clean", "conflicts", "changed"} for merging head into base."""
    if git_version(cwd) < (2, 38):
        raise GitError("git 2.38 or newer is needed for `merge-tree --write-tree`")
    base_sha, head_sha = resolve(base, cwd), resolve(head, cwd)
    _, merge_base = git(["merge-base", base_sha, head_sha], cwd)
    _, counts = git(["rev-list", "--left-right", "--count", "{}...{}".format(base_sha, head_sha)], cwd)
    behind, ahead = (int(part) for part in counts.split())
    code, out = git(["merge-tree", "--write-tree", "--name-only", "--no-messages", base_sha, head_sha], cwd, ok=(0, 1))
    lines = [line for line in out.splitlines()[1:] if line.strip()]
    _, changed = git(["diff", "--name-only", "{}...{}".format(base_sha, head_sha)], cwd)
    return {"base": base_sha, "head": head_sha, "merge_base": merge_base.strip(), "behind": behind, "ahead": ahead,
            "clean": code == 0, "conflicts": sorted(set(lines)) if code == 1 else [],
            "changed": len([line for line in changed.splitlines() if line.strip()])}


def report_lines(base, head, result):
    lines = ["### Merge readiness: {} into {}".format(head, base), "",
             "| | commit |", "|---|---|",
             "| {} | `{}` |".format(base, result["base"]), "| {} | `{}` |".format(head, result["head"]),
             "| merge base | `{}` |".format(result["merge_base"]), "",
             "{} is {} commit(s) ahead of and {} behind {}; the merge would bring in {} changed file(s).".format(
                 head, result["ahead"], result["behind"], base, result["changed"]), ""]
    if result["clean"]:
        lines.append("**Clean**: the trial merge has no conflict.")
    else:
        lines.append("**Conflicting**: {} file(s) conflict in the trial merge:".format(len(result["conflicts"])))
        lines += [""] + ["- `{}`".format(name) for name in result["conflicts"]]
    lines += ["", "Trial merge only (`git merge-tree --write-tree`): nothing was checked out, committed or pushed."]
    return lines


def run(base, head, summary):
    try:
        result = assess(base, head)
    except GitError as error:
        print("merge readiness: error: {}".format(error))
        return 2
    lines = report_lines(base, head, result)
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    if not result["clean"]:
        print("::warning title=merge readiness::{} conflicts with {} in {} file(s): {}".format(
            head, base, len(result["conflicts"]), ", ".join(result["conflicts"][:20])))
    return 0


def self_test():
    if git_version() < (2, 38):
        print("merge_readiness self-test: skipped (git older than 2.38)")
        return 0
    root = tempfile.mkdtemp(prefix="merge_readiness_selftest_")
    try:
        env_args = ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"]

        def commit(message, files):
            for name, text in files.items():
                path = os.path.join(root, name)
                os.makedirs(os.path.dirname(path) or root, exist_ok=True)
                with open(path, "w", encoding="utf-8") as stream:
                    stream.write(text)
            git(["add", "-A"], root)
            git(env_args + ["commit", "-q", "-m", message], root)

        git(["init", "-q", "-b", "main"], root)
        commit("base", {"a.txt": "one\n", "b.txt": "two\n"})
        git(["branch", "clean"], root)
        git(["branch", "conflict"], root)
        commit("main side", {"a.txt": "main\n"})
        git(["checkout", "-q", "clean"], root)
        commit("clean side", {"c.txt": "new\n", "b.txt": "two\nmore\n"})
        git(["checkout", "-q", "conflict"], root)
        commit("conflicting side", {"a.txt": "branch\n", "d/e.txt": "x\n"})
        git(["checkout", "-q", "main"], root)
        git(["tag", "clean", "HEAD"], root)          # a tag spelled like the branch must not replace it
        before = git(["for-each-ref"], root)[1], git(["status", "--porcelain"], root)[1], git(["rev-parse", "HEAD"], root)[1]
        clean = assess("refs/heads/main", "refs/heads/clean", root)
        assert clean["clean"] and clean["conflicts"] == [] and (clean["ahead"], clean["behind"]) == (1, 1), clean
        assert clean["changed"] == 2, clean
        assert clean["head"] == git(["rev-parse", "refs/heads/clean"], root)[1].strip() != clean["base"], clean
        conflicting = assess("refs/heads/main", "refs/heads/conflict", root)
        assert not conflicting["clean"] and conflicting["conflicts"] == ["a.txt"], conflicting
        assert "**Conflicting**: 1 file(s)" in "\n".join(report_lines("main", "conflict", conflicting))
        assert "**Clean**" in "\n".join(report_lines("main", "clean", clean))
        after = git(["for-each-ref"], root)[1], git(["status", "--porcelain"], root)[1], git(["rev-parse", "HEAD"], root)[1]
        assert before == after, "the trial merge changed a ref, the index or the working tree"
        bad_refs = ("refs/heads/missing-branch", "refs/heads/main..refs/heads/clean", "-oops", "refs/heads/a b",
                    "clean", "main", "origin/main", "deadbeef")
        for bad in bad_refs:
            try:
                assess("refs/heads/main", bad, root)
            except GitError:
                continue
            raise AssertionError("{!r} was accepted".format(bad))
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print("merge_readiness self-test: ok (clean, conflicting, refs untouched, a same-named tag ignored, {} bad refs refused)".format(len(bad_refs)))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", default=BASE)
    parser.add_argument("--head", default=HEAD)
    parser.add_argument("--summary", help="append a markdown summary here (GITHUB_STEP_SUMMARY)")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    return self_test() if args.self_test else run(args.base, args.head, args.summary)


if __name__ == "__main__":
    sys.exit(main())
