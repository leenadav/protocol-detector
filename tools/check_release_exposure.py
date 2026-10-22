"""Which workflows would a `v*` tag on a given commit run, and could any of them publish unguarded?

A tag push runs the workflow files found at the tagged commit, not the default branch's. So
the release provenance check in `publish-release.yml` protects only commits that carry it;
every older commit still holds the unguarded `.github/workflows/release.yml`, which publishes
a matching tag. This tool models a tag on any commit without creating one: it reads the
workflow files at that commit (`git show`), lists those a tag push would trigger, and reports
each as exposed unless it is the guarded controller passing policy rules 3 and 4, or its path
is named with `--disabled` (disabled in the repository's Actions settings, which applies to
the workflow at that path on every ref).

Usage:
  check_release_exposure.py --ref COMMIT [--disabled .github/workflows/release.yml ...]
  check_release_exposure.py --self-test
Exit 1 when a tag on COMMIT could publish through an unguarded workflow.
"""
import shutil
import subprocess  # noqa: S404  (argv-only git invocation, no shell)
import sys

import check_workflow_policy as policy

WORKFLOWS = ".github/workflows/"


def exposure(workflows, disabled=()):
    """[(path, reason)] for every workflow a tag push would run that is not guarded or disabled."""
    exposed = []
    for path, text in sorted(workflows.items()):
        try:
            triggered = policy.tag_trigger(text)
        except ValueError as error:
            exposed.append((path, "cannot read its triggers ({}); assumed to run on tags".format(error)))
            continue
        if not triggered or path in disabled:
            continue
        if path != policy.RELEASE_WORKFLOW:
            exposed.append((path, "runs on tag pushes outside the guarded controller"))
            continue
        try:
            problems = policy.check_release_concurrency(text) + policy.check_release_provenance(text)
        except ValueError as error:
            problems = [str(error)]
        if problems:
            exposed.append((path, "guarded controller fails policy: " + "; ".join(problems)))
    return exposed


def workflows_at(ref):
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is not installed")

    def run(*arguments):
        result = subprocess.run([git, *arguments], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, text=True, check=False)
        if result.returncode != 0:
            raise RuntimeError("git {} failed: {}".format(" ".join(arguments), result.stderr.strip()))
        return result.stdout

    names = [name for name in run("ls-tree", "--name-only", ref, WORKFLOWS).splitlines()
             if name.endswith((".yml", ".yaml"))]
    return {name: run("show", "{}:{}".format(ref, name)) for name in names}


PRE_GUARD = """name: release
on:
  push:
    tags: ["v*"]
    branches: ["**"]
    paths:
      - ".github/workflows/release.yml"
jobs:
  build:
    runs-on: x
    steps:
      - run: python -m build
  publish:
    if: github.event_name == 'push' && github.ref_type == 'tag'
    needs: build
    permissions:
      contents: write
    steps:
      - run: gh release create "$TAG" dist/*
"""


def self_test():
    with open(policy.RELEASE_WORKFLOW, encoding="utf-8") as handle:
        guarded = handle.read()
    ci = "name: ci\non:\n  push:\n    branches: [\"**\"]\njobs:\n  a:\n    runs-on: x\n"
    legacy = policy.LEGACY_RELEASE
    # A tag on a pre-guard commit (such as 6e1cd61 or main 214042f) runs the legacy workflow.
    assert exposure({legacy: PRE_GUARD, ".github/workflows/ci.yml": ci}) == [
        (legacy, "runs on tag pushes outside the guarded controller")]
    assert exposure({legacy: PRE_GUARD}, disabled={legacy}) == []
    # The milestone-1 round-1/round-2 heads kept the guard at the legacy path: still exposed until disabled.
    assert exposure({legacy: guarded})[0][0] == legacy
    assert exposure({legacy: guarded}, disabled={legacy}) == []
    # A commit carrying the guarded controller is not exposed; a weakened copy is.
    assert exposure({policy.RELEASE_WORKFLOW: guarded, ".github/workflows/ci.yml": ci}) == []
    weakened = guarded.replace("    if: github.event_name == 'push' && github.ref_type == 'tag'",
                               "    if: success() || github.ref_type == 'tag'")
    assert weakened != guarded
    found = exposure({policy.RELEASE_WORKFLOW: weakened})
    assert len(found) == 1 and "fails policy" in found[0][1], found
    # Disabling the controller's own path would also silence it, which is why rule 5 keeps the paths apart.
    assert exposure({policy.RELEASE_WORKFLOW: weakened}, disabled={policy.RELEASE_WORKFLOW}) == []
    print("check_release_exposure self-test: ok")
    return 0


def main(arguments):
    if "--self-test" in arguments:
        return self_test()
    if "--ref" not in arguments or arguments.index("--ref") + 1 >= len(arguments):
        print("usage: check_release_exposure.py --ref COMMIT [--disabled PATH ...]", file=sys.stderr)
        return 2
    ref = arguments[arguments.index("--ref") + 1]
    disabled = {arguments[i + 1] for i, value in enumerate(arguments[:-1]) if value == "--disabled"}
    found = exposure(workflows_at(ref), disabled)
    for path, reason in found:
        print("release exposure at {}: {}: {}".format(ref, path, reason))
    print("release exposure at {}: {}".format(ref, "exposed" if found else "no unguarded tag-publish path"
                                              + (" (disabled: {})".format(", ".join(sorted(disabled))) if disabled else "")))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
