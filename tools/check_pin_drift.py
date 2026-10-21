"""Fail when a pinned action SHA no longer matches the tag named in its comment.

Supply-chain drift gate: every `uses: owner/repo@<40-hex sha> # <tag>` line in the
workflows is resolved against the action's repository (`git ls-remote`, peeled
tag objects preferred) and the commit the tag points at today must equal the
pinned SHA. A moved or deleted tag, a pin without a tag comment, or a tag that
no longer exists is a failure: either the pin or the comment is lying.

Usage: check_pin_drift.py [.github/workflows] [--self-test]
"""
import re
import shutil
import subprocess  # noqa: S404  (argv-only git invocation, no shell)
import sys
from pathlib import Path

PIN = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)@([0-9a-f]{40})\s*(?:#\s*(\S+))?")
TAG_REF = re.compile(r"^([0-9a-f]{40})\trefs/tags/([^\s^]+)(\^\{\})?$")


def collect(paths):
    """(file, line number, owner/repo, sha, tag or None) for every SHA-pinned action."""
    pins = []
    for root in paths:
        files = [Path(root)] if Path(root).is_file() else sorted(Path(root).glob("*.yml")) + sorted(Path(root).glob("*.yaml"))
        for path in files:
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                match = PIN.match(line)
                if not match or match.group(1).startswith(("./", "docker://")):
                    continue
                repository = "/".join(match.group(1).split("/")[:2])
                pins.append((str(path), number, repository, match.group(2), match.group(3)))
    return pins


def resolve_tags(repository):
    """{tag: commit sha} for every tag of the repository, peeled when annotated."""
    url = "https://github.com/{}.git".format(repository)
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is not installed")
    result = subprocess.run([git, "ls-remote", "--tags", url], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError("git ls-remote {} failed: {}".format(url, result.stderr.strip()[:200]))
    tags = {}
    for line in result.stdout.splitlines():
        match = TAG_REF.match(line)
        if not match:
            continue
        sha, tag, peeled = match.groups()
        if peeled or tag not in tags:
            tags[tag] = sha
    return tags


def check(pins, resolver):
    """Return (failures, checked) where failures is a list of messages."""
    failures = []
    cache = {}
    for path, number, repository, sha, tag in pins:
        where = "{}:{}".format(path, number)
        if not tag:
            failures.append("{}: {}@{} has no tag comment to verify against".format(where, repository, sha[:12]))
            continue
        if repository not in cache:
            try:
                cache[repository] = resolver(repository)
            except RuntimeError as error:
                cache[repository] = error
        tags = cache[repository]
        if isinstance(tags, RuntimeError):
            failures.append("{}: {}".format(where, tags))
            continue
        actual = tags.get(tag)
        if actual is None:
            failures.append("{}: {} has no tag {} (pinned {})".format(where, repository, tag, sha[:12]))
        elif actual != sha:
            failures.append("{}: {}@{} is pinned to {} but the tag now points at {}".format(where, repository, tag, sha[:12], actual[:12]))
    return failures, len(pins)


def self_test():
    """Offline check of the parser and the comparison; no network."""
    text = "\n".join([
        "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2",
        "        uses: github/codeql-action/init@ff0a06e83cb2de871e5a09832bc6a81e7276941f # v3.28.18",
        "      - uses: ./local/action",
        "      - uses: octo/moved@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa # v1.0.0",
        "      - uses: octo/nocomment@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "      - uses: octo/gone@cccccccccccccccccccccccccccccccccccccccc # v9",
        "      - uses: octo/offline@dddddddddddddddddddddddddddddddddddddddd # v1",
    ])
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as handle:
        handle.write(text)
    pins = collect([handle.name])
    Path(handle.name).unlink()
    assert [(p[2], p[4]) for p in pins] == [("actions/checkout", "v4.2.2"), ("github/codeql-action", "v3.28.18"), ("octo/moved", "v1.0.0"),
                                            ("octo/nocomment", None), ("octo/gone", "v9"), ("octo/offline", "v1")], pins
    tables = {"actions/checkout": {"v4.2.2": "11bd71901bbe5b1630ceea73d27597364c9af683"},
              "github/codeql-action": {"v3.28.18": "ff0a06e83cb2de871e5a09832bc6a81e7276941f"},
              "octo/moved": {"v1.0.0": "e" * 40}, "octo/gone": {}}

    def resolver(repository):
        if repository == "octo/offline":
            raise RuntimeError("git ls-remote failed: offline")
        return tables[repository]

    failures, checked = check(pins, resolver)
    assert checked == 6, checked
    assert len(failures) == 4 and "octo/moved@v1.0.0 is pinned to aaaaaaaaaaaa but the tag now points at eeeeeeeeeeee" in failures[0], failures
    assert "no tag comment" in failures[1] and "no tag v9" in failures[2] and "offline" in failures[3], failures
    peeled = "\n".join(["1111111111111111111111111111111111111111\trefs/tags/v1", "2222222222222222222222222222222222222222\trefs/tags/v1^{}",
                        "3333333333333333333333333333333333333333\trefs/tags/v2"])
    tags = {}
    for line in peeled.splitlines():
        sha, tag, peel = TAG_REF.match(line).groups()
        if peel or tag not in tags:
            tags[tag] = sha
    assert tags == {"v1": "2" * 40, "v2": "3" * 40}, tags
    print("check_pin_drift self-test: ok")
    return 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
    pins = collect(argv or [".github/workflows"])
    failures, checked = check(pins, resolve_tags)
    for failure in failures:
        print(failure)
    repositories = sorted({repository for _, _, repository, _, _ in pins})
    print("action pin drift: {} pins over {} repositories checked, {}".format(checked, len(repositories), "no drift" if not failures else "{} problem(s)".format(len(failures))))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
