"""Scheduled release audit: a detective control that no tag-pushed workflow can bypass.

A tag push runs the workflow file at the tagged commit, so the guarded controller's checks
(publish-release.yml) only bind tags on commits that carry it; an older commit's unguarded
release.yml, or a workflow edited on a branch, can still publish. A scheduled workflow always
runs the default branch's copy, so `release-audit.yml` re-checks every outcome after the fact
and fails (GitHub then notifies the owner) when one does not hold:

  every `v*` tag points at a commit already on main          {"kind": "tag", "tag", "compare", "commit"}
  every published release names an extant v* tag whose commit {"kind": "release", "tag", "commit", "assets",
    is the release's, and has assets downloaded intact          "download"}
  every downloaded file, hidden ones included, has its own   {"kind": "asset", "tag", "asset", "verified"}
    attestation verified against the controller
    (publish-release.yml, the tag's ref and commit, a GitHub-hosted runner)

The workflow gathers those facts with the read-only token and writes one JSON object per line;
this helper decides. Unreadable or unknown lines fail closed. Standard library only. Usage:
  release_audit.py --facts FILE [--summary FILE]
  release_audit.py --self-test
"""
import json
import re
import sys


ON_MAIN = {"identical", "ahead"}
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def audit(text):
    """(problems, counts) for the facts in `text` (JSON lines)."""
    problems, counts = [], {"tag": 0, "release": 0, "asset": 0}
    tags, releases, assets = {}, [], {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            fact = json.loads(line)
        except ValueError:
            problems.append("line {}: not JSON: {!r}".format(number, line[:80]))
            continue
        kind = fact.get("kind") if isinstance(fact, dict) else None
        tag = fact.get("tag") if isinstance(fact, dict) else None
        if kind not in counts or not isinstance(tag, str) or not tag:
            problems.append("line {}: unreadable fact {!r}".format(number, line[:80]))
            continue
        counts[kind] += 1
        if kind == "tag":
            tags[tag] = fact
            if fact.get("compare") not in ON_MAIN:
                problems.append("tag {}: its commit is not on main (compare status {!r})".format(tag, fact.get("compare")))
            if not COMMIT.match(str(fact.get("commit"))):
                problems.append("tag {}: its commit could not be resolved ({!r})".format(tag, fact.get("commit")))
        elif kind == "release":
            releases.append(fact)
        else:
            assets.setdefault(tag, []).append(fact)
            if fact.get("verified") is not True:
                problems.append("release {}: asset {!r} has no attestation from publish-release.yml for this tag and "
                                "commit".format(tag, fact.get("asset")))
    for release in releases:
        tag = release["tag"]
        # milestone 7 round 1: a release must be bound to a current, on-main v* tag and its commit
        if not tag.startswith("v"):
            problems.append("release {}: its tag is outside v*, so no tag-bound check covers it".format(tag))
        elif tag not in tags:
            problems.append("release {}: its tag no longer exists among the v* tags".format(tag))
        elif release.get("commit") != tags[tag].get("commit") or not COMMIT.match(str(release.get("commit"))):
            problems.append("release {}: its commit {!r} is not the tag's commit {!r}".format(
                tag, release.get("commit"), tags[tag].get("commit")))
        if release.get("download") != "ok":
            problems.append("release {}: assets could not be downloaded ({!r})".format(tag, release.get("download")))
        elif not isinstance(release.get("assets"), int) or release.get("assets") < 1:
            problems.append("release {}: has no assets to verify".format(tag))
        elif len(assets.get(tag, [])) != release.get("assets"):
            problems.append("release {}: {} file(s) downloaded but {} verified (every file, hidden ones included, "
                            "must be checked)".format(tag, release.get("assets"), len(assets.get(tag, []))))
    for tag in assets:
        if not any(release["tag"] == tag for release in releases):
            problems.append("asset facts for {} have no release fact".format(tag))
    return problems, counts


def report(text):
    problems, counts = audit(text)
    head = "release audit: {} v* tag(s), {} release(s), {} asset(s) checked".format(counts["tag"], counts["release"], counts["asset"])
    lines = [head] + ["  NOT OK: " + problem for problem in problems]
    lines.append("release audit: " + ("FAILED" if problems else "ok"))
    return (1 if problems else 0), lines


def self_test():
    def fact(**fields):
        return json.dumps(fields)
    a, b = "a" * 40, "b" * 40
    tag = fact(kind="tag", tag="v1.0.0", compare="ahead", commit=a)
    release = fact(kind="release", tag="v1.0.0", commit=a, assets=2, download="ok")
    whl = fact(kind="asset", tag="v1.0.0", asset="a.whl", verified=True)
    sums = fact(kind="asset", tag="v1.0.0", asset="SHA256SUMS", verified=True)
    good = "\n".join([tag, fact(kind="tag", tag="v1.0.1", compare="identical", commit=b), release, whl, sums])
    assert report(good)[0] == 0, report(good)
    assert report("")[0] == 0 and "0 v* tag(s), 0 release(s)" in report("")[1][0]
    bad = {
        "tag off main": good + "\n" + fact(kind="tag", tag="v9", compare="diverged", commit=b),
        "tag behind": good + "\n" + fact(kind="tag", tag="v9", compare="behind", commit=b),
        "compare error": good + "\n" + fact(kind="tag", tag="v9", compare="api-error", commit=b),
        "tag commit unresolved": good + "\n" + fact(kind="tag", tag="v9", compare="ahead", commit="api-error"),
        "release download failed": good.replace('"download": "ok"', '"download": "error"'),
        "release without assets": "\n".join([tag, fact(kind="release", tag="v1.0.0", commit=a, assets=0, download="ok")]),
        "asset unverified": good.replace('"asset": "a.whl", "verified": true', '"asset": "a.whl", "verified": false'),
        "asset verified as string": good.replace('"asset": "a.whl", "verified": true', '"asset": "a.whl", "verified": "true"'),
        # milestone 7 round 1, finding 1: releases bound to an extant, on-main v* tag and its commit
        "release outside v*": "\n".join([tag, release, whl, sums, fact(kind="release", tag="nightly", commit=a, assets=1, download="ok"),
                                          fact(kind="asset", tag="nightly", asset="x", verified=True)]),
        "tag deleted": "\n".join([release, whl, sums]),
        "tag moved": "\n".join([fact(kind="tag", tag="v1.0.0", compare="ahead", commit=b), release, whl, sums]),
        "release commit unresolved": good.replace('"commit": "{}", "assets"'.format(a), '"commit": "api-error", "assets"'),
        "tag off main for a release": "\n".join([fact(kind="tag", tag="v1.0.0", compare="diverged", commit=a), release, whl, sums]),
        # milestone 7 round 1, finding 2: every downloaded file must have its own asset fact
        "hidden asset unverified": "\n".join([tag, release, whl]),
        "more files than facts": good.replace('"assets": 2', '"assets": 3'),
        "orphan asset facts": good + "\n" + fact(kind="asset", tag="v7", asset="x", verified=True),
        "unknown kind": good + "\n" + fact(kind="other", tag="v9"),
        "missing tag": good + "\n" + fact(kind="tag", compare="ahead"),
        "not json": good + "\napi-error",
        "not an object": good + "\n[]",
    }
    for label, text in bad.items():
        assert text != good, label
        assert report(text)[0] == 1, (label, report(text))
    print("release_audit self-test: ok")
    return 0


def main(arguments):
    if "--self-test" in arguments:
        return self_test()
    if "--facts" not in arguments or arguments.index("--facts") + 1 >= len(arguments):
        print("usage: release_audit.py --facts FILE [--summary FILE]", file=sys.stderr)
        return 2
    try:
        with open(arguments[arguments.index("--facts") + 1], encoding="utf-8") as handle:
            text = handle.read()
    except OSError as error:
        text = "unreadable facts file: {}".format(error)
    code, lines = report(text)
    print("\n".join(lines))
    if "--summary" in arguments and arguments.index("--summary") + 1 < len(arguments):
        with open(arguments[arguments.index("--summary") + 1], "a", encoding="utf-8") as summary:
            summary.write("\n".join(lines) + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
