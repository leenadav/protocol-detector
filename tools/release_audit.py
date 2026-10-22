"""Scheduled release audit: a detective control that no tag-pushed workflow can bypass.

A tag push runs the workflow file at the tagged commit, so the guarded controller's checks
(publish-release.yml) only bind tags on commits that carry it; an older commit's unguarded
release.yml, or a workflow edited on a branch, can still publish. A scheduled workflow always
runs the default branch's copy, so `release-audit.yml` re-checks every outcome after the fact
and fails (GitHub then notifies the owner) when one does not hold:

  every `v*` tag points at a commit already on main          {"kind": "tag", "tag", "compare"}
  every published release has assets, downloaded intact       {"kind": "release", "tag", "assets", "download"}
  every asset's attestation verifies against the controller   {"kind": "asset", "tag", "asset", "verified"}
    (publish-release.yml, the tag's ref, a GitHub-hosted runner)

The workflow gathers those facts with the read-only token and writes one JSON object per line;
this helper decides. Unreadable or unknown lines fail closed. Standard library only. Usage:
  release_audit.py --facts FILE [--summary FILE]
  release_audit.py --self-test
"""
import json
import sys

ON_MAIN = {"identical", "ahead"}


def audit(text):
    """(problems, counts) for the facts in `text` (JSON lines)."""
    problems, counts = [], {"tag": 0, "release": 0, "asset": 0}
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
        if kind == "tag" and fact.get("compare") not in ON_MAIN:
            problems.append("tag {}: its commit is not on main (compare status {!r})".format(tag, fact.get("compare")))
        elif kind == "release":
            if fact.get("download") != "ok":
                problems.append("release {}: assets could not be downloaded ({!r})".format(tag, fact.get("download")))
            elif not isinstance(fact.get("assets"), int) or fact.get("assets") < 1:
                problems.append("release {}: has no assets to verify".format(tag))
        elif kind == "asset" and fact.get("verified") is not True:
            problems.append("release {}: asset {!r} has no attestation from publish-release.yml for this tag".format(
                tag, fact.get("asset")))
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
    good = "\n".join([fact(kind="tag", tag="v1.0.0", compare="ahead"), fact(kind="tag", tag="v1.0.1", compare="identical"),
                      fact(kind="release", tag="v1.0.0", assets=2, download="ok"),
                      fact(kind="asset", tag="v1.0.0", asset="a.whl", verified=True),
                      fact(kind="asset", tag="v1.0.0", asset="SHA256SUMS", verified=True)])
    assert report(good)[0] == 0, report(good)
    assert report("")[0] == 0 and "0 v* tag(s), 0 release(s)" in report("")[1][0]
    bad = {
        "tag off main": fact(kind="tag", tag="v9", compare="diverged"),
        "tag behind": fact(kind="tag", tag="v9", compare="behind"),
        "compare error": fact(kind="tag", tag="v9", compare="api-error"),
        "release download failed": fact(kind="release", tag="v9", assets=0, download="error"),
        "release without assets": fact(kind="release", tag="v9", assets=0, download="ok"),
        "asset unverified": fact(kind="asset", tag="v9", asset="x.whl", verified=False),
        "asset verified as string": fact(kind="asset", tag="v9", asset="x.whl", verified="true"),
        "unknown kind": fact(kind="other", tag="v9"),
        "missing tag": fact(kind="tag", compare="ahead"),
        "not json": "api-error",
        "not an object": "[]",
    }
    for label, text in bad.items():
        assert report(good + "\n" + text)[0] == 1, label
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
