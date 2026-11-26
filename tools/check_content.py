"""D08 gate: the detection content pack, its release history and the content lock agree.

Since PRO-411 the canonical content is the Go side's: go/internal/content/pack.json, history.json and lock.json,
checked by tools/content_pack.py without the Python engine. That check always runs.

While the frozen Python reference still exists (protocol_engine/content.py and its content_lock.json, until the
Python removal), its own tables, history and lock are also checked against each other, as before. That reference
check is about the Python package only; it never compares the Python tables with the Go pack, which moves on
without it (a batch added with tools/content_pack.py is a Go-only release).

`--update` rewrites protocol_engine/content_lock.json for a new release entry of the Python reference; it refuses
to re-lock content that changed under the same release version, and it needs the reference.
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import content_pack  # noqa: E402

REFERENCE = ROOT / "protocol_engine" / "content.py"


def reference_content():
    """protocol_engine.content while the Python reference exists, else None (PRO-401/PRO-411)."""
    if not REFERENCE.is_file():
        return None
    from protocol_engine import content  # noqa: PLC0415
    return content


def update(content):
    current = content.description()
    try:
        lock = content.read_lock()
    except (OSError, ValueError) as error:
        lock, reason = None, str(error)
    else:
        reason = "it is not an object with a string version and digest and a components object"
    if not (isinstance(lock, dict) and isinstance(lock.get("version"), str) and isinstance(lock.get("digest"), str)
            and isinstance(lock.get("components"), dict)):
        # C11: without the prior lock nothing shows the superseded release's recorded components match it.
        print("refusing to lock release {}: the prior content lock cannot be read ({}); restore content_lock.json "
              "first".format(current["version"], reason))
        return 1
    if lock["version"] == current["version"] and lock["digest"] != current["digest"]:
        print("refusing to re-lock release {}: the content changed; add a new Release to HISTORY first".format(current["version"]))
        return 1
    if lock["version"] != current["version"]:
        # C11: the release being superseded keeps the components it was published with.
        recorded = content._RELEASED_COMPONENTS.get(lock["version"])
        if recorded is None or dict(recorded) != lock["components"]:
            print("refusing to lock release {}: record release {}'s locked components in content._RELEASED_COMPONENTS "
                  "first, exactly as content_lock.json states them".format(current["version"], lock["version"]))
            return 1
    data = content.write_lock()
    print("content lock written: release {} digest {} ({} host entries)".format(data["version"], data["digest"], data["host_entries"]))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--update", action="store_true", help="Write the Python reference's lock for its current release")
    args = parser.parse_args(argv)
    content = reference_content()
    if args.update:
        if content is None:
            print("refusing --update: the Python content reference is removed; add releases with tools/content_pack.py add")
            return 1
        return update(content)
    failed = 0
    problems, tree = content_pack.check(ROOT)
    for problem in problems:
        print("content: " + problem)
    if problems:
        failed = 1
    else:
        print("content ok: {}; {} releases in go/internal/content/lock.json".format(
            content_pack.summary(tree["pack"]), len(tree["lock"]["releases"])))
    if content is None:
        print("python content reference: not present (removed); the Go content above is the source")
        return failed
    problems = content.check()
    for problem in problems:
        print("python content reference: " + problem)
    if problems:
        return 1
    current = content.description()
    print("python content reference ok: release {} ({}, reviewed {}) digest {}; {} releases, {} host entries".format(
        current["version"], current["released"], current["reviewed"], current["digest"], len(content.releases()), current["host_entries"]))
    return failed


if __name__ == "__main__":
    sys.exit(main())
