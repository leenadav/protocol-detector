"""D08 gate: the detection content tables, their release history and the content lock agree.

`--update` rewrites protocol_engine/content_lock.json for a new release entry; it refuses to
re-lock content that changed under the same release version.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol_engine import content  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update", action="store_true", help="Write the lock for the current release")
    args = parser.parse_args(argv)
    if args.update:
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
    problems = content.check()
    for problem in problems:
        print("content: " + problem)
    if problems:
        return 1
    current = content.description()
    print("content ok: release {} ({}, reviewed {}) digest {}; {} releases, {} host entries".format(
        current["version"], current["released"], current["reviewed"], current["digest"], len(content.releases()), current["host_entries"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
