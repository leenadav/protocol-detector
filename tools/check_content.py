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
        try:
            lock = content.read_lock()
        except (OSError, ValueError):
            lock = None
        current = content.description()
        if lock is not None and lock.get("version") == current["version"] and lock.get("digest") != current["digest"]:
            print("refusing to re-lock release {}: the content changed; add a new Release to HISTORY first".format(current["version"]))
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
