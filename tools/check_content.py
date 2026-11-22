"""D08 gate: the detection content tables, their release history and the content lock agree.

`--update` rewrites protocol_engine/content_lock.json for a new release entry; it refuses to
re-lock content that changed under the same release version. It fails closed when the existing lock
is missing, unreadable or malformed, because the C11 predecessor comparison needs it; only
`--update --bootstrap`, and only when no lock file exists, writes a first lock.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol_engine import content  # noqa: E402


def _well_formed(lock):
    return (isinstance(lock, dict) and isinstance(lock.get("version"), str) and isinstance(lock.get("digest"), str)
            and isinstance(lock.get("components"), dict))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update", action="store_true", help="Write the lock for the current release")
    parser.add_argument("--bootstrap", action="store_true",
                        help="With --update: write a first lock when no lock file exists")
    args = parser.parse_args(argv)
    if args.bootstrap and not args.update:
        parser.error("--bootstrap needs --update")
    if args.update:
        try:
            lock = content.read_lock()
        except FileNotFoundError:
            lock = None
            if not args.bootstrap:
                print("refusing to lock release {}: there is no content lock to compare the predecessor with; "
                      "pass --bootstrap only for a first lock".format(content.description()["version"]))
                return 1
        except (OSError, ValueError):
            print("refusing to lock: the content lock cannot be read; restore it from version control first")
            return 1
        if lock is not None and args.bootstrap:
            print("refusing to bootstrap: a content lock already exists")
            return 1
        if lock is not None and not _well_formed(lock):
            print("refusing to lock: the content lock is malformed (it needs a string version and digest and a "
                  "components object); restore it from version control first")
            return 1
        current = content.description()
        if lock is not None and lock.get("version") == current["version"] and lock.get("digest") != current["digest"]:
            print("refusing to re-lock release {}: the content changed; add a new Release to HISTORY first".format(current["version"]))
            return 1
        if lock is not None and lock.get("version") != current["version"]:
            # C11: the release being superseded keeps the components it was published with.
            recorded = content._RELEASED_COMPONENTS.get(lock.get("version"))
            if recorded is None or dict(recorded) != lock.get("components"):
                print("refusing to lock release {}: record release {}'s locked components in content._RELEASED_COMPONENTS "
                      "first, exactly as content_lock.json states them".format(current["version"], lock.get("version")))
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
