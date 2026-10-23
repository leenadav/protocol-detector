"""Release tag provenance: a `v*` tag may publish only a commit that is already on main.

Tag protection and required status checks are not enforceable on this repository's plan
(SSDLC.md, "Enforced controls"), so a tag pushed by any writer, on any commit, reaches the
release workflow. The release-gate job asks the GitHub compare API, with the read-only
token, how `main` relates to the tagged commit (`compare/<sha>...main`) and passes the
answer here:

  identical, ahead   the commit is on main (main equals it or descends from it)
  behind, diverged   it is not

Anything else (an API error, an empty answer) fails closed on a tag. Branch, pull-request
and manual dry runs only report, so the API call is exercised before the first tag.
Standard library only. Usage:
  check_release_ref.py --ref-type TYPE --sha SHA --status STATUS [--summary FILE]
  check_release_ref.py --self-test
"""
import re
import sys

ON_MAIN = {"identical", "ahead"}
OFF_MAIN = {"behind", "diverged"}
SHA = re.compile(r"^[0-9a-f]{40}$")


def decide(ref_type, sha, status):
    """(exit code, message)."""
    status = (status or "").strip()
    if not SHA.match(sha or ""):
        verdict, known = False, "not a full commit SHA: {!r}".format(sha)
    elif status in ON_MAIN:
        verdict, known = True, "commit {} is on main (compare status {})".format(sha, status)
    elif status in OFF_MAIN:
        verdict, known = False, "commit {} is not on main (compare status {})".format(sha, status)
    else:
        verdict, known = False, "cannot tell whether commit {} is on main (compare status {!r})".format(sha, status)
    if ref_type != "tag":
        return 0, "release provenance (dry run, {} ref, report only): {}".format(ref_type or "unknown", known)
    if verdict:
        return 0, "release provenance: {}".format(known)
    return 1, "release provenance: refusing the tag: {}; tag only commits that are already on main".format(known)


def self_test():
    sha = "0123456789abcdef0123456789abcdef01234567"
    for status in ("identical", "ahead"):
        assert decide("tag", sha, status)[0] == 0
    for status in ("behind", "diverged", "", "error", "Ahead", None):
        assert decide("tag", sha, status)[0] == 1, status
    assert decide("tag", "abc123", "ahead")[0] == 1                      # a short or empty SHA never passes
    assert decide("tag", "", "identical")[0] == 1
    for ref_type in ("branch", "", None):
        for status in ("diverged", "error", "ahead"):
            code, message = decide(ref_type, sha, status)
            assert code == 0 and "report only" in message, (ref_type, status)
    assert "is not on main" in decide("tag", sha, "diverged")[1]
    print("check_release_ref self-test: ok")
    return 0


def main(arguments):
    if "--self-test" in arguments:
        return self_test()
    values = {}
    for name in ("--ref-type", "--sha", "--status"):
        if name not in arguments or arguments.index(name) + 1 >= len(arguments):
            print("usage: check_release_ref.py --ref-type TYPE --sha SHA --status STATUS [--summary FILE]", file=sys.stderr)
            return 2
        values[name] = arguments[arguments.index(name) + 1]
    code, message = decide(values["--ref-type"], values["--sha"], values["--status"])
    print(message)
    if "--summary" in arguments and arguments.index("--summary") + 1 < len(arguments):
        with open(arguments[arguments.index("--summary") + 1], "a", encoding="utf-8") as summary:
            summary.write(message + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
