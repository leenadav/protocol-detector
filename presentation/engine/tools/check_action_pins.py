"""Fail when a GitHub Actions step uses a mutable action reference.

SSDLC supply-chain gate: every `uses:` must reference a 40-hex commit SHA, with
the human-readable version kept in a trailing comment. Local actions (./) and
docker:// references are reported but allowed.
"""
import re
import sys
from pathlib import Path

PIN = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)(?:\s*#.*)?$")
SHA = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def main(paths):
    failures = 0
    for root in paths:
        files = [Path(root)] if Path(root).is_file() else sorted(Path(root).glob("*.yml")) + sorted(Path(root).glob("*.yaml"))
        for path in files:
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                match = PIN.match(line)
                if not match:
                    continue
                reference = match.group(1)
                if reference.startswith(("./", "docker://")):
                    continue
                if not SHA.match(reference):
                    failures += 1
                    print("{}:{}: unpinned action reference {}".format(path, number, reference))
    print("checked action pins:", "all pinned" if not failures else "{} unpinned".format(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or [".github/workflows"]))
