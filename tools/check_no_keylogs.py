"""Fail when a tracked file looks like an NSS key log or carries TLS secrets (stage 8, A16/A10).

CI's secret scan (gitleaks) has the same rules in .gitleaks.toml; this check runs in `make check` so a key
log never reaches a commit on a developer machine either. Fixtures and tests are allowed to carry
synthetic entries only when the whole value is a documented placeholder (all-zero or repeated bytes).
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LINE = re.compile(rb"^(CLIENT_RANDOM|(CLIENT|SERVER)_(HANDSHAKE|EARLY)?_?TRAFFIC_SECRET(_0|_N)?|EXPORTER_SECRET|EARLY_EXPORTER_SECRET)\s+([0-9a-fA-F]{64})\s+([0-9a-fA-F]{64,96})\s*$", re.M)
PLACEHOLDER = re.compile(rb"^(00)+$|^([0-9a-fA-F]{2})\2{31,47}$")


def tracked_files():
    output = subprocess.run(["git", "ls-files", "-z"], cwd=str(ROOT), stdout=subprocess.PIPE, check=True).stdout  # noqa: S603,S607 - fixed argv
    return [ROOT / name.decode() for name in output.split(b"\0") if name]


def main():
    problems = []
    for path in tracked_files():
        if path.suffix in (".png", ".pcap", ".pcapng", ".whl", ".gz") or not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        for match in LINE.finditer(data):
            if PLACEHOLDER.match(match.group(5)) and PLACEHOLDER.match(match.group(6)):
                continue
            problems.append("%s: key-log line (%s ...)" % (path.relative_to(ROOT), match.group(1).decode()))
        if path.name.lower().endswith((".keys", ".keylog", "sslkeylog.txt", "keylog.txt")):
            problems.append("%s: key-log file name" % path.relative_to(ROOT))
    if problems:
        print("key logs FAILED:\n  " + "\n  ".join(problems))
        return 1
    print("key logs ok: no NSS key-log lines or key-log files among tracked files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
