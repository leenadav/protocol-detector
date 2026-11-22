#!/usr/bin/env python3
"""Negative controls for the narrow gitleaks allowlists in .gitleaks.toml (PRO-145, PRO-153, PRO-184).

App Research live rounds write each name's public DNS CNAME chain ("host>host>...") into
research/live-results-YYYY-MM-DD-rN.tsv, and generic-api-key reads a label such as "edgekey" before ">" as
key=value. .gitleaks.toml has one [[allowlists]] entry for that, with condition AND: the file is such a TSV and the
whole match is a chain of lowercase DNS names joined by ">". Go table tests carry synthetic HTTP/1 messages as hex,
and a case name such as "session key" next to one reads as key=value too; a second AND entry allows an all-hex secret
decoding to an HTTP/1 start line only in go/**/*_test.go (SEC-CI-1), because the same hex anywhere else could be a
captured request with a cookie or bearer token. This tool proves both allowlists stay that narrow.

  --self-test  reads the entry from .gitleaks.toml and checks its path and regex against fixed samples (Python's re
               reads these two patterns as Go's RE2 does): CNAME chains pass only in live-results TSVs; keys,
               tokens and passwords, in that file or anywhere else, do not; hex HTTP/1 passes only in Go tests
               under go/, and a hex secret that is not an HTTP message passes nowhere.
  --bin DIR    builds a throwaway git repository with the same samples and runs the real gitleaks (DIR/gitleaks)
               with this .gitleaks.toml: exactly the chain in the live-results TSV is allowed; every secret, and the
               same chain in any other file, is still reported; a hex HTTP/1 request is allowed in a Go test under
               go/ and reported in a Python file, a JSON fixture and a Go file that is not a test.

    check_gitleaks_allowlist.py --self-test
    check_gitleaks_allowlist.py --bin DIR
Standard library only; Python 3.9 syntax.
"""
import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

CONFIG = Path(".gitleaks.toml")
LIVE = "research/live-results-2026-12-01-r6.tsv"
# Built at run time too: in this .py file the chain is outside the allowlisted path, so the scan would report it.
CHAIN = "sdds9.vendorupd.com.edge" + "key.net>" + "e4567.dscd.akamaiedge.net"
# Synthetic, never-issued values in the shapes gitleaks' default rules know. Each is assembled at run time, so this
# file holds no literal that the repository's own secret scan would report.
SECRETS = [
    ("generic-api-key", "api" + "_key=" + "Zq8vT3mW9xKp2LrN7sYb4HcJ"),
    ("generic-api-key", "secret" + "_token>" + "Ab3dE5fG7hJ9kL1mN3pQ5rS7tU9"),
    ("aws-access-token", "AKIA" + "Q2ZJ7XKP4MWN6RTB"),
    ("github-pat", "ghp" + "_" + "ZqY8mN2pR4tV6xB9cD1fG3hJ5kL7nP0sQ2wE"),
]
GO_TEST = "go/internal/protocols/x/hex_test.go"
# A synthetic captured request carrying a session cookie, hex-encoded at run time (no literal hex in this file).
HEX_REQUEST = b"GET /a HTTP/1.1\r\nCookie: s=Zq8vT3mW9xKp2LrN\r\n".hex()
HEX_LINE = '\t{{"session key", "{}"}},\n'


def live_allowlist(text):
    """(path regex, match regex) of the [[allowlists]] entry for live-results TSVs, or None."""
    for block in text.split("[[allowlists]]")[1:]:
        block = block.split("\n[")[0]
        if 'regexTarget = "match"' not in block or 'condition = "AND"' not in block:
            continue
        literals = re.findall(r"'''(.*?)'''", block)
        paths = [item for item in literals if "live-results" in item]
        others = [item for item in literals if "live-results" not in item]
        if len(paths) == 1 and len(others) == 1:
            return paths[0], others[0]
    return None


def hex_allowlist(text):
    """(path regex, secret regex) of the [[allowlists]] entry for hex HTTP/1 messages in Go tests, or None."""
    for block in text.split("[[allowlists]]")[1:]:
        block = block.split("\n[")[0]
        if 'condition = "AND"' not in block or "regexTarget" in block:
            continue
        literals = re.findall(r"'''(.*?)'''", block)
        paths = [item for item in literals if item.startswith("^go/")]
        others = [item for item in literals if not item.startswith("^go/")]
        if len(paths) == 1 and len(others) == 1 and others[0].startswith("^(?:47455420"):
            return paths[0], others[0]
    return None


def allowed(entry, path, match):
    path_re, match_re = entry
    return bool(re.search(path_re, path)) and bool(re.search(match_re, match))


def self_test():
    entry = live_allowlist(CONFIG.read_text(encoding="utf-8"))
    assert entry, ".gitleaks.toml has no AND, match-target allowlist for research/live-results-*.tsv"
    assert allowed(entry, LIVE, CHAIN + "\t")
    assert allowed(entry, "research/live-results-2026-11-21-r5.tsv", "a.b.com.edge" + "key.net>" + "e1.x.akamaiedge.net>c.d.net")
    for path in ("docs/notes.tsv", "research/live-results.tsv", "research/other/live-results-2026-12-01-r6.tsv",
                 "research/live-results-2026-12-01-r6.tsv.bak", "go/internal/x_test.go"):
        assert not allowed(entry, path, CHAIN), path
    for _, secret in SECRETS:
        assert not allowed(entry, LIVE, secret), secret
    for match in ("key>Zq8vT3mW9xKp2LrN7sYb4HcJ.example.com", "a.b.com>", "A.B.COM>c.d.com", "a.b.com>c.d.com x=1"):
        assert not allowed(entry, LIVE, match), match
    text = CONFIG.read_text(encoding="utf-8")
    hexed = hex_allowlist(text)
    assert hexed, ".gitleaks.toml has no AND allowlist for hex HTTP/1 messages in go/**/*_test.go"
    assert text.count("47455420") == 1, "the hex HTTP/1 regex appears outside its scoped entry"
    for path in (GO_TEST, "go/internal/textroute/boundary_test.go"):
        assert allowed(hexed, path, HEX_REQUEST), path
        assert allowed(hexed, path, b"HTTP/1.1 200 OK\r\n".hex()) and allowed(hexed, path, b"POST / x".hex())
    for path in ("tools/minimize_example.py", "migration/fixtures/cases.json", "go/internal/x.go", "go/x_test.go.bak",
                 "vendor/go/x_test.go", "docs/go/x_test.go", "research/live-results-2026-12-01-r6.tsv"):
        assert not allowed(hexed, path, HEX_REQUEST), path
    for secret in (b"PUT / HTTP/1.1".hex(), "0123456789abcdef0123456789abcdef", HEX_REQUEST.upper(), HEX_REQUEST + "0",
                   HEX_REQUEST + "zz") + tuple(value for _, value in SECRETS):
        assert not allowed(hexed, GO_TEST, secret), secret
    print("check_gitleaks_allowlist self-test: ok (live-results CNAME chains only; hex HTTP/1 only in Go tests under go/; "
          "{} secret shapes, other paths and malformed values still flag)".format(len(SECRETS)))
    return 0


def run(bin_dir):
    config = CONFIG.resolve()
    with tempfile.TemporaryDirectory() as scratch:
        repo = Path(scratch) / "repo"
        (repo / "research").mkdir(parents=True)
        (repo / "docs").mkdir()
        rows = ["name\thost\tcname\tstatus", "vendor-a\tsdds9.vendorupd.com\t{}\tok".format(CHAIN)]
        rows += ["vendor-{}\tx.vendor.com\t{}\tok".format(number, secret) for number, (_, secret) in enumerate(SECRETS)]
        (repo / LIVE).write_text("\n".join(rows) + "\n", encoding="utf-8")
        (repo / "docs" / "notes.tsv").write_text(rows[1] + "\n", encoding="utf-8")
        hex_files = [GO_TEST, "tools/capture.py", "migration/fixtures/cases.json", "go/internal/protocols/x/hex.go"]
        for name in hex_files:
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_text(HEX_LINE.format(HEX_REQUEST), encoding="utf-8")
        git = ["git", "-C", str(repo), "-c", "user.email=ci@example.invalid", "-c", "user.name=ci"]
        for command in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "fixture"]):
            subprocess.run(git + command, check=True)  # noqa: S603,S607
        report = Path(scratch) / "report.json"
        subprocess.run([str(Path(bin_dir) / "gitleaks"), "git", "--config", str(config), "--no-banner",  # noqa: S603
                        "--report-format", "json", "--report-path", str(report), str(repo)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        found = sorted((item["File"], item["StartLine"], item["RuleID"]) for item in json.loads(report.read_text()))
    expected = sorted([("docs/notes.tsv", 1, "generic-api-key")]
                      + [(LIVE, number + 3, rule) for number, (rule, _) in enumerate(SECRETS)]
                      + [(name, 1, "generic-api-key") for name in hex_files[1:]])
    if found != expected:
        print("FAILED: gitleaks reported {}, expected {}".format(found, expected))
        return 1
    print("check_gitleaks_allowlist: ok with the real gitleaks (the chain in {} and the hex HTTP/1 request in {} allowed; "
          "{} secrets there, the chain in docs/notes.tsv and the hex request in {} other files reported)".format(
              LIVE, GO_TEST, len(SECRETS), len(hex_files) - 1))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--bin", help="directory holding the gitleaks binary")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.bin:
        parser.error("--bin or --self-test is required")
    return run(args.bin)


if __name__ == "__main__":
    sys.exit(main())
