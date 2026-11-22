"""Fail when the Go that builds the pinned scanners falls behind or out of support.

Supply-chain drift gate for the Go-built scanners (tools/scanners, items 21 and 22). The
gitleaks build once ran on a Go release past its support window, and govulncheck only
reports vulnerabilities already known; this catches the drift itself:

  - every `actions/setup-go` step in every workflow (ci.yml, nightly-fuzz.yml, ...) that names a
    release installs the same `go-version`,
    and it equals the compiler tools/scanners/go.mod builds with: its `toolchain` line, else its
    `go` line (https://go.dev/doc/toolchain; the builds run with GOTOOLCHAIN=local). The only
    other form allowed is the go-minimum job's `${{ steps.minimum.outputs.version }}`, the
    engine's declared minimum, which tools/go_ci.py reads from go/go.mod and checks;
  - when go/go.mod exists it builds with that same compiler, and in both go.mod files the `go`
    line (the minimum) is not above the `toolchain` line. The minimum itself is meant to be an
    older release, so it is tested by the go-minimum job, not held to the newest patch;
  - that release line is one of the two newest stable Go lines (Go supports two), and the
    pin is exactly its newest patch release: an older patch fails (patch releases carry the
    security fixes), and so does a patch the list does not hold (a typo or premature bump).

Releases are read from the Go module proxy's toolchain list
(https://proxy.golang.org/golang.org/toolchain/@v/list), the source `GOTOOLCHAIN` itself
uses; an unreadable or empty answer fails. The newest gitleaks and govulncheck releases are
reported for information only: govulncheck in ci decides whether a pinned one is unsafe.

Usage: check_go_drift.py [--self-test]
"""
import json
import re
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from go_ci import module_versions  # noqa: E402  (one go.mod reading for the drift check and the Go gate)

CI = ".github/workflows"
GO_MOD = "tools/scanners/go.mod"
ENGINE_MOD = "go/go.mod"
MINIMUM_SETUP = "${{ steps.minimum.outputs.version }}"
TOOLCHAINS = "https://proxy.golang.org/golang.org/toolchain/@v/list"
LATEST = {"gitleaks": "https://proxy.golang.org/github.com/zricethezav/gitleaks/v8/@latest",
          "govulncheck": "https://proxy.golang.org/golang.org/x/vuln/@latest"}
SUPPORTED_LINES = 2
SETUP_GO_VERSION = re.compile(r'^\s+go-version:\s*"?([0-9][0-9.]*)"?\s*(#.*)?$')
ANY_GO_VERSION = re.compile(r"^\s+go-version(-file)?:\s*(.*?)\s*$")
STABLE = re.compile(r"^v0\.0\.1-go(\d+)\.(\d+)\.(\d+)\.linux-amd64$")


def pinned_versions(ci_text, gomod_text, engine_text=None):
    """(setup-go release versions in ci.yml, the compiler tools/scanners/go.mod builds with or None, problems):
    problems covers a setup-go version in any other form than a release or the go-minimum job's, a go.mod
    whose minimum is above its toolchain, and a go/go.mod that builds with another compiler."""
    versions, problems = [], []
    for line in ci_text.splitlines():
        match, other = SETUP_GO_VERSION.match(line), ANY_GO_VERSION.match(line)
        if match:
            versions.append(match.group(1))
        elif other and other.group(2) != MINIMUM_SETUP:
            problems.append("{}: setup-go `{}` is neither an exact pinned release nor the go-minimum job's {}".format(
                CI, line.strip(), MINIMUM_SETUP))
    _, build, found = module_versions(gomod_text, GO_MOD)
    problems += found
    if engine_text is not None:
        _, engine, found = module_versions(engine_text, ENGINE_MOD)
        problems += found
        if engine is not None and build is not None and engine != build:
            problems.append("{} builds with go {} but {} builds with go {}: one Go toolchain for the scanners and the "
                            "engine".format(ENGINE_MOD, engine, GO_MOD, build))
    return versions, build, problems


def stable_releases(listing):
    """{(major, minor): newest patch} from the toolchain module list; release candidates are skipped."""
    lines = {}
    for entry in listing.split():
        match = STABLE.match(entry.strip())
        if match:
            major, minor, patch = (int(part) for part in match.groups())
            lines[(major, minor)] = max(patch, lines.get((major, minor), -1))
    return lines


def decide(versions, directive, problems, lines):
    """The problems, empty when the pinned Go is consistent, supported and on its newest patch."""
    problems = list(problems)
    if not versions:
        return problems + ["{}: no actions/setup-go go-version found".format(CI)]
    if len(set(versions)) != 1:
        problems.append("{}: setup-go steps install different Go versions: {}".format(CI, ", ".join(sorted(set(versions)))))
    pinned = versions[0]
    if directive != pinned:
        problems.append("{}: builds with `go {}`, which differs from the {} setup-go installs ({}); with GOTOOLCHAIN=local "
                        "the build would fail or run on another release".format(GO_MOD, directive, CI, pinned))
    parts = pinned.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        return problems + ["{}: go-version {} is not an exact release (major.minor.patch)".format(CI, pinned)]
    if not lines:
        return problems + ["the Go toolchain list is empty or unreadable: support cannot be checked"]
    major, minor, patch = (int(part) for part in parts)
    supported = sorted(lines, reverse=True)[:SUPPORTED_LINES]
    if (major, minor) not in supported:
        problems.append("Go {} is past its support window: the supported lines are {}".format(
            pinned, ", ".join("{}.{} (newest {}.{}.{})".format(a, b, a, b, lines[(a, b)]) for a, b in supported)))
    elif lines[(major, minor)] > patch:
        problems.append("Go {} is behind its line's newest patch release {}.{}.{} (patch releases carry the security "
                        "fixes)".format(pinned, major, minor, lines[(major, minor)]))
    elif lines[(major, minor)] < patch:
        # item 23 round 1: a release the list does not hold (a typo or a premature bump) is not "the newest patch"
        problems.append("Go {} is not in the Go toolchain list (its line's newest release is {}.{}.{}): the pin names a "
                        "release that does not exist".format(pinned, major, minor, lines[(major, minor)]))
    return problems


def fetch(url):
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310  (fixed https URLs above)
        return response.read().decode("utf-8")


def self_test():
    listing = "\n".join(["v0.0.1-go1.25.9.linux-amd64", "v0.0.1-go1.26.9.linux-amd64", "v0.0.1-go1.26.10.linux-amd64",
                         "v0.0.1-go1.27.2.linux-amd64", "v0.0.1-go1.27.3.linux-amd64", "v0.0.1-go1.28rc1.linux-amd64",
                         "v0.0.1-go1.27.3.darwin-arm64", "v0.0.1-go1.27.4.windows-amd64"])
    lines = stable_releases(listing)
    assert lines == {(1, 25): 9, (1, 26): 10, (1, 27): 3}, lines   # rc and other platforms skipped
    ci = '      - uses: actions/setup-go@x # v5.6.0\n        with:\n          go-version: "{}"\n          cache: false\n'
    gomod = "module m\n\ngo {}\n\ntool x\n"
    assert decide(*pinned_versions(ci.format("1.27.3") * 2, gomod.format("1.27.3")), lines) == []
    assert decide(*pinned_versions(ci.format("1.26.10"), gomod.format("1.26.10")), lines) == []
    culvert = "module x\n\ngo 1.27.0\n\ntoolchain go1.27.3\n"
    minimum_job = ci.format("1.27.3") + "          go-version: ${{ steps.minimum.outputs.version }}\n"
    assert decide(*pinned_versions(ci.format("1.27.3"), "module m\n\ngo 1.27.0\n\ntoolchain go1.27.3\n"), lines) == []
    assert decide(*pinned_versions(minimum_job, gomod.format("1.27.3"), culvert), lines) == []
    assert decide(*pinned_versions(minimum_job, gomod.format("1.27.3"), gomod.format("1.27.3")), lines) == []
    for label, (engine, expected) in {
            "engine toolchain differs": (culvert.replace("go1.27.3", "go1.27.2"), "go/go.mod builds with go 1.27.2"),
            "engine without toolchain differs": (gomod.format("1.27.0"), "go/go.mod builds with go 1.27.0"),
            "engine minimum above its toolchain": (culvert.replace("go 1.27.0", "go 1.27.9"), "above its toolchain")}.items():
        found = decide(*pinned_versions(minimum_job, gomod.format("1.27.3"), engine), lines)
        assert any(expected in problem for problem in found), (label, found)
    for label, (ci_text, gomod_text, expected) in {
        "behind its patch": (ci.format("1.27.2"), gomod.format("1.27.2"), "behind its line's newest patch release 1.27.3"),
        "future patch": (ci.format("1.27.99"), gomod.format("1.27.99"), "not in the Go toolchain list"),
        "newest plus one": (ci.format("1.27.4"), gomod.format("1.27.4"), "not in the Go toolchain list"),
        "newest plus one, older line": (ci.format("1.26.11"), gomod.format("1.26.11"), "not in the Go toolchain list"),
        "out of support": (ci.format("1.25.9"), gomod.format("1.25.9"), "past its support window"),
        "two setup-go versions": (ci.format("1.27.3") + ci.format("1.26.10"), gomod.format("1.27.3"), "different Go versions"),
        "go.mod differs": (ci.format("1.27.3"), gomod.format("1.26.10"), "differs from"),
        "go.mod without directive": (ci.format("1.27.3"), "module m\n", "no single `go` directive"),
        # the compiler is the `toolchain` line when there is one (go.dev/doc/toolchain)
        "toolchain behind": (ci.format("1.27.3"), "module m\n\ngo 1.27.0\n\ntoolchain go1.27.2\n", "builds with `go 1.27.2`"),
        "minimum above the toolchain": (ci.format("1.27.3"), "module m\n\ngo 1.27.5\n\ntoolchain go1.27.3\n", "above its toolchain"),
        "unknown setup-go form": (ci.format("1.27.3") + "          go-version: ${{ matrix.go }}\n", gomod.format("1.27.3"),
                                  "neither an exact pinned release"),
        "setup-go reads go.mod": (ci.format("1.27.3") + "          go-version-file: go/go.mod\n", gomod.format("1.27.3"),
                                  "neither an exact pinned release"),
        "not an exact release": (ci.format("1.27"), gomod.format("1.27"), "not an exact release"),
        "no setup-go": ("jobs: {}\n", gomod.format("1.27.3"), "no actions/setup-go"),
    }.items():
        found = decide(*pinned_versions(ci_text, gomod_text), lines)
        assert any(expected in problem for problem in found), (label, found)
    assert "empty or unreadable" in decide(*pinned_versions(ci.format("1.27.3"), gomod.format("1.27.3")), {})[0]
    assert stable_releases("<html>proxy error</html>") == {}
    print("check_go_drift self-test: ok")
    return 0


def main():
    engine = Path(ENGINE_MOD)
    workflows = "".join(path.read_text(encoding="utf-8") for path in sorted(Path(CI).glob("*.yml")))
    versions, directive, found = pinned_versions(workflows, Path(GO_MOD).read_text(encoding="utf-8"),
                                                 engine.read_text(encoding="utf-8") if engine.is_file() else None)
    try:
        lines = stable_releases(fetch(TOOLCHAINS))
    except OSError as error:
        print("go drift: cannot read {}: {}".format(TOOLCHAINS, error))
        return 1
    problems = decide(versions, directive, found, lines)
    for name, url in LATEST.items():
        try:
            print("go drift: newest {} release {} (information only)".format(name, json.loads(fetch(url))["Version"]))
        except (OSError, ValueError, KeyError) as error:
            print("go drift: newest {} release unknown ({})".format(name, error))
    for problem in problems:
        print("go drift:", problem)
    print("go drift: {} (Go {} pinned)".format("ok" if not problems else "{} problem(s)".format(len(problems)),
                                              versions[0] if versions else "none"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv[1:] else main())
