"""Two CI invariants as one offline test (after Culvert's workflow_action_pin_test.go and toolchain_consistency_test.go).

1. Action pins. Every `uses:` in every workflow is found, whatever its YAML spelling: a list item, a mapping key,
   quoted, or inside a flow mapping. The raw `uses:` keys are counted separately from the parsed references, and
   any difference fails, so a spelling the parser misses cannot slip past. Each reference must then be one of:
   - a local action (`./...`);
   - `docker://image@sha256:<64 hex>` (pinned by digest, never by tag);
   - `owner/repo[/path]@<40 hex>` followed by a `# <revision>` comment that names the release the SHA is.

   tools/check_action_pins.py and workflow policy rule 7 check the SHA as well; this adds the revision comment, the
   digest rule and the enumeration check, each with a negative control.

2. One Go compiler. The engine's build compiler is go/go.mod's `toolchain` line, else its `go` line. Everything
   that selects a Go must agree with it:
   - every `go-version:` in the workflows (only the go-minimum job's `${{ steps.minimum.outputs.version }}`,
     the engine's declared minimum checked by tools/go_ci.py, may differ);
   - no `go-version-file:`;
   - every `GOTOOLCHAIN:` that a workflow sets is `local`, so no job downloads another Go;
   - the `go` and `toolchain` lines of tools/scanners/go.mod and every tools/golint/*/go.mod;
   - the policy's pinned setup-go (SETUP_GO in tools/check_workflow_policy.py).

   go/go.mod's minimum (its `go` line) may be lower; it is tested by go-minimum, but may not be above the
   compiler. tools/check_go_drift.py keeps that compiler the newest patch of a supported line (online); this keeps
   every declaration equal to it on every run (offline).

A commit without go/go.mod checks the pins only, and the Go tool modules against one another.

    check_ci_consistency.py [--self-test]
Standard library only; Python 3.9 syntax.
"""
import re
import sys
from pathlib import Path

WORKFLOWS = Path(".github/workflows")
ENGINE_MOD = Path("go/go.mod")
TOOL_MODS = ("tools/scanners/go.mod",)
TOOL_MOD_GLOB = "tools/golint/*/go.mod"
POLICY = Path("tools/check_workflow_policy.py")
MINIMUM_SETUP = "${{ steps.minimum.outputs.version }}"

USES_KEY = re.compile(r"""(?:^|[\s{,-])["']?uses["']?\s*:""")
USES = re.compile(r"""(?:^|[\s{,-])["']?uses["']?\s*:\s*["']?([^\s"',}#]+)["']?\s*[,}]?\s*(#.*)?$""")
REMOTE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$")
DOCKER = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^#\s*\S")
GO_VERSION = re.compile(r"""^\s*go-version\s*:\s*["']?(\$\{\{[^}]*\}\}|[^"'\s#]+)["']?""")
GO_VERSION_FILE = re.compile(r"^\s*go-version-file\s*:")
GOTOOLCHAIN = re.compile(r"""^\s*GOTOOLCHAIN\s*:\s*["']?([^"'\s#]+)["']?""")
GOTOOLCHAIN_INLINE = re.compile(r"GOTOOLCHAIN=(?![\"']?local\b)([^\s\"';]+)")
MOD_GO = re.compile(r"^go\s+(\S+)\s*$", re.M)
MOD_TOOLCHAIN = re.compile(r"^toolchain\s+go(\S+)\s*$", re.M)
POLICY_SETUP = re.compile(r"""SETUP_GO\s*=\s*\{"uses":\s*"actions/setup-go",\s*"with":\s*\{"go-version":\s*"([^"]+)\"""")


def pin_problems(name, text):
    """Problems with the `uses:` references of one workflow."""
    problems, keys, found = [], 0, 0
    for number, line in enumerate(text.splitlines(), 1):
        code = line.split(" #", 1)[0] if not line.lstrip().startswith("#") else ""
        if not USES_KEY.search(code):
            continue
        keys += 1
        match = USES.search(line)
        if not match:
            problems.append("{}:{}: a `uses:` key whose reference could not be read: {}".format(name, number, line.strip()))
            continue
        found += 1
        reference, comment = match.group(1), (match.group(2) or "").strip()
        if reference.startswith("./"):
            continue
        if reference.startswith("docker://"):
            if not DOCKER.match(reference):
                problems.append("{}:{}: {} is not pinned by digest (docker://image@sha256:<64 hex>)".format(name, number, reference))
            continue
        if not REMOTE.match(reference):
            problems.append("{}:{}: {} is not pinned to a full commit SHA".format(name, number, reference))
        elif not REVISION.match(comment):
            problems.append("{}:{}: {} has no `# <revision>` comment naming the release it pins".format(name, number, reference))
    if keys != found:
        problems.append("{}: {} `uses:` key(s) but {} reference(s) read".format(name, keys, found))
    return problems, found


def module_lines(text):
    """(go line, toolchain version or None) of a go.mod."""
    go = MOD_GO.search(text or "")
    toolchain = MOD_TOOLCHAIN.search(text or "")
    return (go.group(1) if go else None), (toolchain.group(1) if toolchain else None)


def build_compiler(text):
    go, toolchain = module_lines(text)
    return toolchain or go


def release_tuple(version):
    return tuple(int(part) for part in re.findall(r"\d+", version or ""))


def toolchain_problems(engine_text, tool_mods, workflows, policy_text):
    """Problems with the Go compiler declarations. tool_mods and workflows: {path: text}."""
    problems = []
    compiler = None
    if engine_text is not None:
        minimum, toolchain = module_lines(engine_text)
        compiler = toolchain or minimum
        if minimum is None:
            problems.append("{} has no `go` line".format(ENGINE_MOD))
        elif toolchain and release_tuple(minimum) > release_tuple(toolchain):
            problems.append("{}: the minimum `go {}` is above the compiler `toolchain go{}`".format(ENGINE_MOD, minimum, toolchain))
    for path, text in sorted(tool_mods.items()):
        go, toolchain = module_lines(text)
        own = toolchain or go
        if own is None:
            problems.append("{} has no `go` line".format(path))
            continue
        compiler = compiler or own
        if own != compiler or (go and go != compiler):
            problems.append("{} builds with go {} (go line {}) but the compiler is go {}".format(path, own, go, compiler))
    for path, text in sorted(workflows.items()):
        for number, line in enumerate(text.splitlines(), 1):
            version = GO_VERSION.match(line)
            if version and version.group(1) != MINIMUM_SETUP and version.group(1) != compiler:
                problems.append("{}:{}: setup-go installs {} but the compiler is go {}".format(path, number, version.group(1), compiler))
            if GO_VERSION_FILE.match(line):
                problems.append("{}:{}: go-version-file lets go.mod choose the Go; name the release".format(path, number))
            setting = GOTOOLCHAIN.match(line)
            if setting and setting.group(1) != "local":
                problems.append("{}:{}: GOTOOLCHAIN {} would let a job download another Go; it must be local".format(
                    path, number, setting.group(1)))
            inline = GOTOOLCHAIN_INLINE.search(line)
            if inline and not line.lstrip().startswith("#"):
                problems.append("{}:{}: GOTOOLCHAIN={} in a run step; it must be local".format(path, number, inline.group(1)))
    setup = POLICY_SETUP.search(policy_text or "")
    if setup is None:
        problems.append("{}: SETUP_GO's go-version could not be read".format(POLICY))
    elif compiler is not None and setup.group(1) != compiler:
        problems.append("{}: SETUP_GO pins go {} but the compiler is go {}".format(POLICY, setup.group(1), compiler))
    return problems, compiler


def check(root="."):
    root = Path(root)
    problems, references = [], 0
    workflows = {path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
                 for path in sorted((root / WORKFLOWS).glob("*.y*ml"))}
    if not workflows:
        problems.append("no workflow found under {}: the check would pass vacuously".format(WORKFLOWS))
    for path, text in workflows.items():
        found, count = pin_problems(path, text)
        problems += found
        references += count
    engine = root / ENGINE_MOD
    tool_mods = {name: (root / name).read_text(encoding="utf-8") for name in TOOL_MODS if (root / name).is_file()}
    tool_mods.update({path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
                      for path in sorted(root.glob(TOOL_MOD_GLOB))})
    policy = root / POLICY
    found, compiler = toolchain_problems(engine.read_text(encoding="utf-8") if engine.is_file() else None, tool_mods,
                                         workflows, policy.read_text(encoding="utf-8") if policy.is_file() else None)
    return problems + found, references, compiler, len(workflows), len(tool_mods)


SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"


def self_test():
    good = ("jobs:\n  a:\n    steps:\n"
            "      - uses: actions/checkout@{0} # v7.0.1\n"
            "      - name: x\n        uses: actions/setup-go@{0} # v7.0.0\n"
            "      - {{ name: y, uses: owner/repo/path@{0} }} # v1.2.3\n"
            "      - \"uses\": 'owner/repo@{0}' # v2\n"
            "      - uses: ./.github/actions/local\n"
            "      - uses: docker://alpine@sha256:{1}\n").format(SHA, "a" * 64)
    assert pin_problems("w.yml", good) == ([], 6), pin_problems("w.yml", good)
    for label, line, expected in [
            ("tag", "      - uses: actions/checkout@v7 # v7\n", "not pinned to a full commit SHA"),
            ("short SHA", "      - uses: actions/checkout@3d3c42e # v7\n", "not pinned to a full commit SHA"),
            ("branch", "      - uses: owner/repo@main\n", "not pinned to a full commit SHA"),
            ("no revision comment", "      - uses: actions/checkout@{}\n".format(SHA), "no `# <revision>` comment"),
            ("empty revision comment", "      - uses: actions/checkout@{} #\n".format(SHA), "no `# <revision>` comment"),
            ("docker by tag", "      - uses: docker://alpine:3.20\n", "not pinned by digest"),
            ("quoted tag", "      - 'uses': \"actions/checkout@v7\"\n", "not pinned to a full commit SHA"),
            ("flow mapping tag", "      - { uses: actions/checkout@v7 }\n", "not pinned to a full commit SHA"),
            ("unreadable", "      - uses:\n", "could not be read")]:
        found, _ = pin_problems("w.yml", "steps:\n" + line)
        assert any(expected in problem for problem in found), (label, found)
    assert pin_problems("w.yml", "    # uses: actions/checkout@v7 in a comment\n") == ([], 0)
    modules = {"tools/scanners/go.mod": "module s\n\ngo 1.27.4\n", "tools/golint/gosec/go.mod": "module g\n\ngo 1.27.4\n"}
    flows = {"ci.yml": '        with:\n          go-version: "1.27.4"\n        env:\n          GOTOOLCHAIN: local\n'
                       "          go-version: ${{ steps.minimum.outputs.version }}\n"}
    policy = 'SETUP_GO = {"uses": "actions/setup-go", "with": {"go-version": "1.27.4", "cache": "false"}}\n'
    engine = "module e\n\ngo 1.26.0\n\ntoolchain go1.27.4\n"
    assert toolchain_problems(engine, modules, flows, policy) == ([], "1.27.4")
    assert toolchain_problems(None, modules, flows, policy) == ([], "1.27.4")      # main before the migration lands
    for label, change, expected in [
            ("engine on another compiler", ("engine", "module e\n\ngo 1.27.3\n"), "setup-go installs 1.27.4 but the compiler is go 1.27.3"),
            ("minimum above compiler", ("engine", "module e\n\ngo 1.28.0\n\ntoolchain go1.27.4\n"), "is above the compiler"),
            ("tool module behind", ("mods", dict(modules, **{"tools/golint/gosec/go.mod": "module g\n\ngo 1.26.6\n"})), "tools/golint/gosec/go.mod builds with go 1.26.6"),
            ("tool module toolchain", ("mods", dict(modules, **{"tools/golint/gosec/go.mod": "module g\n\ngo 1.27.4\n\ntoolchain go1.27.5\n"})), "builds with go 1.27.5"),
            ("setup-go behind", ("flows", {"ci.yml": '          go-version: "1.27.3"\n'}), "setup-go installs 1.27.3"),
            ("setup-go line only", ("flows", {"ci.yml": "          go-version: '1.27'\n"}), "setup-go installs 1.27 "),
            ("go-version-file", ("flows", {"ci.yml": "          go-version-file: go/go.mod\n"}), "go-version-file lets go.mod choose"),
            ("GOTOOLCHAIN auto", ("flows", {"ci.yml": "          GOTOOLCHAIN: auto\n"}), "GOTOOLCHAIN auto would let"),
            ("GOTOOLCHAIN pinned", ("flows", {"ci.yml": '          GOTOOLCHAIN: "go1.27.4"\n'}), "GOTOOLCHAIN go1.27.4 would let"),
            ("GOTOOLCHAIN inline", ("flows", {"ci.yml": "          run: GOTOOLCHAIN=go1.26.6 go build ./...\n"}), "GOTOOLCHAIN=go1.26.6 in a run step"),
            ("policy behind", ("policy", policy.replace("1.27.4", "1.27.3")), "SETUP_GO pins go 1.27.3"),
            ("policy unreadable", ("policy", "SETUP_GO = dict()\n"), "could not be read")]:
        arguments = {"engine": engine, "mods": modules, "flows": flows, "policy": policy}
        arguments[change[0]] = change[1]
        found, _ = toolchain_problems(arguments["engine"], arguments["mods"], arguments["flows"], arguments["policy"])
        assert any(expected in problem for problem in found), (label, found)
    assert not toolchain_problems(engine, modules, {"ci.yml": "          # GOTOOLCHAIN=go1.26.6 in a comment\n"}, policy)[0]
    print("check_ci_consistency self-test: ok (pins in every YAML spelling, revision comments, docker digests, "
          "enumeration, one Go compiler across go.mod files, workflows, GOTOOLCHAIN and the policy)")
    return 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
    problems, references, compiler, workflows, modules = check()
    for problem in problems:
        print("ci consistency:", problem)
    print("ci consistency: {} ({} action references in {} workflows pinned with revision comments; Go {} in go/go.mod, "
          "{} tool modules, every setup-go and GOTOOLCHAIN)".format(
              "ok" if not problems else "{} problem(s)".format(len(problems)), references, workflows, compiler, modules))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
