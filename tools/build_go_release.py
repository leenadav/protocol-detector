"""Reproducible Go release binaries and their SBOM (the release controller's build job, publish-release.yml).

For each target in TARGETS, `go/cmd/protodetect` is built twice, each time with its own empty GOCACHE and
GOTMPDIR, with CGO_ENABLED=0, -trimpath, -buildvcs=false and -ldflags "-s -w -buildid=", on exactly the pinned
compiler (tools/go_ci.py: the installed Go must be the one go/go.mod builds with, a dependency must be vendored,
GOFLAGS=-mod=vendor then, and the job runs with GOPROXY=off). The two builds must be byte-identical, or the
release fails: that is the reproducibility claim, and anyone can repeat it with the same Go and these flags.

The SBOM (CycloneDX 1.5 JSON, dist/protodetect-<version>-go.cdx.json) is generated from the binaries' own build
information (`go version -m -json`): the main module, every linked module with its version and go.sum hash, and
the Go toolchain. Every linked module must be one go/vendor/modules.txt lists. It has no timestamp and a serial
number derived from its content, so it is reproducible too. The SBOM lists the union of the modules the targets
link: a target may link fewer (golang.org/x/crypto links golang.org/x/sys for CPU feature detection on amd64
only), but a module linked by two targets must be the same version and go.sum hash in both. Each component's
`go:targets` property names the GOOS/GOARCH targets whose binary links it (the toolchain: every target).

Files written into --out (the controller's dist/, which it checksums, attests and on a tag publishes):
    protodetect-<version>-<goos>-<goarch>[.exe]    protodetect-<version>-go.cdx.json
A commit without go/go.mod (no Go engine at all) builds nothing and says so. With go/go.mod present, a missing
go/cmd/protodetect fails the release, as go_ci.py fails on a partial tree: a renamed or deleted main package must
not publish a tag without its Go binaries.

    build_go_release.py --version X.Y.Z [--out DIR] [--summary FILE]
    build_go_release.py --self-test
Standard library only; Python 3.9 syntax.
"""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_ci  # noqa: E402

MAIN = "./cmd/protodetect"
TARGETS = (("linux", "amd64"), ("linux", "arm64"), ("darwin", "amd64"), ("darwin", "arm64"), ("windows", "amd64"))
FLAGS = ["-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid="]
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z.]+)?$")
MODULE_LINE = re.compile(r"^# (\S+) (\S+)")
GO_SUM = Path("go/go.sum")


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def build_once(goos, goarch, out, env):
    with tempfile.TemporaryDirectory(prefix="go-release-cache-") as cache, tempfile.TemporaryDirectory(prefix="go-release-tmp-") as tmp:
        build_env = dict(env, CGO_ENABLED="0", GOOS=goos, GOARCH=goarch, GOCACHE=cache, GOTMPDIR=tmp)
        subprocess.run(["go", "build"] + FLAGS + ["-o", str(out), MAIN], cwd="go", env=build_env, check=True)  # noqa: S603,S607


def vendored_modules(text):
    """{path: version} of the modules go/vendor/modules.txt lists."""
    return dict(match.groups() for match in map(MODULE_LINE.match, (text or "").splitlines()) if match)


def targets_property(targets):
    """The `go:targets` property (sorted, comma-separated GOOS/GOARCH) when the targets are known, else none."""
    return [{"name": "go:targets", "value": ",".join(sorted(targets))}] if targets else []


def go_sums(text):
    """{(path, version): h1 hash} of the module zips go/go.sum records (the /go.mod lines are not linked code)."""
    sums = {}
    for line in (text or "").splitlines():
        fields = line.split()
        if len(fields) == 3 and not fields[1].endswith("/go.mod"):
            sums[(fields[0], fields[1])] = fields[2]
    return sums


def with_sums(infos, sums):
    """The build infos with each dependency's missing Sum taken from go.sum: a -mod=vendor build records none."""
    return {target: dict(info, Deps=[dep if dep.get("Sum") else dict(dep, Sum=sums.get((dep["Path"], dep["Version"]), ""))
                                     for dep in info.get("Deps") or []])
            for target, info in infos.items()}


def sbom(version, info, go_version):
    """A CycloneDX 1.5 document for the binaries, from one binary's `go version -m -json` record."""
    main = info.get("Main") or {}
    components = [{"type": "library", "bom-ref": "pkg:golang/{}@{}".format(dep["Path"], dep["Version"]),
                   "name": dep["Path"], "version": dep["Version"],
                   "purl": "pkg:golang/{}@{}".format(dep["Path"], dep["Version"]),
                   "properties": [{"name": "go:sum", "value": dep.get("Sum", "")}] + targets_property(dep.get("Targets"))}
                  for dep in sorted(info.get("Deps") or [], key=lambda item: item["Path"])]
    platform = {"type": "platform", "bom-ref": "pkg:golang/stdlib@{}".format(go_version), "name": "golang",
                "version": go_version, "purl": "pkg:golang/stdlib@{}".format(go_version)}
    if info.get("Targets"):
        platform["properties"] = targets_property(info["Targets"])
    components.append(platform)
    document = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "application", "bom-ref": "protodetect", "name": "protodetect",
                                   "version": version, "description": "the Go protodetect binary ({})".format(info.get("Path")),
                                   "properties": [{"name": "go:main-module", "value": main.get("Path", "")}]},
                     "tools": {"components": [{"type": "application", "name": "tools/build_go_release.py"}]}},
        "components": components,
        "dependencies": [{"ref": "protodetect", "dependsOn": [item["bom-ref"] for item in components]}],
    }
    serial = uuid.uuid5(uuid.NAMESPACE_URL, "protodetect-sbom:" + json.dumps(document, sort_keys=True))
    return dict(document, serialNumber="urn:uuid:{}".format(serial))


def module_problems(infos, vendored):
    """Problems with the linked modules: one module linked at two versions or hashes, a module the vendor tree
    does not list, or one without a go.sum hash. Targets may link different subsets (the SBOM lists their union)."""
    problems, seen = [], {}
    for target, info in sorted(infos.items()):
        for dep in info.get("Deps") or []:
            path, version, digest = dep["Path"], dep["Version"], dep.get("Sum", "")
            if vendored.get(path) != version:
                problems.append("{} links {} {}, which go/vendor/modules.txt does not list".format(target, path, version))
            if not digest:
                problems.append("{} links {} {}, which has no go.sum hash".format(target, path, version))
            first = seen.setdefault(path, (version, digest, target))
            if first[:2] != (version, digest):
                problems.append("{} is {} {} on {} but {} {} on {}".format(path, first[0], first[1], first[2], version, digest, target))
    return sorted(set(problems))


def linked_union(infos):
    """One build-info document whose Deps are every module any target links (each once, sorted by path), each with
    the targets that link it under "Targets"; the document's own "Targets" are all of them (the toolchain's)."""
    deps, targets = {}, {}
    for target, info in sorted(infos.items()):
        for dep in info.get("Deps") or []:
            deps.setdefault(dep["Path"], dep)
            targets.setdefault(dep["Path"], []).append(target)
    first = next(iter(sorted(infos.items())))[1]
    return dict(first, Targets=sorted(infos), Deps=[dict(deps[path], Targets=targets[path]) for path in sorted(deps)])


def tree_state(root="."):
    """("skip", why) without go/go.mod, ("fail", why) with go/go.mod but no main package, else ("build", "")."""
    root = Path(root)
    if not (root / "go" / "go.mod").is_file():
        return "skip", "No go/go.mod on this commit: no Go binary to build."
    if not (root / "go" / MAIN).is_dir():
        return "fail", ("go/go.mod is present but go/{} is not: the Go binaries cannot be built, and a release without "
                        "them must not pass (renamed or deleted main package?)".format(MAIN[2:]))
    return "build", ""


def run(version, out, summary):
    title = "### Go release binaries"
    state, why = tree_state()
    if state == "skip":
        go_ci.summarise(summary, [title, "", why])
        return 0
    if state == "fail":
        go_ci.summarise(summary, [title, "", "- FAILED: " + why])
        return 1
    tree, problems = go_ci.toolchain_problems()
    if problems:
        go_ci.summarise(summary, [title, ""] + ["- FAILED: " + problem for problem in problems])
        return 1
    env = go_ci.go_env(tree.get("vendored"))
    out = Path(out).resolve()   # absolute: the builds run with cwd go/, so a relative path would land in go/
    out.mkdir(parents=True, exist_ok=True)
    lines, infos, failed = [title, "", "| file | sha256 | reproducible |", "|---|---|---|"], {}, False
    with tempfile.TemporaryDirectory(prefix="go-release-second-") as second:
        for goos, goarch in TARGETS:
            name = "protodetect-{}-{}-{}{}".format(version, goos, goarch, ".exe" if goos == "windows" else "")
            first, again = out / name, Path(second, name)
            build_once(goos, goarch, first, env)
            build_once(goos, goarch, again, env)
            same = sha256(first) == sha256(again)
            failed |= not same
            lines.append("| `{}` | `{}` | {} |".format(name, sha256(first), "yes" if same else "NO: the second build differs"))
            raw = subprocess.run(["go", "version", "-m", "-json", str(first)], stdout=subprocess.PIPE, check=True).stdout  # noqa: S603,S607
            infos["{}/{}".format(goos, goarch)] = json.loads(raw.decode("utf-8"))
    vendored = vendored_modules(go_ci.read(go_ci.VENDOR))
    infos = with_sums(infos, go_sums(go_ci.read(GO_SUM)))
    found = module_problems(infos, vendored)
    lines += ["- FAILED: " + problem for problem in found]
    failed |= bool(found)
    info = linked_union(infos)
    document = sbom(version, info, info.get("GoVersion", ""))
    sbom_path = out / "protodetect-{}-go.cdx.json".format(version)
    sbom_path.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    lines += ["", "SBOM `{}`: {} linked module(s) and {}{}".format(
        sbom_path.name, len(document["components"]) - 1, info.get("GoVersion"),
        ", GOFLAGS=-mod=vendor" if tree.get("vendored") else "")]
    go_ci.summarise(summary, lines)
    return 1 if failed else 0


def self_test():
    info = {"GoVersion": "go1.27.4", "Path": "github.com/x/go/cmd/protodetect", "Main": {"Path": "github.com/x/go"},
            "Deps": [{"Path": "golang.org/x/sys", "Version": "v0.50.0", "Sum": "h1:b="},
                     {"Path": "golang.org/x/crypto", "Version": "v0.59.0", "Sum": "h1:a="}]}
    document = sbom("1.2.3", info, "go1.27.4")
    names = [component["name"] for component in document["components"]]
    assert names == ["golang.org/x/crypto", "golang.org/x/sys", "golang"], names
    assert document["metadata"]["component"]["version"] == "1.2.3" and "timestamp" not in document["metadata"]
    assert sbom("1.2.3", info, "go1.27.4") == document                       # reproducible: same input, same document
    assert sbom("1.2.4", info, "go1.27.4")["serialNumber"] != document["serialNumber"]
    modules = "# golang.org/x/crypto v0.59.0\n## explicit; go 1.24\ngolang.org/x/crypto/chacha20\n# golang.org/x/sys v0.50.0\n"
    vendored = vendored_modules(modules)
    assert vendored == {"golang.org/x/crypto": "v0.59.0", "golang.org/x/sys": "v0.50.0"}, vendored
    assert module_problems({"linux/amd64": info, "darwin/arm64": info}, vendored) == []
    fewer = dict(info, Deps=info["Deps"][1:])                                # x/crypto only, as on arm64
    assert module_problems({"linux/amd64": info, "linux/arm64": fewer}, vendored) == []
    union = linked_union({"linux/arm64": fewer, "linux/amd64": info})
    assert [d["Path"] for d in union["Deps"]] == ["golang.org/x/crypto", "golang.org/x/sys"], union["Deps"]
    marked = {c["name"]: dict((p["name"], p["value"]) for p in c.get("properties", []))
              for c in sbom("1.2.3", union, "go1.27.4")["components"]}
    assert marked["golang.org/x/crypto"] == {"go:sum": "h1:a=", "go:targets": "linux/amd64,linux/arm64"}, marked
    assert marked["golang.org/x/sys"] == {"go:sum": "h1:b=", "go:targets": "linux/amd64"}, marked
    assert marked["golang"] == {"go:targets": "linux/amd64,linux/arm64"}, marked
    assert sbom("1.2.3", union, "go1.27.4") == sbom("1.2.3", linked_union({"linux/amd64": info, "linux/arm64": fewer}), "go1.27.4")
    skewed = dict(info, Deps=[dict(info["Deps"][1], Sum="h1:other=")] + info["Deps"][:1])
    assert any("but" in problem for problem in module_problems({"a": info, "b": skewed}, vendored))
    bumped = dict(info, Deps=[dict(info["Deps"][0], Version="v0.51.0")])
    assert any("v0.50.0" in problem and "v0.51.0" in problem for problem in module_problems({"a": info, "b": bumped},
               dict(vendored, **{"golang.org/x/sys": "v0.51.0"})))
    assert any("does not list" in problem for problem in module_problems({"a": info}, {"golang.org/x/sys": "v0.50.0"}))
    assert module_problems({"a": dict(info, Deps=[])}, {}) == []              # main today: no dependency
    sums = go_sums("golang.org/x/sys v0.50.0 h1:b=\ngolang.org/x/sys v0.50.0/go.mod h1:m=\n")
    assert sums == {("golang.org/x/sys", "v0.50.0"): "h1:b="}, sums
    unsummed = {"a": dict(info, Deps=[dict(dep, Sum="") for dep in info["Deps"]])}   # what a -mod=vendor build records
    filled = with_sums(unsummed, sums)["a"]["Deps"]
    assert [dep["Sum"] for dep in filled] == ["h1:b=", ""], filled
    assert any("no go.sum hash" in problem and "x/crypto" in problem
               for problem in module_problems(with_sums(unsummed, sums), vendored))
    assert with_sums({"a": info}, {})["a"] == info                           # a recorded Sum is kept
    for good in ("0.66.0", "1.0.0-rc.1"):
        assert VERSION.match(good), good
    for bad in ("v0.66.0", "0.66", "1.0.0;rm", "../1.0.0"):
        assert not VERSION.match(bad), bad
    root = Path(tempfile.mkdtemp(prefix="build_go_release_selftest_"))
    try:
        assert tree_state(root)[0] == "skip"                                  # no Go engine on the commit at all
        (root / "go").mkdir()
        (root / "go" / "go.mod").write_text("module example.invalid/go\n", encoding="utf-8")
        state, why = tree_state(root)
        assert state == "fail" and "cmd/protodetect" in why, (state, why)    # go.mod without the main package
        (root / "go" / "cmd" / "protodetekt").mkdir(parents=True)            # a renamed main package still fails
        assert tree_state(root)[0] == "fail"
        (root / "go" / "cmd" / "protodetect").mkdir()
        assert tree_state(root) == ("build", "")
        (root / "a").write_bytes(b"same")
        (root / "b").write_bytes(b"same")
        (root / "c").write_bytes(b"diff")
        assert sha256(root / "a") == sha256(root / "b") != sha256(root / "c")
    finally:
        shutil.rmtree(str(root), ignore_errors=True)
    print("build_go_release self-test: ok (SBOM shape and reproducibility, per-target module union and go:targets, "
          "version and hash skew, go.sum hashes, vendor cross-check, version names, missing main package fails, "
          "no go.mod skips)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", help="the release version (pyproject.toml's, equal to the tag without its v)")
    parser.add_argument("--out", default="dist")
    parser.add_argument("--summary", help="append a markdown summary here (GITHUB_STEP_SUMMARY)")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.version or not VERSION.match(args.version):
        print("build_go_release: --version must be a release version such as 0.66.0, got {!r}".format(args.version), file=sys.stderr)
        return 2
    return run(args.version, args.out, args.summary)


if __name__ == "__main__":
    sys.exit(main())
