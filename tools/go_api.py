"""API compatibility of the Go engine module (the `go-api` ci job), with apidiff.

apidiff (golang.org/x/exp/cmd/apidiff, built by the job from tools/golint/apidiff/go.mod and go.sum) writes the
module's API as export data at the base and at this commit, both on the vendored tree with no module download,
and compares them.

  base    a pull request's base (BASE_SHA, the event's base.sha) merged-based with HEAD; on a push, HEAD's first
          parent. A base without go/go.mod has no API to compare: success, and the summary says so.
  public  the module's importable API: every package that is not internal and not a main package. An
          incompatible change there (a removed or changed exported identifier) fails the job, unless the pull
          request carries the `api-break` label (LABELS, the event's label names). The job then passes and says
          the break was accepted by label. ci also runs on `labeled` and `unlabeled`, so the label takes effect
          without a new push; a re-run would see the labels the pull request had when the run was created.
  internal  apidiff -allow-internal, reported in the summary only. The engine's packages are internal while
          the migration lasts, and changing their API is ordinary refactoring there, not a break for any
          importer.

Today the module has no public package: its only non-internal package is cmd/protodetect, a main package. So the
gating part compares nothing until a package is made importable. That is stated in the summary instead of
reported as a pass with findings.

    go_api.py --bin DIR [--summary FILE]      (env: BASE_SHA, LABELS)
    go_api.py --self-test
Standard library only; Python 3.9 syntax.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_ci  # noqa: E402  (the pinned Go, the vendor tree, the environment)

GO_ROOT = Path("go")
LABEL = "api-break"
MODULE = re.compile(r"^module\s+(\S+)", re.M)
SECTION = re.compile(r"^(Incompatible|Compatible) changes:\s*$")


def git(*args, check=True):
    result = subprocess.run(["git"] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)  # noqa: S603,S607
    if check and result.returncode:
        raise RuntimeError("git {} failed: {}".format(" ".join(args), result.stderr.decode("utf-8", "replace").strip()))
    return result.stdout.decode("utf-8", "replace").strip()


def labels_of(text):
    """The pull request's label names from LABELS (toJSON of the names; `null` on a push)."""
    try:
        value = json.loads(text or "null")
    except ValueError:
        return []
    return [str(item) for item in value] if isinstance(value, list) else []


def parse_report(text):
    """(incompatible, compatible) change lines of an apidiff report."""
    sections, current = {"Incompatible": [], "Compatible": []}, None
    for line in (text or "").splitlines():
        header = SECTION.match(line)
        if header:
            current = header.group(1)
        elif current and line.startswith("- "):
            sections[current].append(line[2:].strip())
    return sections["Incompatible"], sections["Compatible"]


def public_packages(listing):
    """Import paths of the importable packages: not internal, not main, from `go list -f '{{.ImportPath}} {{.Name}}'`."""
    packages = []
    for line in (listing or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] != "main" and not re.search(r"(^|/)internal(/|$)", parts[0]):
            packages.append(parts[0])
    return packages


def decide(public_incompatible, labels):
    """(failed, line) for the gating part."""
    if not public_incompatible:
        return False, "No incompatible change to the public API."
    if LABEL in labels:
        return False, "{} incompatible public API change(s), accepted by the `{}` label.".format(len(public_incompatible), LABEL)
    return True, "{} incompatible public API change(s); add the `{}` label if the break is intended.".format(len(public_incompatible), LABEL)


def export(tool, directory, module, out, env, internal):
    command = [tool, "-m", "-w", str(out), module]
    if internal:
        command.insert(1, "-allow-internal")
    result = subprocess.run(command, cwd=str(directory), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)  # noqa: S603
    if result.returncode:
        raise RuntimeError("apidiff could not export {} in {}: {}".format(module, directory, result.stdout.decode("utf-8", "replace").strip()[-400:]))


def export_packages(path):
    """The package entries of an `apidiff -m -w` export (a zip: a `module` entry, then one `<path>.x` per package)."""
    try:
        with zipfile.ZipFile(str(path)) as archive:
            return sorted(name[:-2] for name in archive.namelist() if name.endswith(".x"))
    except (OSError, zipfile.BadZipFile) as error:
        raise RuntimeError("apidiff export {} is unreadable: {}".format(path, error)) from error


def judge_report(returncode, stdout, stderr, old_packages, new_packages):
    """(incompatible, compatible, stderr) of one apidiff comparison, or RuntimeError: it never fails open (SEC-CI-A12-2).

    apidiff exits 0 after writing its report and 1 or 2 when it dies, so any other exit is a failure. An empty report
    is apidiff's "no change", except when the two exports hold different packages: a package added or removed is
    always reported, so an empty report then means a broken run. Text outside the report's sections is a failure too.
    """
    note = (stderr or "").strip()
    if returncode != 0:
        raise RuntimeError("apidiff exited {}: {}".format(returncode, note[-400:] or "(no stderr)"))
    incompatible, compatible = parse_report(stdout)
    if (stdout or "").strip() and not incompatible and not compatible:
        raise RuntimeError("apidiff printed no report section: {}".format(stdout.strip()[-400:]))
    if not incompatible and not compatible and sorted(old_packages) != sorted(new_packages):
        raise RuntimeError("apidiff reported nothing although the package set changed ({} -> {} package(s)){}".format(
            len(old_packages), len(new_packages), ": " + note[-400:] if note else ""))
    return incompatible, compatible, note


def stderr_lines(notes):
    """Summary lines for apidiff's stderr: its "Ignoring internal package" notices counted, anything else quoted."""
    ignored, other = set(), []
    for note in notes:
        for line in (note or "").splitlines():
            if line.startswith("Ignoring internal package "):
                ignored.add(line)
            elif line.strip() and line not in other:
                other.append(line)
    lines = ["", "apidiff skipped {} internal package(s) in the public comparison.".format(len(ignored))] if ignored else []
    return lines + (["", "apidiff stderr:"] + ["    " + line for line in other[-20:]] if other else [])


def compare(tool, old, new, internal):
    command = [tool, "-m", str(old), str(new)]
    if internal:
        command.insert(1, "-allow-internal")
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)  # noqa: S603
    return judge_report(result.returncode, result.stdout.decode("utf-8", "replace"), result.stderr.decode("utf-8", "replace"),
                        export_packages(old), export_packages(new))


def run(bin_dir, summary):
    title = "### Go API compatibility (apidiff)"
    tree, problems = go_ci.toolchain_problems()
    if tree is None:
        go_ci.summarise(summary, [title, "", "No {} on this commit: no API to compare.".format(go_ci.GO_MOD)])
        return 0
    if problems:
        go_ci.summarise(summary, [title, ""] + ["- FAILED: " + problem for problem in problems])
        return 1
    tool = str(Path(bin_dir).resolve() / "apidiff")
    module = MODULE.search(go_ci.read(go_ci.GO_MOD) or "")
    base_ref = os.environ.get("BASE_SHA") or "HEAD^1"
    try:
        base = git("merge-base", base_ref, "HEAD")
    except RuntimeError as error:
        go_ci.summarise(summary, [title, "", "- FAILED: no base to compare with ({})".format(error)])
        return 1
    if subprocess.run(["git", "cat-file", "-e", "{}:{}".format(base, go_ci.GO_MOD.as_posix())],  # noqa: S603,S607
                      stderr=subprocess.DEVNULL, check=False).returncode:
        go_ci.summarise(summary, [title, "", "Base {} has no {}: no earlier API to compare.".format(base[:12], go_ci.GO_MOD)])
        return 0
    env = go_ci.go_env(tree.get("vendored"))
    listing = subprocess.run(["go", "list", "-f", "{{.ImportPath}} {{.Name}}", "./..."], cwd=str(GO_ROOT), env=env,  # noqa: S603,S607
                             stdout=subprocess.PIPE, check=False).stdout.decode("utf-8", "replace")
    public = public_packages(listing)
    scratch = tempfile.mkdtemp(prefix="go-api-")
    worktree = Path(scratch, "base")
    try:
        git("worktree", "add", "--detach", str(worktree), base)
        base_env = go_ci.go_env((worktree / go_ci.VENDOR).is_file())
        base_module = MODULE.search((worktree / go_ci.GO_MOD).read_text(encoding="utf-8"))
        if not module or not base_module or base_module.group(1) != module.group(1):
            go_ci.summarise(summary, [title, "", "- FAILED: the module path changed ({} -> {}): every importer breaks".format(
                base_module.group(1) if base_module else None, module.group(1) if module else None)])
            return 1
        results = {}
        for internal in (False, True):
            old, new = Path(scratch, "old-{}.api".format(internal)), Path(scratch, "new-{}.api".format(internal))
            export(tool, worktree / GO_ROOT, module.group(1), old, base_env, internal)
            export(tool, GO_ROOT, module.group(1), new, env, internal)
            results[internal] = compare(tool, old, new, internal)
    except RuntimeError as error:
        go_ci.summarise(summary, [title, "", "- FAILED: {}".format(error)])
        return 1
    finally:
        git("worktree", "remove", "--force", str(worktree), check=False)
        shutil.rmtree(scratch, ignore_errors=True)
    failed, verdict = decide(results[False][0], labels_of(os.environ.get("LABELS")))
    lines = [title, "", "Base `{}`; public packages: {}.".format(base[:12], ", ".join("`{}`".format(p) for p in public) or
                                                               "none (cmd/protodetect is a main package; every other package is internal)"), ""]
    lines.append(("- FAILED: " if failed else "") + verdict)
    lines += ["  - {}".format(change) for change in results[False][0]]
    incompatible, compatible, _ = results[True]
    lines += ["", "Internal API (reported only): {} incompatible, {} compatible change(s).".format(len(incompatible), len(compatible))]
    lines += ["- incompatible: {}".format(change) for change in incompatible[:40]]
    lines += ["- compatible: {}".format(change) for change in compatible[:40]]
    lines += stderr_lines(results[internal][2] for internal in sorted(results))
    go_ci.summarise(summary, lines)
    return 1 if failed else 0


def self_test():
    report = ("Incompatible changes:\n- ./pkg.Old: removed\n- ./pkg.F: changed from func() to func(int)\n\n"
              "Compatible changes:\n- ./pkg.New: added\n")
    assert parse_report(report) == (["./pkg.Old: removed", "./pkg.F: changed from func() to func(int)"], ["./pkg.New: added"])
    assert parse_report("Compatible changes:\n- ./internal/content.CompareVersions: added\n") == ([], ["./internal/content.CompareVersions: added"])
    assert parse_report("") == ([], [])
    listing = ("example.com/m/go/cmd/protodetect main\nexample.com/m/go/internal/a a\nexample.com/m/go/pkg/api api\n"
               "example.com/m/go/pkg/internal/b b\nexample.com/m/go/internal internal\n")
    assert public_packages(listing) == ["example.com/m/go/pkg/api"], public_packages(listing)
    assert labels_of('["api-break", "docs"]') == ["api-break", "docs"] and labels_of("null") == [] and labels_of("") == []
    assert labels_of("not json") == []
    assert decide([], []) == (False, "No incompatible change to the public API.")
    failed, line = decide(["./pkg.Old: removed"], ["docs"])
    assert failed and "add the `api-break` label" in line
    failed, line = decide(["./pkg.Old: removed"], ["api-break"])
    assert not failed and "accepted by the `api-break` label" in line
    assert judge_report(0, report, "", ["m/a"], ["m/a"]) == (parse_report(report)[0], parse_report(report)[1], "")
    assert judge_report(0, "", "", ["m/a"], ["m/a"]) == ([], [], "")                       # no change: empty report
    assert judge_report(0, "", "Ignoring internal package m/x\n", ["m/a"], ["m/a"])[2] == "Ignoring internal package m/x"
    for label, args, expected in [
            ("crash", (1, "", "panic: runtime error\n", ["m/a"], ["m/a"]), "apidiff exited 1: panic: runtime error"),
            ("usage", (2, "", "", ["m/a"], ["m/a"]), "apidiff exited 2: (no stderr)"),
            ("killed", (-9, "", "", ["m/a"], ["m/a"]), "apidiff exited -9"),
            ("garbled", (0, "something else\n", "", ["m/a"], ["m/a"]), "printed no report section"),
            ("silent on a removed package", (0, "", "", ["m/a", "m/b"], ["m/a"]), "package set changed (2 -> 1"),
            ("silent on an added package", (0, "\n", "warn\n", ["m/a"], ["m/a", "m/c"]), "(1 -> 2 package(s)): warn")]:
        try:
            judge_report(*args)
        except RuntimeError as error:
            assert expected in str(error), (label, str(error))
        else:
            raise AssertionError("{}: apidiff failed open".format(label))
    assert stderr_lines(["Ignoring internal package m/a\nIgnoring internal package m/b", "Ignoring internal package m/a\nwarn: x"]) == [
        "", "apidiff skipped 2 internal package(s) in the public comparison.", "", "apidiff stderr:", "    warn: x"]
    assert stderr_lines(["", None]) == []
    scratch = tempfile.mkdtemp(prefix="go-api-self-test-")
    try:
        archive = Path(scratch, "x.api")
        with zipfile.ZipFile(str(archive), "w") as out:
            out.writestr("module", "m")
            out.writestr("m/b.x", "")
            out.writestr("m/a.x", "")
        assert export_packages(archive) == ["m/a", "m/b"]
        Path(scratch, "bad.api").write_bytes(b"not a zip")
        try:
            export_packages(Path(scratch, "bad.api"))
        except RuntimeError as error:
            assert "unreadable" in str(error)
        else:
            raise AssertionError("an unreadable export must fail")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    print("go_api self-test: ok (apidiff fails closed on exit code, garbled or silent reports; apidiff report parsing, public package selection, labels, gate decision)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bin", help="directory holding the pinned apidiff")
    parser.add_argument("--summary", help="append a markdown summary here (GITHUB_STEP_SUMMARY)")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.bin:
        parser.error("--bin is required")
    return run(args.bin, args.summary)


if __name__ == "__main__":
    sys.exit(main())
