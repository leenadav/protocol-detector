"""The per-push Go fuzz smoke (`make go-check-fuzz`), optionally one shard of it.

The Makefile's GO_FUZZ_SMOKE lists each target as `<package>:<FuzzTarget>:<seconds>`; this runs every listed
target with `go test <package> -run NONE -fuzz ^<FuzzTarget>$ -fuzztime <seconds>s` in go/, on the Go that
GO_TOOLCHAIN names and the vendored tree, and keeps going after a failure so one run names every failing target.
`--shard I/N` runs only shard I of N: the targets are split by a fixed rule (longest first, each to the shard with
the least work so far, ties to the lower shard; a target's work is its seconds plus a fixed build allowance), so the
N shards of one list are disjoint, together run every target, and do not change between runs. CI runs the shards as
a matrix (ci.yml `go-fuzz-smoke`); `make go-check` runs the default 1/1, the whole list.

A listed target that no `_test.go` under go/ defines fails: `go test -fuzz` with no match fuzzes nothing and exits 0.
A defined target missing from the list is named in the output, so it can be added; the nightly job
(tools/go_fuzz_long.py) fuzzes every defined target either way.

    go_fuzz_smoke.py --toolchain goX.Y.Z [--shard I/N] [--summary FILE] ENTRY...
    go_fuzz_smoke.py --check-matrix .github/workflows/ci.yml
                     the go-fuzz-smoke job's `shard:` matrix must be exactly "1/N" .. "N/N" (a missing shard would
                     leave its targets unfuzzed and every job green); make workflow-policy and the workflow-lint
                     job run it
    go_fuzz_smoke.py --self-test
Standard library only; Python 3.9 syntax.
"""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_fuzz_long  # noqa: E402  (one discovery of the fuzz targets under go/)

GO_ROOT = Path("go")
ENTRY = re.compile(r"^(\./[A-Za-z0-9_][A-Za-z0-9_./-]*):(Fuzz[A-Za-z0-9_]+):([1-9][0-9]{0,2})$")
SHARD = re.compile(r"^([1-9][0-9]?)/([1-9][0-9]?)$")
TOOLCHAIN = re.compile(r"^go\d+\.\d+(?:\.\d+)?$")
BUILD_ALLOWANCE = 8     # seconds per target for building the instrumented test binary and starting the workers
MAX_SECONDS = 300       # one smoke target; the nightly job is where targets fuzz for minutes
MAX_SHARDS = 16


def parse_entries(raw):
    """[(package, target, seconds)] in list order, or ValueError naming the first bad or repeated entry."""
    entries, seen = [], set()
    for text in raw:
        match = ENTRY.match(text)
        if not match or ".." in match.group(1).split("/"):
            raise ValueError("bad GO_FUZZ_SMOKE entry {!r}: want ./<package>:Fuzz<Name>:<seconds>".format(text))
        package, target, seconds = match.group(1), match.group(2), int(match.group(3))
        if seconds > MAX_SECONDS:
            raise ValueError("GO_FUZZ_SMOKE entry {!r} fuzzes {} s: at most {} s per smoke target".format(text, seconds, MAX_SECONDS))
        if (package, target) in seen:
            raise ValueError("GO_FUZZ_SMOKE lists {}:{} twice".format(package, target))
        seen.add((package, target))
        entries.append((package, target, seconds))
    if not entries:
        raise ValueError("GO_FUZZ_SMOKE lists no target")
    return entries


def parse_shard(text):
    """(index, count) from "I/N" with 1 <= I <= N <= MAX_SHARDS, or ValueError."""
    match = SHARD.match(text or "")
    if not match:
        raise ValueError("bad shard {!r}: want I/N".format(text))
    index, count = int(match.group(1)), int(match.group(2))
    if not 1 <= index <= count <= MAX_SHARDS:
        raise ValueError("bad shard {!r}: want 1 <= I <= N <= {}".format(text, MAX_SHARDS))
    return index, count


def assign(entries, count):
    """count lists of entries: longest first, each to the least-loaded shard (lowest index on a tie)."""
    shards, loads = [[] for _ in range(count)], [0] * count
    order = sorted(range(len(entries)), key=lambda i: (-entries[i][2], i))
    for i in order:
        shard = min(range(count), key=lambda s: (loads[s], s))
        shards[shard].append(entries[i])
        loads[shard] += entries[i][2] + BUILD_ALLOWANCE
    position = {entry: i for i, entry in enumerate(entries)}
    return [sorted(shard, key=position.get) for shard in shards]


def coverage(entries, defined):
    """(listed but not defined, defined but not listed), each sorted [(package, target)]."""
    listed = {(package, target) for package, target, _ in entries}
    return sorted(listed - set(defined)), sorted(set(defined) - listed)


MATRIX_JOB = "go-fuzz-smoke"
JOB_LINE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
SHARD_LINE = re.compile(r"^\s+shard:\s*\[(.*)\]\s*$")


def matrix_problems(text):
    """Problems with the go-fuzz-smoke job's shard matrix in a ci.yml text; [] when it is "1/N" .. "N/N"."""
    block, inside = [], False
    for line in (text or "").splitlines():
        job = JOB_LINE.match(line)
        if job:
            inside = job.group(1) == MATRIX_JOB
            continue
        if inside and line.strip() and not line.startswith(" "):
            break
        if inside:
            block.append(line)
    if not block:
        return ["ci.yml has no `{}` job".format(MATRIX_JOB)]
    rows = [match.group(1) for match in map(SHARD_LINE.match, block) if match]
    if len(rows) != 1:
        return ["the `{}` job needs exactly one one-line `shard: [...]` matrix, found {}".format(MATRIX_JOB, len(rows))]
    values = [value.strip().strip("\"'") for value in rows[0].split(",") if value.strip()]
    try:
        shards = [parse_shard(value) for value in values]
    except ValueError as error:
        return ["the `{}` matrix: {}".format(MATRIX_JOB, error)]
    count = shards[0][1] if shards else 0
    wanted = [(index, count) for index in range(1, count + 1)]
    if not shards or shards != wanted:
        return ["the `{}` matrix is {}: it must list every shard once, in order, \"1/N\" .. \"N/N\"".format(
            MATRIX_JOB, values)]
    return []


def write(summary, lines):
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)


def run(toolchain, shard, raw, summary, root=GO_ROOT):
    index, count = shard
    title = "### Go fuzz smoke, shard {} of {}".format(index, count)
    entries = parse_entries(raw)
    undefined, unlisted = coverage(entries, go_fuzz_long.discover(root))
    if undefined:
        write(summary, [title, ""] + ["- FAILED: GO_FUZZ_SMOKE lists {}:{} but no _test.go under {} defines it "
                                      "(go test -fuzz would fuzz nothing)".format(p, t, root) for p, t in undefined])
        return 1
    mine = assign(entries, count)[index - 1]
    env = dict(os.environ, GOTOOLCHAIN=toolchain, GOFLAGS="-mod=vendor")
    lines = [title, "", "{} of {} targets, {} s of fuzzing, on {}".format(
        len(mine), len(entries), sum(seconds for _, _, seconds in mine), toolchain), "",
        "| package | target | seconds | result |", "|---|---|---|---|"]
    failed = 0
    for package, target, seconds in mine:
        command = ["go", "test", package, "-run", "NONE", "-fuzz", "^{}$".format(target), "-fuzztime", "{}s".format(seconds)]
        print("+ (cd {}) {}".format(root, " ".join(command)), flush=True)
        code = subprocess.run(command, cwd=str(root), env=env, check=False).returncode  # noqa: S603,S607
        failed += code != 0
        lines.append("| `{}` | `{}` | {} | {} |".format(package, target, seconds, "ok" if code == 0 else "FAILED (exit {})".format(code)))
    lines.append("")
    lines.append("{} of {} targets failed".format(failed, len(mine)) if failed else "all {} targets ok".format(len(mine)))
    lines += ["- not in GO_FUZZ_SMOKE (fuzzed nightly only): `{}:{}`".format(p, t) for p, t in unlisted]
    write(summary, lines)
    return 1 if failed else 0


def self_test():
    entries = parse_entries(["./a:FuzzA:20", "./a:FuzzB:10", "./b/c:FuzzC:15", "./d:FuzzD:10", "./e:FuzzE:5"])
    assert entries[2] == ("./b/c", "FuzzC", 15)
    for bad in ("a:FuzzA:10", "./a:TestA:10", "./a:FuzzA:0", "./a:FuzzA:10s", "./../x:FuzzA:10", "./a/../b:FuzzA:10",
                "./a:FuzzA", "./a:FuzzA:301", "./a;rm:FuzzA:10", ""):
        try:
            parse_entries([bad])
        except ValueError:
            continue
        raise AssertionError("entry {!r} accepted".format(bad))
    for bad in (["./a:FuzzA:10", "./a:FuzzA:20"], []):
        try:
            parse_entries(bad)
        except ValueError:
            continue
        raise AssertionError("list {!r} accepted".format(bad))
    assert parse_shard("1/1") == (1, 1) and parse_shard("3/3") == (3, 3)
    for bad in ("0/3", "4/3", "1/17", "1/0", "a/b", "1/3 ", "", "1-3", "01/3"):
        try:
            parse_shard(bad)
        except ValueError:
            continue
        raise AssertionError("shard {!r} accepted".format(bad))
    # every shard count: disjoint, complete, list order kept inside a shard, and the same answer twice
    for count in range(1, 8):
        shards = assign(entries, count)
        flat = [entry for shard in shards for entry in shard]
        assert sorted(flat) == sorted(entries) and len(flat) == len(entries), count
        assert all(shard == sorted(shard, key=entries.index) for shard in shards), count
        assert shards == assign(entries, count), count
    assert assign(entries, 1) == [entries]
    # longest first to the least-loaded shard: 20 | 15 | 10, then 10 and 5 fill the two lightest
    assert assign(entries, 3) == [[("./a", "FuzzA", 20)], [("./b/c", "FuzzC", 15), ("./e", "FuzzE", 5)],
                                  [("./a", "FuzzB", 10), ("./d", "FuzzD", 10)]], assign(entries, 3)
    # balance on the real-sized case: 28 targets of mostly 10 s in 3 shards stay within one target of each other
    real = parse_entries(["./p{}:FuzzT{}:{}".format(i, i, 20 if i == 3 else 15 if i == 5 else 5 if i == 8 else 10) for i in range(28)])
    loads = [sum(s + BUILD_ALLOWANCE for _, _, s in shard) for shard in assign(real, 3)]
    assert max(loads) - min(loads) <= 20 + BUILD_ALLOWANCE, loads
    job = "jobs:\n  {}:\n    strategy:\n      matrix:\n        shard: [{}]\n    steps: []\n  next:\n    steps: []\n"
    assert matrix_problems(job.format(MATRIX_JOB, '"1/3", "2/3", "3/3"')) == []
    assert matrix_problems(job.format(MATRIX_JOB, '"1/1"')) == []
    for label, values in {"missing shard": '"1/3", "3/3"', "extra shard": '"1/2", "2/2", "3/2"',
                          "mixed counts": '"1/3", "2/2", "3/3"', "repeated": '"1/2", "1/2"', "out of order": '"2/2", "1/2"',
                          "bad value": '"1/3", "2-3", "3/3"', "empty": ""}.items():
        assert matrix_problems(job.format(MATRIX_JOB, values)), label
    assert matrix_problems(job.format("go-fuzz", '"1/1"')) == ["ci.yml has no `go-fuzz-smoke` job"]
    assert matrix_problems(job.format(MATRIX_JOB, '"1/1"').replace("        shard", "        other")), "no shard row"
    assert matrix_problems(job.format(MATRIX_JOB, '"1/1"') + "  x:\n    shard: [\"1/2\"]\n") == []   # other jobs ignored
    undefined, unlisted = coverage(entries, [("./a", "FuzzA"), ("./a", "FuzzB"), ("./b/c", "FuzzC"), ("./d", "FuzzD"), ("./x", "FuzzX")])
    assert undefined == [("./e", "FuzzE")] and unlisted == [("./x", "FuzzX")], (undefined, unlisted)
    assert TOOLCHAIN.match("go1.27.4") and not TOOLCHAIN.match("1.27.4") and not TOOLCHAIN.match("go1.27.4;x")
    print("go_fuzz_smoke self-test: ok (entry and shard validation, disjoint complete stable shards, balance, coverage, 9 matrix refusals)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("entries", nargs="*", help="GO_FUZZ_SMOKE entries, ./<package>:Fuzz<Name>:<seconds>")
    parser.add_argument("--toolchain", help="the GO_TOOLCHAIN the targets run on, e.g. go1.27.4")
    parser.add_argument("--shard", default="1/1", help="run only shard I of N (default 1/1, every target)")
    parser.add_argument("--summary", help="append a markdown summary here (GITHUB_STEP_SUMMARY)")
    parser.add_argument("--check-matrix", metavar="CI_YML", help="check the go-fuzz-smoke shard matrix in this workflow")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.check_matrix:
        found = matrix_problems(Path(args.check_matrix).read_text(encoding="utf-8"))
        for problem in found:
            print("fuzz smoke matrix:", problem)
        if not found:
            print("fuzz smoke matrix: ok")
        return 1 if found else 0
    if not TOOLCHAIN.match(args.toolchain or ""):
        parser.error("--toolchain must name one Go release, e.g. go1.27.4")
    try:
        shard = parse_shard(args.shard)
        return run(args.toolchain, shard, args.entries, args.summary)
    except ValueError as error:
        write(args.summary, ["### Go fuzz smoke", "", "- FAILED: {}".format(error)])
        return 1


if __name__ == "__main__":
    sys.exit(main())
