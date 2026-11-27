"""Performance regression gate of the Go engine (the `go-bench` ci job), with benchstat.

Every existing Go benchmark under go/ (each `func BenchmarkXxx(b *testing.B)` in a non-vendored *_test.go) runs on
the pull request's head and on its merge base, and benchstat (golang.org/x/perf/cmd/benchstat, built by the job
from tools/golint/benchstat/go.mod and go.sum) compares the two. Nothing new is benchmarked here.

  head    HEAD_SHA (the event's pull_request.head.sha); on a push, schedule or dispatch, HEAD.
  base    `git merge-base BASE_SHA head` (BASE_SHA is the event's pull_request.base.sha); otherwise HEAD's first
          parent. A base without go/go.mod has nothing to compare: success, and the summary says so.
  scope   the job measures only when `git diff --name-only base head` touches go/, this tool or its benchstat
          module (tools/golint/benchstat/). Otherwise it reports that and passes. A diff git cannot produce
          measures (fail closed).
  method  each tree's test binaries are built once (`go test -c`, vendored, no module download), then run in
          COUNT interleaved rounds (base then head, head then base, ...) with -benchmem and -benchtime BENCHTIME,
          so slow drift of a shared runner hits both sides alike. benchstat compares each package's samples
          (median, Mann-Whitney U test, alpha 0.05).
  gate    on a hot-path benchmark (HOT: per-flow inspect, which runs the TLS, HTTP, SSH and unknown flows through
          the engine's parsers, whole and byte by byte, and the QUIC datagram assembler):
            - sec/op slower by more than TIME_LIMIT (+10 %) with p < ALPHA (0.05) fails;
            - allocs/op whose head median is above the base median fails, whatever p (allocation counts are
              deterministic, so any growth is real);
            - a HOT pattern that matches no benchmark at head fails: a renamed or deleted hot-path benchmark
              would otherwise switch the gate off. Moving HOT is a reviewed change to this file.
          Every other benchmark, B/op, improvements and benchmarks new at head are reported, never failed.
          A head test binary that does not build or a benchmark run that fails at head fails the job; the
          same at the base drops that package's comparison and says so.

    go_bench.py --bin DIR [--summary FILE]      (env: BASE_SHA, HEAD_SHA)
    go_bench.py --self-test
Standard library only; Python 3.9 syntax. SSDLC.md item 44 documents the thresholds.
"""
import argparse
import csv
import io
import os
import re
import shutil
import subprocess  # noqa: S404 - fixed argv, no shell
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_ci  # noqa: E402  (the pinned Go, the vendor tree, the environment)

GO_ROOT = Path("go")
COUNT = 6
BENCHTIME = "500ms"
TIME_LIMIT = 0.10
ALPHA = 0.05
SCOPE = ("go/", "tools/go_bench.py", "tools/golint/benchstat/")
# (package directory under go/, benchmark name pattern without the Benchmark prefix and the -GOMAXPROCS suffix)
HOT = (
    ("detector", re.compile(r"^Flow/")),            # per-flow inspect: NewFlow, both first flights, Close (tls, http, ssh, unknown)
    ("detector", re.compile(r"^FlowBytewise/")),    # the same flows fed one byte per Feed (the adversarial shape)
    ("internal/protocols/quicx", re.compile(r"^AssemblerDatagram/")),  # QUIC CRYPTO-frame datagram assembly
)
BENCH_FUNC = re.compile(r"^func\s+Benchmark\w*\s*\(\s*\w+\s+\*testing\.B\s*\)", re.M)
PROCS = re.compile(r"-\d+$")
P_VALUE = re.compile(r"p=([0-9.]+)")


def git(*args, check=True):
    result = subprocess.run(["git"] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)  # noqa: S603,S607
    if check and result.returncode:
        raise RuntimeError("git {} failed: {}".format(" ".join(args), result.stderr.decode("utf-8", "replace").strip()))
    return result.stdout.decode("utf-8", "replace").strip()


def in_scope(paths):
    """The changed paths that make the job measure (None, a diff git could not produce, means measure)."""
    if paths is None:
        return None
    return [path for path in paths if any(path == s or (s.endswith("/") and path.startswith(s)) for s in SCOPE)]


def bench_packages(go_dir):
    """Package directories under go_dir (posix, relative) whose non-vendored *_test.go files hold a benchmark."""
    found = set()
    for path in sorted(Path(go_dir).rglob("*_test.go")):
        relative = path.relative_to(go_dir)
        if relative.parts[0] in ("vendor", "testdata") or "testdata" in relative.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if BENCH_FUNC.search(text):
            found.add(relative.parent.as_posix())
    return sorted(found)


def short(name):
    return PROCS.sub("", name)


def parse_csv(text):
    """{unit: {name: (base, head, p)}} from `benchstat -format csv base=... head=...`. base or head is None when
    that side has no sample; p is None when benchstat gave none. Configuration lines and geomean rows are skipped."""
    tables, unit = {}, None
    for row in csv.reader(io.StringIO(text or "")):
        if not row or not any(cell.strip() for cell in row):
            unit = None
            continue
        if len(row) >= 7 and row[0] == "" and row[5] == "vs base" and row[1]:
            unit = row[1]
            tables.setdefault(unit, {})
            continue
        if unit is None or len(row) < 7 or not row[0] or row[0] == "geomean":
            continue
        match = P_VALUE.search(row[6])
        tables[unit][short(row[0])] = (number(row[1]), number(row[3]), float(match.group(1)) if match else None)
    return tables


def number(cell):
    try:
        return float(cell)
    except ValueError:
        return None


def is_hot(package, name):
    return any(package == hot_package and pattern.search(name) for hot_package, pattern in HOT)


def judge(package, tables):
    """[(name, hot, verdict, failed)] for one package's benchstat tables. verdict is one short sentence."""
    times, allocs = tables.get("sec/op", {}), tables.get("allocs/op", {})
    results = []
    for name in sorted(set(times) | set(allocs)):
        hot = is_hot(package, name)
        base, head, p = times.get(name, (None, None, None))
        base_allocs, head_allocs, _ = allocs.get(name, (None, None, None))
        if head is None and head_allocs is None:
            results.append((name, hot, "gone at head", False))
            continue
        if base is None and base_allocs is None:
            results.append((name, hot, "new at head: nothing to compare", False))
            continue
        problems, notes = [], []
        if base and head is not None:
            delta = head / base - 1
            significant = p is not None and p < ALPHA
            note = "sec/op {:+.2f} % ({})".format(100 * delta, "p={:.3f}".format(p) if p is not None else "no p")
            if delta > TIME_LIMIT + 1e-9 and significant:   # 1e-9: 1.10 / 1.0 - 1 is 0.10000000000000009
                problems.append(note + ", over +{:.0f} % with p < {}".format(100 * TIME_LIMIT, ALPHA))
            else:
                notes.append(note + ("" if significant else ", not significant"))
        if base_allocs is not None and head_allocs is not None:
            note = "allocs/op {:.0f} -> {:.0f}".format(base_allocs, head_allocs)
            (problems if head_allocs > base_allocs else notes).append(note)
        failed = hot and bool(problems)
        results.append((name, hot, "; ".join(problems + notes) or "no comparable sample", failed))
    return results


def missing_hot(head_names):
    """HOT patterns that match no benchmark at head ({package: [names]})."""
    return ["{} {}".format(package, pattern.pattern) for package, pattern in HOT
            if not any(pattern.search(name) for name in head_names.get(package, ()))]


def bench_names(output):
    """Benchmark names (no prefix, no -GOMAXPROCS suffix) in raw `go test -bench` output."""
    names = set()
    for line in (output or "").splitlines():
        if line.startswith("Benchmark") and len(line.split()) > 2:
            names.add(short(line.split()[0][len("Benchmark"):]))
    return names


def build(go_dir, package, out, env):
    result = subprocess.run(["go", "test", "-c", "-o", str(out), "./" + package], cwd=str(go_dir), env=env,  # noqa: S603,S607
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    return None if result.returncode == 0 else result.stdout.decode("utf-8", "replace").strip()[-600:]


def run_binary(binary, cwd, env):
    command = [str(binary), "-test.run", "^$", "-test.bench", ".", "-test.benchmem", "-test.count", "1",
               "-test.benchtime", BENCHTIME]
    result = subprocess.run(command, cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)  # noqa: S603
    text = result.stdout.decode("utf-8", "replace")
    return text, (None if result.returncode == 0 else text.strip()[-600:])


def measure(trees, scratch, rounds=COUNT):
    """{side: {package: raw output}} and problems {side: {package: why}} for trees {side: (go_dir, env)}."""
    binaries, outputs, problems = {}, {}, {}
    for side, (go_dir, env) in trees.items():
        binaries[side], outputs[side], problems[side] = {}, {}, {}
        for package in bench_packages(go_dir):
            binary = Path(scratch, "{}-{}.test".format(side, package.replace("/", "_")))
            why = build(go_dir, package, binary, env)
            if why:
                problems[side][package] = "the test binary does not build: " + why
            else:
                binaries[side][package] = binary
                outputs[side][package] = ""
    sides = list(trees)
    for number_ in range(rounds):
        for side in (sides if number_ % 2 == 0 else list(reversed(sides))):
            go_dir, env = trees[side]
            for package, binary in sorted(binaries[side].items()):
                if package in problems[side]:
                    continue
                text, why = run_binary(binary, Path(go_dir, package), env)
                if why:
                    problems[side][package] = "a benchmark run failed: " + why
                outputs[side][package] += text
    return outputs, problems


def benchstat(tool, base_file, head_file, csv_format):
    command = [tool] + (["-format", "csv"] if csv_format else []) + ["base=" + str(base_file), "head=" + str(head_file)]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)  # noqa: S603
    if result.returncode:
        raise RuntimeError("benchstat failed on {} and {}".format(base_file, head_file))
    return result.stdout.decode("utf-8", "replace")


def run(bin_dir, summary):
    title = "### Go benchmarks: head against its merge base (benchstat)"
    tree, problems = go_ci.toolchain_problems()
    if tree is None:
        go_ci.summarise(summary, [title, "", "No {} on this commit: no benchmark to run.".format(go_ci.GO_MOD)])
        return 0
    if problems:
        go_ci.summarise(summary, [title, ""] + ["- FAILED: " + problem for problem in problems])
        return 1
    tool = str(Path(bin_dir).resolve() / "benchstat")
    try:
        head = git("rev-parse", "--verify", (os.environ.get("HEAD_SHA") or "HEAD") + "^{commit}")
        base = git("merge-base", os.environ.get("BASE_SHA") or head + "^1", head)
    except RuntimeError as error:
        go_ci.summarise(summary, [title, "", "- FAILED: no head or base to compare ({})".format(error)])
        return 1
    diff = subprocess.run(["git", "diff", "--name-only", "--no-renames", "-z", base, head],  # noqa: S603,S607
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    paths = [p for p in diff.stdout.decode("utf-8", "surrogateescape").split("\0") if p] if diff.returncode == 0 else None
    scoped = in_scope(paths)
    header = "Head `{}`, merge base `{}`.".format(head[:12], base[:12])
    if scoped == []:
        go_ci.summarise(summary, [title, "", header, "", "No change under {}: nothing to measure.".format(", ".join(SCOPE))])
        return 0
    if subprocess.run(["git", "cat-file", "-e", "{}:{}".format(base, go_ci.GO_MOD.as_posix())],  # noqa: S603,S607
                      stderr=subprocess.DEVNULL, check=False).returncode:
        go_ci.summarise(summary, [title, "", header, "", "The base has no {}: nothing to compare.".format(go_ci.GO_MOD)])
        return 0
    scratch = tempfile.mkdtemp(prefix="go-bench-")
    worktrees = {"base": Path(scratch, "base"), "head": Path(scratch, "head")}
    try:
        trees = {}
        for side, commit in (("base", base), ("head", head)):
            git("worktree", "add", "--detach", str(worktrees[side]), commit)
            trees[side] = (worktrees[side] / GO_ROOT, go_ci.go_env((worktrees[side] / go_ci.VENDOR).is_file()))
        outputs, run_problems = measure(trees, scratch)
        failures, rows, texts = [], [], []
        failures += ["head {}: {}".format(package, why) for package, why in sorted(run_problems["head"].items())]
        notes = ["base {}: {}; not compared".format(package, why) for package, why in sorted(run_problems["base"].items())]
        head_names = {package: bench_names(text) for package, text in outputs["head"].items()}
        failures += ["hot-path benchmark missing at head: {} (HOT in tools/go_bench.py)".format(item)
                     for item in missing_hot(head_names)]
        for package in sorted(outputs["head"]):
            if package in run_problems["head"]:
                continue
            if package not in outputs["base"] or package in run_problems["base"]:
                rows += [(package, name, is_hot(package, name), "no base sample: nothing to compare", False)
                         for name in sorted(head_names[package])]
                continue
            files = {}
            for side in ("base", "head"):
                files[side] = Path(scratch, "{}-{}.txt".format(side, package.replace("/", "_")))
                files[side].write_text(outputs[side][package], encoding="utf-8")
            rows += [(package,) + result for result in judge(package, parse_csv(benchstat(tool, files["base"], files["head"], True)))]
            texts.append(benchstat(tool, files["base"], files["head"], False))
    except RuntimeError as error:
        go_ci.summarise(summary, [title, "", header, "", "- FAILED: {}".format(error)])
        return 1
    finally:
        for path in worktrees.values():
            git("worktree", "remove", "--force", str(path), check=False)
        shutil.rmtree(scratch, ignore_errors=True)
    failures += ["{} {}: {}".format(package, name, verdict) for package, name, _, verdict, failed in rows if failed]
    lines = [title, "", header, "{} interleaved rounds per side, -benchtime {}; a hot-path benchmark fails when sec/op is "
             "more than {:.0f} % slower with p < {}, or allocs/op grows.".format(COUNT, BENCHTIME, 100 * TIME_LIMIT, ALPHA), ""]
    lines += ["- FAILED: " + failure for failure in failures] or ["No hot-path regression."]
    lines += ["- note: " + note for note in notes]
    lines += ["", "| package | benchmark | hot | result |", "|---|---|---|---|"]
    lines += ["| {} | {} | {} | {}{} |".format(package, name, "yes" if hot else "", "**FAILED** " if failed else "", verdict)
              for package, name, hot, verdict, failed in rows]
    lines += ["", "<details><summary>benchstat</summary>", "", "```"] + "\n".join(texts).splitlines() + ["```", "</details>"]
    go_ci.summarise(summary, lines)
    print("\n".join(lines))
    return 1 if failures else 0


SAMPLE_CSV = """goos: linux
goarch: amd64
pkg: example.com/m/go/detector
cpu: Example CPU
,base,,head,,,
,sec/op,CI,sec/op,CI,vs base,P
Flow/tls-4,1.0e-05,2%,1.2e-05,3%,+20.00%,p=0.002 n=6
Flow/http-4,1.0e-05,2%,1.2e-05,30%,~,p=0.180 n=6
Flow/ssh-4,1.0e-05,2%,1.05e-05,1%,+5.00%,p=0.002 n=6
FlowBytewise/tls-4,2.0e-04,2%,1.0e-04,1%,-50.00%,p=0.002 n=6
Other/x-4,1.0e-06,2%,2.0e-06,1%,+100.00%,p=0.002 n=6
Flow/new-4,,,1.0e-06,1%,,
geomean,1.0e-05,,1.1e-05,,+10.00%,

,base,,head,,,
,allocs/op,CI,allocs/op,CI,vs base,P
Flow/tls-4,89,0%,89,0%,~,p=1.000 n=6
Flow/http-4,76,0%,76,0%,~,p=1.000 n=6
Flow/ssh-4,53,0%,54,0%,+1.89%,p=0.002 n=6
FlowBytewise/tls-4,500,0%,400,0%,-20.00%,p=0.002 n=6
Other/x-4,1,0%,9,0%,+800.00%,p=0.002 n=6
Flow/new-4,,,3,0%,,
geomean,1,,1,,+0.00%,
"""


def self_test():
    tables = parse_csv(SAMPLE_CSV)
    assert set(tables) == {"sec/op", "allocs/op"}, tables
    assert tables["sec/op"]["Flow/tls"] == (1.0e-05, 1.2e-05, 0.002), tables["sec/op"]["Flow/tls"]
    assert tables["sec/op"]["Flow/new"] == (None, 1.0e-06, None) and "geomean" not in tables["sec/op"]
    verdicts = {name: (hot, verdict, failed) for name, hot, verdict, failed in judge("detector", tables)}
    assert verdicts["Flow/tls"][2] and "over +10 %" in verdicts["Flow/tls"][1], verdicts["Flow/tls"]   # +20 %, p=0.002
    assert not verdicts["Flow/http"][2] and "not significant" in verdicts["Flow/http"][1]               # +20 %, p=0.18
    assert verdicts["Flow/ssh"][2] and "allocs/op 53 -> 54" in verdicts["Flow/ssh"][1]                   # +5 % time, +1 alloc
    assert not verdicts["FlowBytewise/tls"][2]                                                          # faster, fewer allocs
    assert verdicts["Other/x"][0] is False and not verdicts["Other/x"][2]                               # not hot: reported
    assert not verdicts["Flow/new"][2] and verdicts["Flow/new"][1].startswith("new at head")
    gone = judge("detector", {"sec/op": {"Flow/tls": (1.0, None, None)}})
    assert gone == [("Flow/tls", True, "gone at head", False)], gone
    # exactly at the limit is not over it; just above with p just under alpha fails
    edge = judge("detector", {"sec/op": {"Flow/a": (1.0, 1.10, 0.01), "Flow/b": (1.0, 1.1001, 0.049), "Flow/c": (1.0, 1.5, 0.05)}})
    assert [failed for *_, failed in edge] == [False, True, False], edge
    assert is_hot("internal/protocols/quicx", "AssemblerDatagram/held1024") and not is_hot("detector", "AssemblerDatagram/x")
    assert not is_hot("internal/signatures", "HostileDocumentLoad/set-873")
    raw = ("goos: linux\nBenchmarkFlow/tls-4   \t 100\t 10 ns/op\nBenchmarkFlowBytewise/ssh-16 \t 5\t 9 ns/op\nPASS\n"
           "BenchmarkAssemblerDatagram/empty-4 \t 1\t 2 ns/op\n")
    assert bench_names(raw) == {"Flow/tls", "FlowBytewise/ssh", "AssemblerDatagram/empty"}, bench_names(raw)
    assert missing_hot({"detector": bench_names(raw), "internal/protocols/quicx": {"AssemblerDatagram/empty"}}) == []
    assert missing_hot({"detector": {"Flow/tls"}}) == ["detector ^FlowBytewise/", "internal/protocols/quicx ^AssemblerDatagram/"]
    assert short("HostileDocumentLoad/set-873-4") == "HostileDocumentLoad/set-873"
    assert in_scope(["README.md", "go/detector/engine.go"]) == ["go/detector/engine.go"]
    assert in_scope(["tools/golint/benchstat/go.sum", "tools/go_bench.py", "tools/go_api.py", "gopher/x"]) == \
        ["tools/golint/benchstat/go.sum", "tools/go_bench.py"]
    assert in_scope(["docs/a.md", "tools/go_ci.py"]) == [] and in_scope(None) is None
    with tempfile.TemporaryDirectory() as directory:
        for relative, text in {"detector/bench_test.go": "func BenchmarkFlow(b *testing.B) {}\n",
                               "detector/other_test.go": "func TestX(t *testing.T) {}\n",
                               "internal/a/a_test.go": "func helper(b *testing.B) {}\n",
                               "internal/b/b_test.go": "func Benchmark(b *testing.B) {}\n",
                               "vendor/x/y_test.go": "func BenchmarkV(b *testing.B) {}\n",
                               "internal/c/testdata/z_test.go": "func BenchmarkT(b *testing.B) {}\n"}.items():
            Path(directory, relative).parent.mkdir(parents=True, exist_ok=True)
            Path(directory, relative).write_text("package p\n\n" + text, encoding="utf-8")
        assert bench_packages(directory) == ["detector", "internal/b"], bench_packages(directory)
    print("go_bench self-test: ok (benchstat CSV parsing, the +10 %/p<0.05 and allocs/op rules, hot-path selection "
          "and presence, scope, benchmark discovery)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bin", help="directory holding the pinned benchstat")
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
