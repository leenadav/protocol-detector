"""Performance history (perf-history.yml): record each main run's measurements and flag regressions.

Measurements are the existing ones, nothing new is benchmarked:
  - tools/perf_profile.py (sections cpu, bytes, memory): CPU p50 per layer per flow (decode, engine, adapter
    path), tracemalloc bytes held per connection per state, and bytes-to-identification (median and maximum
    shortest identifying prefix over the labelled fixtures);
  - every Go `func BenchmarkXxx(*testing.B)` under go/ (none exists yet; the engine's allocation ceilings
    are the bench-gate tests inside `make go-check`), run with -benchmem: ns/op, B/op and allocs/op.

The store is this workflow's own artifacts: each run downloads the history (history.jsonl) of the newest
successful run of the same workflow on the same branch, appends its own record and uploads the result. No
branch, no commit, no cache entry is written; a run on a feature branch reads only that branch's runs.

Each metric is compared with the median of up to BASELINE_RUNS earlier records taken on the same Python
minor version (timings also on the same CPU model, since shared runners differ). Thresholds, per kind:
  bytes   (memory per connection, Go B/op)             fail above +10 %
  count   (bytes to identification, Go allocs/op)      fail above +10 %
  time    (CPU p50, Go ns/op; shared-runner noise)     warn above +30 %, fail above +100 %
A metric with no comparable baseline is recorded, not judged. Improvements are reported, never failed.
A failing run uploads nothing, so a regression never becomes the baseline; an intended change is accepted
with `--accept true` (the workflow's `accept_regression` dispatch input): reported, not failed, and recorded.

    perf_history.py measure --out FILE             run the measurements, write one record
    perf_history.py compare --current FILE --history FILE [--summary FILE]
    perf_history.py append --current FILE --history FILE --out FILE
    perf_history.py --self-test
Standard library only; Python 3.9 syntax.
"""
import argparse
import json
import os
import platform
import re
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_ci  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
BASELINE_RUNS = 5
KEEP = 400
THRESHOLDS = {"bytes": (None, 0.10), "count": (None, 0.10), "time": (0.30, 1.00)}   # (warn, fail) as a fraction
BENCH_FUNC = re.compile(r"^func\s+(Benchmark\w+)\s*\(\s*\w+\s+\*testing\.B\s*\)", re.M)
BENCH_LINE = re.compile(r"^(Benchmark\S+?)(?:-\d+)?\s+\d+\s+(.*)$")


def cpu_model():
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass   # no /proc on this host: fall back to what platform reports
    return platform.processor() or platform.machine()


def profile_metrics(report):
    """{name: {"value": float, "kind": str}} from a perf_profile.py JSON report."""
    metrics = {}
    for flow, layers in sorted((report.get("cpu") or {}).items()):
        for layer in ("decode", "engine", "adapter_path"):
            value = (layers.get(layer) or {}).get("p50_us")
            if isinstance(value, (int, float)):
                metrics["cpu.{}.{}.p50_us".format(flow, layer)] = {"value": float(value), "kind": "time"}
    for state, values in sorted((report.get("memory") or {}).items()):
        value = values.get("bytes_per_connection_held")
        if isinstance(value, (int, float)):
            metrics["memory.{}.bytes_per_connection".format(state)] = {"value": float(value), "kind": "bytes"}
    summary = (report.get("bytes_to_identification") or {}).get("summary") or {}
    for key in ("median_shortest_prefix", "max_shortest_prefix"):
        if isinstance(summary.get(key), (int, float)):
            metrics["bytes_to_identification.{}".format(key)] = {"value": float(summary[key]), "kind": "count"}
    return metrics


def go_bench_metrics(output):
    """{name: metric} from `go test -bench -benchmem` output (ns/op, B/op, allocs/op)."""
    metrics = {}
    for line in output.splitlines():
        match = BENCH_LINE.match(line.strip())
        if not match:
            continue
        fields = match.group(2).split()
        for value, unit in zip(fields[0::2], fields[1::2]):
            kind = {"ns/op": "time", "B/op": "bytes", "allocs/op": "count"}.get(unit)
            if kind:
                metrics["go.{}.{}".format(match.group(1), unit.replace("/", "_per_"))] = {"value": float(value), "kind": kind}
    return metrics


def go_bench_packages(root):
    packages = set()
    for directory, dirs, files in os.walk(str(root)):
        dirs[:] = [name for name in dirs if name not in ("vendor", "testdata") and not name.startswith(".")]
        for name in files:
            if name.endswith("_test.go") and BENCH_FUNC.search(Path(directory, name).read_text(encoding="utf-8", errors="replace")):
                packages.add("./" + Path(directory).relative_to(root).as_posix())
    return sorted(packages)


def measure(out):
    metrics = {}
    # PRO-403: tools/perf_profile.py measures the Python reference engine, so it runs only on a tree that still has
    # it (the tag python-final and earlier); on the Go-only tree the Go benchmarks below are the measurements.
    if (ROOT / "protocol_adapters").is_dir() and (ROOT / "protocol_engine").is_dir():
        with tempfile.TemporaryDirectory() as scratch:
            report_path = Path(scratch, "profile.json")
            subprocess.run([sys.executable, "-B", str(ROOT / "tools/perf_profile.py"), "--sections", "cpu,bytes,memory",  # noqa: S603
                            "--json", str(report_path)], check=True, stdout=subprocess.DEVNULL, cwd=str(ROOT))
            metrics = profile_metrics(json.loads(report_path.read_text(encoding="utf-8")))
    go_note = "no go/go.mod"
    if (ROOT / "go/go.mod").is_file():
        packages = go_bench_packages(ROOT / "go")
        go_note = "no Go benchmark function"
        if packages:
            tree, problems = go_ci.toolchain_problems()
            if problems:
                raise SystemExit("perf_history: " + "; ".join(problems))
            result = subprocess.run(["go", "test", "-run", "^$", "-bench", ".", "-benchmem", "-benchtime", "200x", "-count", "1"]  # noqa: S603,S607
                                    + packages, cwd=str(ROOT / "go"), env=go_ci.go_env(tree.get("vendored")),
                                    stdout=subprocess.PIPE, check=True)
            metrics.update(go_bench_metrics(result.stdout.decode("utf-8", "replace")))
            go_note = "{} package(s)".format(len(packages))
    record = {"commit": os.environ.get("GITHUB_SHA", ""), "run_id": os.environ.get("GITHUB_RUN_ID", ""),
              "ref": os.environ.get("GITHUB_REF", ""), "python": "{}.{}".format(*sys.version_info[:2]),
              "cpu": cpu_model(), "go_benchmarks": go_note, "metrics": metrics}
    Path(out).write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
    print("perf_history: {} metrics recorded (Go: {})".format(len(metrics), go_note))
    return 0


def read_history(path):
    records = []
    if path and Path(path).is_file():
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if isinstance(record, dict) and isinstance(record.get("metrics"), dict):
                    records.append(record)
    return records


def judge(current, history):
    """[(name, kind, baseline or None, value, change or None, verdict)], verdict in ok/improved/warn/fail/new."""
    rows = []
    for name, metric in sorted(current["metrics"].items()):
        kind, value = metric["kind"], metric["value"]
        comparable = [record for record in history if record.get("python") == current.get("python")
                      and (kind != "time" or record.get("cpu") == current.get("cpu"))
                      and name in record["metrics"]][-BASELINE_RUNS:]
        if not comparable:
            rows.append((name, kind, None, value, None, "new"))
            continue
        baseline = statistics.median(record["metrics"][name]["value"] for record in comparable)
        change = (value - baseline) / baseline if baseline else (0.0 if value == baseline else float("inf"))
        warn, fail = THRESHOLDS[kind]
        verdict = "fail" if change > fail else "warn" if warn is not None and change > warn else "improved" if change < 0 else "ok"
        rows.append((name, kind, baseline, value, change, verdict))
    return rows


def compare(current_path, history_path, summary, accept=False):
    current = json.loads(Path(current_path).read_text(encoding="utf-8"))
    rows = judge(current, read_history(history_path))
    counts = {verdict: sum(1 for row in rows if row[5] == verdict) for verdict in ("fail", "warn", "improved", "ok", "new")}
    lines = ["### Performance history", "",
             "Python {}, CPU {}; baseline: median of up to {} earlier comparable runs.".format(
                 current.get("python"), current.get("cpu"), BASELINE_RUNS),
             "Thresholds: bytes and counts fail above +10 %; timings warn above +30 % and fail above +100 %.", "",
             "{fail} fail, {warn} warn, {improved} improved, {ok} ok, {new} without a baseline".format(**counts), "",
             "| metric | kind | baseline | now | change | |", "|---|---|---|---|---|---|"]
    for name, kind, baseline, value, change, verdict in rows:
        lines.append("| `{}` | {} | {} | {:g} | {} | {} |".format(
            name, kind, "-" if baseline is None else "{:g}".format(baseline), value,
            "-" if change is None else "{:+.1%}".format(change), verdict))
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write("\n".join(lines) + "\n")
    print("\n".join(lines[:7]))
    for name, _, baseline, value, change, verdict in rows:
        if verdict in ("warn", "fail"):
            print("::{} title=performance regression::{} {:+.1%} ({:g} -> {:g})".format(
                "error" if verdict == "fail" else "warning", name, change, baseline, value))
    if counts["fail"] and accept:
        print("perf_history: {} regression(s) accepted by the run's accept_regression input; recorded as the new "
              "baseline".format(counts["fail"]))
        return 0
    return 1 if counts["fail"] else 0


def append(current_path, history_path, out):
    records = read_history(history_path) + [json.loads(Path(current_path).read_text(encoding="utf-8"))]
    Path(out).write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in records[-KEEP:]), encoding="utf-8")
    print("perf_history: {} record(s) in {}".format(min(len(records), KEEP), out))
    return 0


def self_test():
    report = {"cpu": {"http": {"decode": {"p50_us": 10.0}, "engine": {"p50_us": 20.0}, "adapter_path": {"p50_us": 100.0}}},
              "memory": {"syn_only": {"bytes_per_connection_held": 1000}},
              "bytes_to_identification": {"summary": {"median_shortest_prefix": 36, "max_shortest_prefix": 247}}}
    metrics = profile_metrics(report)
    assert set(metrics) == {"cpu.http.decode.p50_us", "cpu.http.engine.p50_us", "cpu.http.adapter_path.p50_us",
                            "memory.syn_only.bytes_per_connection", "bytes_to_identification.median_shortest_prefix",
                            "bytes_to_identification.max_shortest_prefix"}, metrics
    go = go_bench_metrics("goos: linux\nBenchmarkFeed-8   \t     200\t      5120 ns/op\t     768 B/op\t       9 allocs/op\nok x 1s\n")
    assert go == {"go.BenchmarkFeed.ns_per_op": {"value": 5120.0, "kind": "time"},
                  "go.BenchmarkFeed.B_per_op": {"value": 768.0, "kind": "bytes"},
                  "go.BenchmarkFeed.allocs_per_op": {"value": 9.0, "kind": "count"}}, go

    def record(memory=1000.0, cpu=100.0, python="3.13", model="X", count=247.0):
        return {"python": python, "cpu": model, "metrics": {
            "memory.a": {"value": memory, "kind": "bytes"}, "cpu.a": {"value": cpu, "kind": "time"},
            "count.a": {"value": count, "kind": "count"}}}
    history = [record(), record(memory=1010.0), record(memory=990.0, cpu=110.0)]

    def verdicts(current, past=None):
        return {row[0]: row[5] for row in judge(current, history if past is None else past)}
    assert verdicts(record()) == {"memory.a": "ok", "cpu.a": "ok", "count.a": "ok"}
    assert verdicts(record(memory=1120.0))["memory.a"] == "fail"           # +12 % bytes
    assert verdicts(record(memory=1090.0))["memory.a"] == "ok"             # +9 % bytes
    assert verdicts(record(cpu=140.0))["cpu.a"] == "warn"                  # +40 % time
    assert verdicts(record(cpu=210.0))["cpu.a"] == "fail"                  # +110 % time
    assert verdicts(record(cpu=60.0))["cpu.a"] == "improved"
    assert verdicts(record(count=280.0))["count.a"] == "fail"              # more bytes needed to identify
    assert verdicts(record(model="Y", cpu=500.0))["cpu.a"] == "new"        # another CPU: timings not compared
    assert verdicts(record(model="Y", memory=2000.0))["memory.a"] == "fail"  # bytes still compared
    assert set(verdicts(record(python="3.9")).values()) == {"new"}         # another Python: nothing comparable
    assert set(verdicts(record(), past=[]).values()) == {"new"}
    long_history = [record(memory=5000.0)] * 10 + [record()] * BASELINE_RUNS
    assert verdicts(record(), past=long_history)["memory.a"] == "ok"       # only the latest runs form the baseline
    with tempfile.TemporaryDirectory() as scratch:
        current, past, out = (Path(scratch, name) for name in ("current.json", "history.jsonl", "out.jsonl"))
        current.write_text(json.dumps(record(memory=1500.0)), encoding="utf-8")
        past.write_text("".join(json.dumps(item) + "\n" for item in history) + "not json\n", encoding="utf-8")
        codes = (compare(str(current), str(past), None), compare(str(current), str(past), None, accept=True),
                 compare(str(current), str(Path(scratch, "missing.jsonl")), None))   # the last: first run, recorded only
        assert codes == (1, 0, 0), codes
        written = append(str(current), str(past), str(out))
        assert written == 0, written
        assert len(read_history(str(out))) == 4
    print("perf_history self-test: ok (metric extraction, Go benchmarks, 12 verdict cases, compare and append)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", nargs="?", choices=("measure", "compare", "append"))
    parser.add_argument("--out")
    parser.add_argument("--current")
    parser.add_argument("--history")
    parser.add_argument("--summary")
    parser.add_argument("--accept", default="false", help="compare: `true` reports regressions without failing")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if args.action == "measure" and args.out:
        return measure(args.out)
    if args.accept not in ("true", "false"):
        print("perf_history: --accept must be true or false, got {!r}".format(args.accept), file=sys.stderr)
        return 2
    if args.action == "compare" and args.current:
        return compare(args.current, args.history, args.summary, args.accept == "true")
    if args.action == "append" and args.current and args.out:
        return append(args.current, args.history, args.out)
    print("perf_history: see --help for the arguments each action needs", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
