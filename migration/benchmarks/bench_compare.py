"""Migration M4/M9: Python and Go engine feed-loop cost on identical bytes, same host, alternating rounds.

    python3 -B migration/benchmarks/bench_compare.py --iterations 300 --rounds 5 --write migration/benchmarks/engine-go-vs-python-<head>.json

Writes migration/benchmarks/workloads.json (the exact chunks benchmark_engine.py uses for the workloads the Go
backend answers), builds the Go CLI once, then runs Python and Go rounds alternately (order seeded) so neither
side benefits from a quiet or a busy phase of the host. Reports distributions, allocation counts (Go) and the
ratio of medians. Relative results only: the plan sets no production target and this is not SWG latency.
"""
import argparse
import json
import os
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from protocol_engine import Config, Inspector, RuleIndex  # noqa: E402
from proxy_demo import client_hello  # noqa: E402


def workloads():
    http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    long_http = http[:-2] + b"X-Padding: " + b"a" * 6000 + b"\r\n\r\n"
    hello = client_hello()
    split = lambda data, size: [data[i:i + size] for i in range(0, len(data), size)]  # noqa: E731
    return [
        {"name": "http_small", "chunks": [http], "expected": "http/1.1"},
        {"name": "http_fragmented", "chunks": split(long_http, 32), "expected": "http/1.1"},
        {"name": "tls_whole", "chunks": [hello], "expected": "tls"},
        {"name": "tls_fragmented", "chunks": split(hello, 32), "expected": "tls"},
        {"name": "http_after_identification", "chunks": [http] + [b"x" * 1024] * 64, "expected": "http/1.1"},
    ]


def distribution(samples):
    ordered = sorted(samples)
    return {"p50_us": round(statistics.median(ordered) / 1000, 3),
            "p95_us": round(ordered[int((len(ordered) - 1) * .95)] / 1000, 3),
            "p99_us": round(ordered[int((len(ordered) - 1) * .99)] / 1000, 3)}


def python_round(chunks, expected, count):
    samples = []
    config, rules = Config(), RuleIndex()
    for _ in range(count):
        inspector = Inspector(config, rules)
        start = time.perf_counter_ns()
        for chunk in chunks:
            inspector.feed(chunk)
        samples.append(time.perf_counter_ns() - start)
        result = inspector.observation
        if result.status != "identified" or (result.application_protocol or result.encryption) != expected:
            raise RuntimeError("Python correctness assertion failed: " + repr(result))
    return samples


def go_round(binary, workloads_path, name, iterations):
    # Fixed argv: the binary this script built and literal flags; nothing from the environment or input is interpolated.
    out = subprocess.run([binary, "bench", "--workloads", str(workloads_path), "--iterations", str(iterations), "--rounds", "1",  # noqa: S603
                          "--warmup", "0", "--only", name], check=True, capture_output=True, text=True)
    return json.loads(out.stdout)["cases"][name]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--iterations", type=int, default=300)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--write", default=None)
    parser.add_argument("--head", default=None)
    args = parser.parse_args(argv)
    if not 10 <= args.iterations <= 10000 or not 1 <= args.rounds <= 20:
        parser.error("Use 10..10000 iterations and 1..20 rounds")
    loads = workloads()
    workloads_path = ROOT / "migration/benchmarks/workloads.json"
    workloads_path.write_text(json.dumps({"schema": 1, "source": "benchmark_engine.py workloads the Go backend answers",
                                          "workloads": [{"name": w["name"], "chunks": [c.hex() for c in w["chunks"]], "expected": w["expected"]}
                                                        for w in loads]}, indent=1) + "\n", encoding="utf-8")
    go_dir = ROOT / "go"
    toolchain = "go" + (go_dir / "go.mod").read_text().split("\ngo ", 1)[1].split("\n", 1)[0].strip()
    env = dict(os.environ, GOTOOLCHAIN=toolchain)
    go_binary = shutil.which("go")
    if go_binary is None:
        raise SystemExit("bench_compare: no `go` on PATH")
    scratch = os.environ.get("BENCH_SCRATCH") or tempfile.mkdtemp(prefix="protodetect-bench-")
    binary = Path(scratch) / "protodetect-bench"
    subprocess.run([go_binary, "build", "-o", str(binary), "./cmd/protodetect"], cwd=go_dir, check=True, env=env)  # noqa: S603  fixed argv
    go_version = subprocess.run([go_binary, "version"], cwd=go_dir, check=True, capture_output=True, text=True, env=env).stdout.strip()  # noqa: S603
    rng = random.Random(402)
    result = {"recorded": time.strftime("%Y-%m-%d"), "head": args.head, "host": platform.platform(), "cpu_count": os.cpu_count(),
              "python": platform.python_version(), "go": go_version, "iterations_per_round": args.iterations, "rounds": args.rounds,
              "warmup_flows": 50, "order": "python/go alternated per round, seed 402",
              "scope": "Engine feed loop including events; excludes Inspector construction, capture, TCP reassembly, output, concurrency; "
                       "Python with gc enabled, Go with default GC; not SWG latency",
              "cases": {}}
    for w in loads:
        chunks, expected, name = w["chunks"], w["expected"], w["name"]
        python_round(chunks, expected, 50)
        go_round(str(binary), workloads_path, name, 50)
        py_samples, py_rounds, go_rounds, go_allocs, go_bytes, go_metrics, go_dist_rounds = [], [], [], [], [], None, []
        for _ in range(args.rounds):
            order = ["python", "go"]
            rng.shuffle(order)
            for side in order:
                if side == "python":
                    times = python_round(chunks, expected, args.iterations)
                    py_samples.extend(times)
                    py_rounds.append(distribution(times)["p50_us"])
                else:
                    row = go_round(str(binary), workloads_path, name, args.iterations)
                    go_rounds.append(row["flow"]["p50_us"])
                    go_dist_rounds.append(row["flow"])
                    go_allocs.append(row["allocs_per_flow"])
                    go_bytes.append(row["alloc_bytes_per_flow"])
                    go_metrics = row["metrics"]
        py = distribution(py_samples)
        go = {"p50_us": round(statistics.median(go_rounds), 3),
              "p95_us": round(statistics.median(d["p95_us"] for d in go_dist_rounds), 3),
              "p99_us": round(statistics.median(d["p99_us"] for d in go_dist_rounds), 3)}
        result["cases"][name] = {"input_bytes": sum(map(len, chunks)), "chunks": len(chunks),
                                 "python": {"flow": py, "round_p50_us": py_rounds},
                                 "go": {"flow": go, "round_p50_us": go_rounds, "allocs_per_flow": round(statistics.median(go_allocs), 1),
                                        "alloc_bytes_per_flow": round(statistics.median(go_bytes), 1), "metrics": go_metrics},
                                 "python_over_go_p50": round(py["p50_us"] / go["p50_us"], 2) if go["p50_us"] else None}
    text = json.dumps(result, indent=1) + "\n"
    if args.write:
        Path(args.write).write_text(text, encoding="utf-8")
    for name, row in result["cases"].items():
        print("%-26s python p50 %9.3f us  go p50 %9.3f us  ratio %5.2fx  go allocs/flow %6.1f  go bytes/flow %8.1f" % (
            name, row["python"]["flow"]["p50_us"], row["go"]["flow"]["p50_us"], row["python_over_go_p50"] or 0,
            row["go"]["allocs_per_flow"], row["go"]["alloc_bytes_per_flow"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
