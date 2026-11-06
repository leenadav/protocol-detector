"""Compare two engine snapshots on identical fixtures and validation outcomes.

No network traffic. Reports local Python feed-loop cost, not SWG latency.
Use --baseline /path/to/old/project (must contain protocol_engine).
"""
import argparse
import hashlib
import importlib.util
import json
import platform
import random
import statistics
import sys
import time
from dataclasses import asdict
from pathlib import Path
from protocol_demo import AMQP_091, AMQP_10, HTTP2, MQTT, RESP, SOCKS5
from proxy_demo import client_hello


def load_engine(root, name):
    package = root / "protocol_engine"
    spec = importlib.util.spec_from_file_location(name, package / "__init__.py",
                                                submodule_search_locations=[str(package)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    digest = hashlib.sha256()
    for path in sorted(package.glob("*.py")):
        digest.update(path.name.encode() + b"\x00" + path.read_bytes())
    return module, digest.hexdigest()


def distribution(samples):
    ordered = sorted(samples)
    return {"p50_us": round(statistics.median(ordered) / 1000, 3),
            "p95_us": round(ordered[int((len(ordered) - 1) * .95)] / 1000, 3),
            "p99_us": round(ordered[int((len(ordered) - 1) * .99)] / 1000, 3)}


def run(engine, chunks, expected, count):
    samples = []
    config, rules = engine.Config(), engine.RuleIndex()
    for _ in range(count):
        inspector = engine.Inspector(config, rules)
        start = time.perf_counter_ns()
        for chunk in chunks:
            inspector.feed(chunk)
        samples.append(time.perf_counter_ns() - start)
        result = inspector.observation
        if result.status != "identified" or (result.application_protocol or result.encryption) != expected:
            raise RuntimeError("Benchmark correctness assertion failed: " + repr(result))
    return samples, asdict(inspector.metrics)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--iterations", type=int, default=500, help="Samples per round")
    parser.add_argument("--rounds", type=int, default=5)
    args = parser.parse_args()
    if not 10 <= args.iterations <= 10000 or not 1 <= args.rounds <= 20:
        parser.error("Use 10..10000 iterations and 1..20 rounds")
    engines, hashes = {}, {}
    roots = {"current": Path(__file__).resolve().parent}
    if args.baseline:
        roots["baseline"] = args.baseline.resolve()
    for label, root in roots.items():
        engines[label], hashes[label] = load_engine(root, "bench_" + label)
    http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    long_http = http[:-2] + b"X-Padding: " + b"a" * 6000 + b"\r\n\r\n"
    hello = client_hello()
    split = lambda data, size: [data[i:i + size] for i in range(0, len(data), size)]
    cases = {"http_small": ([http], "http/1.1"),
             "http_fragmented": (split(long_http, 32), "http/1.1"),
             "tls_whole": ([hello], "tls"),
             "tls_fragmented": (split(hello, 32), "tls"),
             "http2_whole": ([HTTP2], "http/2"),
             "http2_fragmented": (split(HTTP2, 7), "http/2"),
             "socks5": ([SOCKS5], "socks5"),
             "smtp": ([b"EHLO client.example.com\r\n"], "smtp"),
             "ssh": ([b"SSH-2.0-Demo_1.0\r\n"], "ssh"),
             "http_after_identification": ([http] + [b"x" * 1024] * 64, "http/1.1")}
    new = {"mqtt": (split(MQTT, 7), "mqtt/3.1.1"), "resp": (split(RESP, 7), "resp"),
           "amqp_091": (split(AMQP_091, 7), "amqp/0-9-1"),
           "amqp_10": (split(AMQP_10, 7), "amqp/1.0")}
    result = {"environment": {"python": platform.python_version(), "platform": platform.platform(),
                               "iterations_per_round": args.iterations, "rounds": args.rounds,
                               "warmup_flows_per_case_version": 50, "order_seed": 402,
                               "gc": "enabled", "engine_sha256": hashes},
              "scope": "Feed loop including events; excludes Inspector construction, import, capture, TCP, TLS decryption, logging and concurrency",
              "cases": {}}
    rng = random.Random(402)
    for name, (chunks, expected) in {**cases, **new}.items():
        versions = ["current"] if name in new else list(engines)
        samples = {version: [] for version in versions}
        metrics = {}
        rounds = {version: [] for version in versions}
        for version in versions:
            run(engines[version], chunks, expected, 50)
        for _ in range(args.rounds):
            rng.shuffle(versions)
            for version in versions:
                times, metrics[version] = run(engines[version], chunks, expected, args.iterations)
                samples[version].extend(times)
                rounds[version].append(distribution(times)["p50_us"])
        row = {version: {"flow": distribution(samples[version]), "round_p50_us": rounds[version],
                         "metrics": metrics[version]} for version in versions}
        row["input_bytes"] = sum(map(len, chunks))
        row["chunks"] = len(chunks)
        if "baseline" in row:
            row["p50_change_percent"] = round((row["current"]["flow"]["p50_us"] /
                                              row["baseline"]["flow"]["p50_us"] - 1) * 100, 1)
        result["cases"][name] = row
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
