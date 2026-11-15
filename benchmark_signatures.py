"""Signature evaluation benchmark (stage 7, A11): compilation and runtime costs, separately, with memory.

Local CPU work only; not a production latency figure. Workloads per size (100, 1,000, 4,096 signatures):
    spread        signatures over three families, 60% indexable exact-host, the rest patterns/OR/negations
    one-family    every signature in the http family (the worst case for a per-family scan)
    prefilter     pattern signatures whose literal anchor is present but the pattern does not match
    nonmatch      contexts that hit nothing (the common case in production)
Each runtime figure is the per-lookup cost over `--lookups` lookups: p50/p99 in microseconds, plus the mean
number of candidates evaluated, for the indexed match and for the linear reference match.
"""
import argparse
import json
import platform
import random
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from protocol_engine import SignatureSet  # noqa: E402

SIZES = (100, 1000, 4096)
HOSTS = ["host-%05d.example" % i for i in range(5000)]


def exact(i, context="http-req-host-header"):
    return {"name": "exact-%05d" % i, "conditions": [{"context": context, "operator": "equal-to", "value": HOSTS[i % len(HOSTS)]}]}


def pattern(i, context="http-req-host-header"):
    return {"name": "pattern-%05d" % i, "conditions": [{"context": context, "operator": "pattern-match",
                                                        "pattern": "^svc-%05d\\.[a-z]+\\.example$" % i}]}


def negated(i):
    return {"name": "neg-%05d" % i, "conditions": [{"context": "http-req-host-header", "operator": "equal-to", "value": HOSTS[i % len(HOSTS)], "negate": True},
                                                   {"context": "http-req-uri-path", "operator": "pattern-match", "pattern": "^/api/v%d/" % (i % 9)}]}


def documents(kind, size, rng):
    out = []
    for i in range(size):
        if kind == "spread":
            context = ("http-req-host-header", "ssl-req-chello-sni", "dns-req-query-name")[i % 3]
            roll = rng.random()
            out.append(exact(i, context) if roll < 0.6 else pattern(i, context) if roll < 0.85 else negated(i))
        elif kind == "one-family":
            out.append(exact(i) if i % 2 else pattern(i))
        elif kind == "prefilter":
            out.append(pattern(i))
        else:
            out.append(exact(i))
    return out


def contexts_for(kind, size, rng):
    if kind == "prefilter":
        # The anchor literal of a random pattern is present, the pattern does not match (prefilter passes, regex fails).
        i = rng.randrange(size)
        return {"http-req-host-header": ("svc-%05d.9.example" % i).encode()}
    if kind == "nonmatch":
        return {"http-req-host-header": b"nobody.invalid", "http-req-uri-path": b"/"}
    if rng.random() < 0.5:
        return {"http-req-host-header": HOSTS[rng.randrange(size) % len(HOSTS)].encode(), "http-req-uri-path": b"/api/v3/x"}
    return {"ssl-req-chello-sni": HOSTS[rng.randrange(size) % len(HOSTS)].encode()}


def family_for(kind, contexts):
    return "tls" if "ssl-req-chello-sni" in contexts else "http"


def percentile(samples, q):
    ordered = sorted(samples)
    return ordered[min(len(ordered) - 1, int(q * (len(ordered) - 1)))]


def measure(kind, size, lookups, seed):
    rng = random.Random(seed)
    docs = documents(kind, size, rng)
    tracemalloc.start()
    started = time.perf_counter()
    signatures = SignatureSet(docs)
    compile_seconds = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    cases = [contexts_for(kind, size, rng) for _ in range(lookups)]
    results = {}
    for name, function in (("indexed", lambda f, c: signatures.match_counted(f, c)), ("linear", lambda f, c: (signatures.match_linear(f, c), len(signatures._by_family.get(f, ()))))):
        timings, evaluated, hits = [], [], 0
        for contexts in cases:
            family = family_for(kind, contexts)
            before = time.perf_counter_ns()
            found, count = function(family, contexts)
            timings.append((time.perf_counter_ns() - before) / 1000)
            evaluated.append(count)
            hits += found is not None
        results[name] = {"p50_us": round(percentile(timings, 0.5), 2), "p99_us": round(percentile(timings, 0.99), 2),
                         "mean_candidates": round(statistics.mean(evaluated), 1), "hits": hits}
    return {"workload": kind, "signatures": size, "compile_ms": round(compile_seconds * 1000, 1),
            "compile_peak_kib": round(peak / 1024), "indexed": signatures.stats["indexed"], "scanned": signatures.stats["scanned"],
            "runtime": results}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lookups", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=71)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    rows = [measure(kind, size, args.lookups, args.seed) for kind in ("spread", "one-family", "prefilter", "nonmatch") for size in SIZES]
    if args.json:
        print(json.dumps({"python": platform.python_version(), "machine": platform.machine(), "rows": rows}, indent=1))
        return 0
    print("Python %s on %s; %d lookups per cell; local CPU work, not a production figure" % (platform.python_version(), platform.machine(), args.lookups))
    print("| workload | signatures | compile ms | peak KiB | indexed/scanned | indexed p50/p99 us | candidates | linear p50/p99 us | candidates |")
    print("|---|---|---|---|---|---|---|---|---|")
    for row in rows:
        i, l = row["runtime"]["indexed"], row["runtime"]["linear"]
        print("| %s | %d | %.1f | %d | %d/%d | %.1f / %.1f | %.1f | %.1f / %.1f | %.1f |" % (
            row["workload"], row["signatures"], row["compile_ms"], row["compile_peak_kib"], row["indexed"], row["scanned"],
            i["p50_us"], i["p99_us"], i["mean_candidates"], l["p50_us"], l["p99_us"], l["mean_candidates"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
