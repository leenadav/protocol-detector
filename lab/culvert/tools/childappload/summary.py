"""Benchstat-style summary of the PRO-516 child-app load test (run.py output).

For every protocol, rate and metric: the off and on medians over the repetitions with the largest deviation from the
median in percent ("± x%", as benchstat prints it), the change of the medians, and the range of the per-repetition
paired differences (on minus off, repetition by repetition). A change is printed as "~" when the off and on ranges
overlap, the way benchstat marks a difference that the samples do not support.

Usage: python3 summary.py results.json > summary.md
       python3 summary.py --self-test
"""
import json
import statistics
import sys

METRICS = [
    ("p50_us", "p50 latency (µs)", 0),
    ("p95_us", "p95 latency (µs)", 0),
    ("p99_us", "p99 latency (µs)", 0),
    ("throughput", "throughput (req/s)", 1),
    ("cpu_us_per_req", "proxy CPU per request (µs)", 1),
    ("allocs_per_req", "heap allocations per request", 1),
    ("alloc_bytes_per_req", "heap bytes per request", 0),
    ("gc_per_1k", "GC cycles per 1,000 requests", 2),
    ("peak_rss_mib", "peak RSS (MiB)", 1),
]


def value(r, key):
    if key == "gc_per_1k":
        return r["gc_cycles"] * 1000.0 / r["requests"]
    return r[key]


def fmt(x, nd):
    return ("{:,.%df}" % nd).format(x)


def cell(vals, nd):
    m = statistics.median(vals)
    dev = max(abs(v - m) for v in vals) / abs(m) * 100 if m else 0.0
    return "%s ± %.0f%%" % (fmt(m, nd), dev), m


def summarize(results):
    out = []
    protos = sorted({r["proto"] for r in results})
    rates = sorted({r["rate"] for r in results})
    for proto in protos:
        out.append("### %s\n" % ("HTTP/1.1 (runH1InspectLoop)" if proto == "h1" else "HTTP/2 (handleInspectH2)"))
        out.append("| Rate | Metric | off | on | change of medians | paired on − off, range | n |")
        out.append("|---:|---|---:|---:|---:|---:|---:|")
        for rate in rates:
            cell_rows = [r for r in results if r["proto"] == proto and r["rate"] == rate]
            off = {r["rep"]: r for r in cell_rows if r["arm"] == "off"}
            on = {r["rep"]: r for r in cell_rows if r["arm"] == "on"}
            reps = sorted(set(off) & set(on))
            if not reps:
                continue
            for key, label, nd in METRICS:
                a = [value(off[i], key) for i in reps]
                b = [value(on[i], key) for i in reps]
                ca, ma = cell(a, nd)
                cb, mb = cell(b, nd)
                diffs = [y - x for x, y in zip(a, b)]
                overlap = max(a) >= min(b) and max(b) >= min(a)
                pct = (mb - ma) / ma * 100 if ma else 0.0
                change = "~" if overlap else "%+.1f%%" % pct
                change = "%s (%s%s)" % (change, "+" if mb >= ma else "−", fmt(abs(mb - ma), nd))
                rng = "%s .. %s" % (fmt(min(diffs), nd), fmt(max(diffs), nd))
                out.append("| %d | %s | %s | %s | %s | %s | %d |" % (rate, label, ca, cb, change, rng, len(reps)))
        out.append("")
    # Every request sent must be classified once: pd requests = requests + the 5 s warm-up at 100 req/s (500) +
    # requests Go's transport re-sent on a fresh tunnel after a reused one closed (vegeta counts those once).
    ons = [r for r in results if r["arm"] == "on"]
    excess = [r["pd_requests"] - r["requests"] - 500 for r in ons]
    out.append("Classification check: %d on-steps; pd requests minus (requests sent + 500 warm-up) ranges %d .. %d "
               "(a negative value would be an unclassified request)." % (len(ons), min(excess), max(excess)))
    for arm in ("off", "on"):
        rows = [r for r in results if r["arm"] == arm]
        failed = [(r["proto"], r["rate"], r["rep"], r["requests"] - r["status_codes"].get("200", 0), r["errors"])
                  for r in rows if r["status_codes"].get("200", 0) != r["requests"]]
        out.append("%s: %d steps, %d requests, %d not 200%s." % (
            arm, len(rows), sum(r["requests"] for r in rows), sum(f[3] for f in failed),
            "".join("; %s %d/s rep %d: %d (%s)" % (f[0], f[1], f[2], f[3], "; ".join(f[4])) for f in failed)))
    out.append("pd requests on off-steps: %d." % sum(r["pd_requests"] for r in results if r["arm"] == "off"))
    return "\n".join(out) + "\n"


def self_test():
    rows = []
    for rep in (1, 2, 3):
        for arm, base in (("off", 100.0), ("on", 120.0)):
            rows.append({"rep": rep, "proto": "h1", "rate": 200, "arm": arm, "requests": 1000, "success": 1,
                         "status_codes": {"200": 1000}, "errors": [],
                         "pd_requests": 1500 if arm == "on" else 0, "gc_cycles": 2, "throughput": 200.0,
                         **{k: base + rep for k, _, _ in METRICS if k not in ("gc_per_1k", "throughput")}})
    s = summarize(rows)
    assert "| 200 | p50 latency (µs) | 102 ± 1% | 122 ± 1% | +19.6% (+20) | 20 .. 20 | 3 |" in s, s
    assert "| 200 | throughput (req/s) | 200.0 ± 0% | 200.0 ± 0% | ~ (+0.0)" in s, s
    assert "ranges 0 .. 0" in s and "off: 3 steps, 3000 requests, 0 not 200." in s, s
    print("childappload summary self-test: ok")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        with open(sys.argv[1]) as fh:
            sys.stdout.write(summarize(json.load(fh)))
