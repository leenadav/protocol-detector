"""Summarize a loadtest.py results file as the Markdown tables of docs/integration/LOAD-TEST.md.

Per (configuration, scheme, rate) it takes the median over the rounds. Added latency is computed per round
(D minus B, the same lab binary with the detector on and off; B minus A, the lab build against unmodified Culvert)
and reported as the median of the rounds with the min..max range, so the noise is visible next to the figure.

Usage: python3 tools/loadtest_summary.py results-loadtest/results.json [more.json ...] > results-loadtest/summary.md
       (several files are merged: their steps and rates are combined)
       python3 tools/loadtest_summary.py --self-test
"""
import json
import statistics
import sys

PCTS = (("p50", "50th"), ("p95", "95th"), ("p99", "99th"))


def index(steps):
    out = {}
    for s in steps:
        out.setdefault((s["config"], s["scheme"], s["target_rate"]), {})[s["round"]] = s
    return out


def med(values):
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def fmt(v, digits=0):
    if v is None:
        return "n/a"
    return ("%%.%df" % digits) % v


def diffs(idx, on, off, scheme, rate, key):
    a, b = idx.get((on, scheme, rate), {}), idx.get((off, scheme, rate), {})
    return [a[r]["latency_us"][key] - b[r]["latency_us"][key] for r in sorted(set(a) & set(b))]


def summary(results):
    idx = index(results["steps"])
    rates = results["rates"]
    lines = []
    for scheme in ("https", "http"):
        lines.append("### %s (%s)" % (scheme.upper(), "CONNECT tunnel, observed by the detector in D" if scheme ==
                                       "https" else "forward proxy, not observed: the control"))
        lines.append("")
        lines.append("Latency per request (µs, median of %d rounds) and achieved throughput (req/s):" % results["rounds"])
        lines.append("")
        lines.append("| Rate | Config | p50 | p95 | p99 | max | Throughput | Success | CPU s / 1,000 flows | Peak RSS MiB | "
                     "PD records |")
        lines.append("|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        for rate in rates:
            for cfg in ("direct", "A", "B", "D"):
                rounds = idx.get((cfg, scheme, rate), {})
                if not rounds:
                    continue
                rs = list(rounds.values())
                lat = {k: med([s["latency_us"][k] for s in rs]) for k in ("50th", "95th", "99th", "max")}
                cpu = med([s.get("proxy_cpu_s_per_1000_flows") for s in rs])
                rss = med([(s.get("proxy_rss") or {}).get("peak_kib") for s in rs])
                pd = med([s.get("pd_records") for s in rs])
                req = med([s["requests"] for s in rs])
                lines.append("| %d | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
                    rate, cfg, fmt(lat["50th"]), fmt(lat["95th"]), fmt(lat["99th"]), fmt(lat["max"]),
                    fmt(med([s["throughput"] for s in rs]), 1), "%.2f%%" % (100 * min(s["success"] for s in rs)),
                    fmt(cpu, 3), fmt(rss / 1024 if rss else None, 1),
                    "n/a" if pd is None else "%d of %d" % (pd, req)))
        lines.append("")
        lines.append("Added latency (µs; median of the per-round differences, range in brackets):")
        lines.append("")
        lines.append("| Rate | Pair | p50 | p95 | p99 |")
        lines.append("|---:|---|---:|---:|---:|")
        for rate in rates:
            for on, off, label in (("D", "B", "D − B: detector observe vs off (same binary)"),
                                   ("B", "A", "B − A: lab build, detector off, vs unmodified Culvert")):
                cells = []
                for _, key in PCTS:
                    d = diffs(idx, on, off, scheme, rate, key)
                    cells.append("n/a" if not d else "%+.0f [%+.0f..%+.0f]" % (statistics.median(d), min(d), max(d)))
                lines.append("| %d | %s | %s |" % (rate, label, " | ".join(cells)))
        lines.append("")
        lines.append("Proxy CPU (s per 1,000 flows) and peak RSS (MiB) differences, D − B (median of rounds):")
        lines.append("")
        lines.append("| Rate | CPU s / 1,000 flows, B | D | D − B | Peak RSS B | D | D − B |")
        lines.append("|---:|---:|---:|---:|---:|---:|---:|")
        for rate in rates:
            b, d = idx.get(("B", scheme, rate), {}), idx.get(("D", scheme, rate), {})
            cb = med([s["proxy_cpu_s_per_1000_flows"] for s in b.values()])
            cd = med([s["proxy_cpu_s_per_1000_flows"] for s in d.values()])
            rb = med([s["proxy_rss"]["peak_kib"] for s in b.values()])
            rd = med([s["proxy_rss"]["peak_kib"] for s in d.values()])
            if None in (cb, cd, rb, rd):
                continue
            lines.append("| %d | %.3f | %.3f | %+.3f | %.1f | %.1f | %+.1f |" % (
                rate, cb, cd, cd - cb, rb / 1024, rd / 1024, (rd - rb) / 1024))
        lines.append("")
    return "\n".join(lines)


def self_test():
    def step(cfg, rnd, p50):
        return {"config": cfg, "scheme": "https", "target_rate": 100, "round": rnd, "requests": 10, "throughput": 10.0,
                "success": 1, "latency_us": {"50th": p50, "95th": p50 * 2, "99th": p50 * 3, "max": p50 * 4},
                "proxy_cpu_s_per_1000_flows": 0.5, "proxy_rss": {"peak_kib": 2048}, "pd_records": 10 if cfg == "D" else None}
    res = {"rounds": 2, "rates": [100], "steps": [step("B", 1, 100), step("D", 1, 130), step("B", 2, 100),
                                                     step("D", 2, 110), step("A", 1, 90), step("A", 2, 95)]}
    out = summary(res)
    assert "+20 [+10..+30]" in out, out
    assert "10 of 10" in out, out
    print("loadtest_summary self-test: ok")


def main(argv):
    if argv[1:] == ["--self-test"]:
        self_test()
        return 0
    merged = None
    for path in argv[1:]:
        with open(path) as f:
            res = json.load(f)
        if merged is None:
            merged = res
        else:
            merged["steps"] += res["steps"]
            merged["rates"] = sorted(set(merged["rates"]) | set(res["rates"]))
            merged["rounds"] = min(merged["rounds"], res["rounds"])
    print(summary(merged))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
