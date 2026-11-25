"""Render the load test's summary.json as the Markdown tables of docs/integration/LOAD-TEST-SPLIT.md (PRO-269).

  python3 loadtest_report.py <results dir>

Values are medians over the rounds; the range [min-max] is shown where it matters for the reading. "Added" is
observe mode (D) minus the same lab binary with the detector off (B): the detector's own cost. B minus A (the
unmodified build) is the cost of the lab hook with the detector off, which should be noise.
"""
import json, os, sys


def load(d):
    with open(os.path.join(d, "summary.json")) as f:
        rows = json.load(f)
    return {(r["scheme"], r["rate"], r["build"]): r for r in rows}


def ms(v):
    return f"{v:.2f}"


def rng(r, k, fmt="{:.2f}"):
    return f"{fmt.format(r[k])} [{fmt.format(r[k + '_min'])}–{fmt.format(r[k + '_max'])}]"


def main():
    d = sys.argv[1]
    s = load(d)
    schemes = sorted({k[0] for k in s}, key=lambda x: x != "https")
    rates = sorted({k[1] for k in s})
    for scheme in schemes:
        print(f"\n#### {scheme.upper()}: latency per request (ms), median of rounds [min–max]\n")
        print("| Rate | Build | p50 | p95 | p99 | Throughput (req/s) | Success |")
        print("|---:|---|---:|---:|---:|---:|---:|")
        for rate in rates:
            for b in ("A", "B", "D"):
                r = s.get((scheme, rate, b))
                if r:
                    print(f"| {rate}/s | {b} | {rng(r, 'p50_ms')} | {rng(r, 'p95_ms')} | {rng(r, 'p99_ms')} |"
                          f" {r['throughput']:.1f} | {100 * r['success_min']:.2f}% (min) |")
        print(f"\n#### {scheme.upper()}: what observe mode adds (D − B), and the lab hook with the detector off (B − A)\n")
        print("| Rate | Δp50 D−B | Δp95 D−B | Δp99 D−B | Δp50 B−A | Δp99 B−A |")
        print("|---:|---:|---:|---:|---:|---:|")
        for rate in rates:
            a, b, dd = (s.get((scheme, rate, x)) for x in "ABD")
            if a and b and dd:
                print(f"| {rate}/s | {dd['p50_ms'] - b['p50_ms']:+.2f} | {dd['p95_ms'] - b['p95_ms']:+.2f} |"
                      f" {dd['p99_ms'] - b['p99_ms']:+.2f} | {b['p50_ms'] - a['p50_ms']:+.2f} |"
                      f" {b['p99_ms'] - a['p99_ms']:+.2f} |")
        print(f"\n#### {scheme.upper()}: proxy CPU and memory\n")
        print("| Rate | Build | Proxy CPU per 1,000 flows (ms) | Proxy CPU (% of one core) | RSS idle (MiB) |"
              " RSS peak (MiB) | GC cycles per 1,000 flows | Detector records | Refused admissions |")
        print("|---:|---|---:|---:|---:|---:|---:|---:|---:|")
        for rate in rates:
            for b in ("A", "B", "D"):
                r = s.get((scheme, rate, b))
                if r:
                    print(f"| {rate}/s | {b} | {rng(r, 'cpu_ms_per_1k', '{:.0f}')} | {r['proxy_cpu_pct']:.0f} |"
                          f" {r['rss_idle_mib']:.1f} | {rng(r, 'rss_peak_mib', '{:.1f}')} | {r['gc_per_1k']:.2f} |"
                          f" {r['pd_records']:.0f} of {r['requests']:.0f} | {r['pd_refused']:.0f} |")
        print(f"\n#### {scheme.upper()}: observe-mode cost per 1,000 flows (D − B)\n")
        print("| Rate | Proxy CPU (ms) | RSS peak (MiB) | GC cycles |")
        print("|---:|---:|---:|---:|")
        for rate in rates:
            b, dd = s.get((scheme, rate, "B")), s.get((scheme, rate, "D"))
            if b and dd:
                print(f"| {rate}/s | {dd['cpu_ms_per_1k'] - b['cpu_ms_per_1k']:+.0f} |"
                      f" {dd['rss_peak_mib'] - b['rss_peak_mib']:+.1f} | {dd['gc_per_1k'] - b['gc_per_1k']:+.2f} |")


if __name__ == "__main__":
    main()
