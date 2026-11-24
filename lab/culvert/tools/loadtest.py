"""Culvert load test: what the protocol detector adds per connection (PRO-269, docs/integration/LOAD-TEST.md).

Drives vegeta (MIT, a test tool only, never shipped) through three Culvert builds, one at a time:

  A  unmodified Culvert at the lab base
  B  lab build, detector off   (CULVERT_LAB_PROTODETECT unset: the relay path is the unmodified one)
  D  lab build, observe mode   (CULVERT_LAB_PROTODETECT=real, visibility only, nothing is blocked)

Each request opens its own client connection (vegeta -keepalive=false), so for HTTPS every request is one CONNECT
bypass tunnel, which is one detector flow on D. HTTP requests go through Culvert's forward path, which the lab does
not observe; they are the control. Loopback and synthetic traffic only: the origin is tools/loadorigin on
203.0.113.10 (RFC 5737), and the proxy, the origin and vegeta are pinned to separate CPUs.

For every cell (scheme x rate x build x round) the proxy is started fresh, warmed up, then attacked; its CPU time
comes from /proc/<pid>/stat, its RSS is sampled every 100 ms, and its GC cycles are counted from GODEBUG=gctrace=1.
The raw per-cell results go to <out>/cells.json; per-group medians (with min and max) are written to <out>/summary.json.

Usage (as root, from anywhere; paths follow the other lab scripts):
  python3 loadtest.py --lab /home/user/culvert-lab --out <dir> [--rates 200,500,1000] [--duration 30] [--rounds 3]
"""
import argparse, json, os, re, shutil, signal, statistics, subprocess, sys, time, urllib.request

CLK = os.sysconf("SC_CLK_TCK")
PAGE = os.sysconf("SC_PAGE_SIZE")
PROXY_CPUS, VEGETA_CPUS, ORIGIN_CPUS = "0,1", "2", "3"
BUILDS = {"A": ("culvert-A", {}), "B": ("culvert-lab", {}),
          "D": ("culvert-lab", {"CULVERT_LAB_PROTODETECT": "real", "CULVERT_LAB_PD_WINDOW_MS": "3000"})}
PORT, UI_PORT = 18090, 19190
GC_LINE = re.compile(r"^gc \d+ @")
CLEAN_ENV = {k: v for k, v in os.environ.items()
             if k.lower() not in ("https_proxy", "http_proxy", "all_proxy", "no_proxy")}


def cpu_ticks(pid):
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    return int(fields[11]) + int(fields[12])  # utime + stime (fields 14 and 15 of the full line)


def rss_kib(pid):
    with open(f"/proc/{pid}/statm") as f:
        return int(f.read().split()[1]) * PAGE // 1024


def healthy(port, timeout=30):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    end = time.time() + timeout
    while time.time() < end:
        try:
            if opener.open(f"http://127.0.0.1:{port}/health", timeout=2).status == 200:
                return True
        except OSError:
            time.sleep(0.3)
    return False


def start_proxy(lab, build, run_dir):
    binary, extra = BUILDS[build]
    data = os.path.join(run_dir, f"data-load-{build}")
    shutil.rmtree(data, ignore_errors=True)
    os.makedirs(data)
    env = dict(CLEAN_ENV, CULVERT_DATA_DIR=data, GODEBUG="gctrace=1", **extra)
    log = open(os.path.join(run_dir, f"culvert-load-{build}.log"), "w")
    p = subprocess.Popen(["taskset", "-c", PROXY_CPUS, os.path.join(lab, "bin", binary),  # noqa: S603, S607  (fixed argv, lab binaries; loopback lab only)
                          "-port", str(PORT), "-ui-port", str(UI_PORT)],
                         env=env, stdout=log, stderr=subprocess.STDOUT)
    if not healthy(PORT):
        p.kill()
        sys.exit(f"build {build} did not become healthy; see {log.name}")
    return p, log


def stop_proxy(p, log):
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
    log.close()


def log_counts(path):
    """(GC cycles, PROTODETECT records, refused admissions) written so far to a proxy's log."""
    gc = pd = refused = 0
    with open(path, errors="replace") as f:
        for line in f:
            if GC_LINE.match(line):
                gc += 1
            elif "PROTODETECT {" in line:
                pd += 1
                refused += '"admission":"refused"' in line
    return gc, pd, refused


def attack(lab, run_dir, scheme, rate, seconds, out_bin):
    targets = os.path.join(run_dir, f"targets-{scheme}.txt")
    with open(targets, "w") as f:
        f.write(f"GET {scheme}://origin.lab.test/load\n")
    env = dict(CLEAN_ENV, HTTPS_PROXY=f"http://127.0.0.1:{PORT}", HTTP_PROXY=f"http://127.0.0.1:{PORT}")
    cmd = ["taskset", "-c", VEGETA_CPUS, os.path.join(lab, "bin", "vegeta"), "attack", "-targets", targets,
           "-rate", str(rate), "-duration", f"{seconds}s", "-keepalive=false", "-timeout", "10s",
           "-root-certs", os.path.join(run_dir, "origin.pem"), "-output", out_bin]
    return subprocess.Popen(cmd, env=env)  # noqa: S603, S607  (fixed argv, lab binaries; loopback lab only)


def report(lab, out_bin):
    r = subprocess.run([os.path.join(lab, "bin", "vegeta"), "report", "-type=json", out_bin],  # noqa: S603, S607  (fixed argv, lab binaries; loopback lab only)
                       check=True, capture_output=True, text=True)
    return json.loads(r.stdout)


def cell(lab, run_dir, scheme, rate, build, seconds, warmup, rnd):
    p, log = start_proxy(lab, build, run_dir)
    try:
        w = attack(lab, run_dir, scheme, rate, warmup, os.devnull)
        w.wait()
        time.sleep(3.5)  # let the warm-up's observation windows end, so its records are not counted below
        idle_rss = rss_kib(p.pid)
        gc0, pd0, ref0 = log_counts(log.name)
        t0, c0 = time.time(), cpu_ticks(p.pid)
        out_bin = os.path.join(run_dir, f"attack-{scheme}-{rate}-{build}-{rnd}.bin")
        a = attack(lab, run_dir, scheme, rate, seconds, out_bin)
        samples = []
        while a.poll() is None:
            samples.append(rss_kib(p.pid))
            time.sleep(0.1)
        c1, t1 = cpu_ticks(p.pid), time.time()
        time.sleep(3.5)  # the last tunnels' windows end and their records are logged
        gc1, pd1, ref1 = log_counts(log.name)
    finally:
        stop_proxy(p, log)
    rep = report(lab, out_bin)
    os.remove(out_bin)
    n = rep["requests"]
    cpu_s = (c1 - c0) / CLK
    lat = rep["latencies"]
    return {
        "scheme": scheme, "rate": rate, "build": build, "round": rnd, "requests": n,
        "success": rep["success"], "throughput": rep["throughput"], "status_codes": rep["status_codes"],
        "errors": rep.get("errors") or [],
        "p50_ms": lat["50th"] / 1e6, "p95_ms": lat["95th"] / 1e6, "p99_ms": lat["99th"] / 1e6,
        "mean_ms": lat["mean"] / 1e6, "max_ms": lat["max"] / 1e6,
        "proxy_cpu_s": cpu_s, "wall_s": t1 - t0, "cpu_ms_per_1k": cpu_s * 1000 / n * 1000,
        "proxy_cpu_pct": 100 * cpu_s / (t1 - t0),
        "rss_idle_mib": idle_rss / 1024, "rss_peak_mib": max(samples) / 1024,
        "rss_mean_mib": statistics.mean(samples) / 1024, "gc_cycles": gc1 - gc0,
        "gc_per_1k": (gc1 - gc0) / n * 1000, "pd_records": pd1 - pd0, "pd_refused": ref1 - ref0,
    }


def summarise(cells):
    keys = ["p50_ms", "p95_ms", "p99_ms", "mean_ms", "throughput", "success", "cpu_ms_per_1k", "proxy_cpu_pct",
            "rss_idle_mib", "rss_peak_mib", "rss_mean_mib", "gc_per_1k", "pd_records", "pd_refused", "requests"]
    groups = {}
    for c in cells:
        groups.setdefault((c["scheme"], c["rate"], c["build"]), []).append(c)
    out = []
    for (scheme, rate, build), cs in sorted(groups.items()):
        row = {"scheme": scheme, "rate": rate, "build": build, "rounds": len(cs)}
        for k in keys:
            vals = [c[k] for c in cs]
            row[k] = statistics.median(vals)
            row[k + "_min"], row[k + "_max"] = min(vals), max(vals)
        out.append(row)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lab", default="/home/user/culvert-lab")
    ap.add_argument("--out", required=True)
    ap.add_argument("--rates", default="200,500,1000")
    ap.add_argument("--schemes", default="https,http")
    ap.add_argument("--builds", default="A,B,D")
    ap.add_argument("--duration", type=int, default=30)
    ap.add_argument("--warmup", type=int, default=3)
    ap.add_argument("--rounds", type=int, default=3)
    a = ap.parse_args()
    run_dir = os.path.join(a.lab, "run")
    os.makedirs(a.out, exist_ok=True)
    origin = subprocess.Popen(["taskset", "-c", ORIGIN_CPUS, os.path.join(a.lab, "bin", "loadorigin"),  # noqa: S603, S607  (fixed argv, lab binaries; loopback lab only)
                               "-cert", os.path.join(run_dir, "origin.pem")],
                              stdout=open(os.path.join(run_dir, "loadorigin.log"), "w"), stderr=subprocess.STDOUT)
    time.sleep(1)
    cells = []
    builds = a.builds.split(",")
    try:
        for rnd in range(a.rounds):
            order = builds[rnd % len(builds):] + builds[:rnd % len(builds)]  # rotate, so no build always goes first
            for scheme in a.schemes.split(","):
                for rate in [int(r) for r in a.rates.split(",")]:
                    for build in order:
                        c = cell(a.lab, run_dir, scheme, rate, build, a.duration, a.warmup, rnd)
                        cells.append(c)
                        print(f"round {rnd} {scheme:5} {rate:5}/s {build}: p50 {c['p50_ms']:.2f} p95 {c['p95_ms']:.2f}"
                              f" p99 {c['p99_ms']:.2f} ms, ok {c['success']:.4f}, cpu {c['cpu_ms_per_1k']:.0f} ms/1k,"
                              f" rss peak {c['rss_peak_mib']:.0f} MiB, pd {c['pd_records']}", flush=True)
                        with open(os.path.join(a.out, "cells.json"), "w") as f:
                            json.dump(cells, f, indent=1)
    finally:
        origin.terminate()
    with open(os.path.join(a.out, "summary.json"), "w") as f:
        json.dump(summarise(cells), f, indent=1)


if __name__ == "__main__":
    main()
