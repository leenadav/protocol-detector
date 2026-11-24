"""Culvert lab load test (PRO-269): what the protocol detector adds to each connection.

Loopback and synthetic traffic only. vegeta (MIT, a test tool that is never shipped) sends sustained load through
local Culvert builds to the synthetic origin `loadorigin` on 203.0.113.10 (RFC 5737, a loopback alias):

  direct  vegeta straight to the origin, no proxy (the floor)
  A       unmodified Culvert at the lab base (ef94311)
  B       the lab build with the detector off (CULVERT_LAB_PROTODETECT unset)
  D       the lab build with the real detector in observe mode (CULVERT_LAB_PROTODETECT=real)

HTTPS goes through a CONNECT tunnel that Culvert relays without inspection, which is the path the detector
observes. HTTP goes through Culvert's forward proxy, which the detector does not observe: it is the control.
Every request opens a new connection (vegeta -keepalive=false), so one request is one flow.

For every step the script records vegeta's JSON report, the proxy's CPU time (utime + stime from /proc), its
resident memory sampled every 100 ms, and the number of PROTODETECT records the step logged.

Usage (see docs/integration/LOAD-TEST.md):
  python3 tools/loadtest.py --bin /home/user/culvert-lab/bin --out results-loadtest/results.json
  python3 tools/loadtest.py --self-test
"""
import argparse
import json
import os
import shutil
import signal
import subprocess  # noqa: S404  (argv-only calls of the lab binaries, no shell)
import sys
import threading
import time
import urllib.request
from pathlib import Path

ORIGIN_HOST = "origin.lab.test"
ORIGIN_ADDR = "203.0.113.10"
CONFIGS = {
    "A": ("culvert-A", {}),
    "B": ("culvert-lab", {}),
    "D": ("culvert-lab", {"CULVERT_LAB_PROTODETECT": "real"}),
}
PROXY_CPUS, VEGETA_CPUS, ORIGIN_CPUS = "0,1", "2", "3"
PROXY_ENV_DROP = ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy",
                  "NO_PROXY", "no_proxy")
CLK_TCK = os.sysconf("SC_CLK_TCK")
TASKSET = shutil.which("taskset") or "/usr/bin/taskset"


def clean_env(extra=None):
    env = {k: v for k, v in os.environ.items() if k not in PROXY_ENV_DROP}
    env.update(extra or {})
    return env


def cpu_seconds(pid):
    """utime + stime of a process, in seconds (fields 14 and 15 of /proc/<pid>/stat)."""
    text = Path("/proc/%d/stat" % pid).read_text()
    fields = text[text.rindex(")") + 2:].split()
    return (int(fields[11]) + int(fields[12])) / CLK_TCK


def rss_kib(pid):
    for line in Path("/proc/%d/status" % pid).read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    raise ValueError("no VmRSS for pid %d" % pid)


class RssSampler(threading.Thread):
    """Samples a process's VmRSS every `period` seconds until stopped; keeps the peak and the mean."""

    def __init__(self, pid, period=0.1):
        super().__init__(daemon=True)
        self.pid, self.period = pid, period
        self.samples = []
        self.done = threading.Event()

    def run(self):
        while not self.done.is_set():
            try:
                self.samples.append(rss_kib(self.pid))
            except (OSError, ValueError):
                return
            self.done.wait(self.period)

    def stop(self):
        self.done.set()
        self.join()
        if not self.samples:
            return {"peak_kib": None, "mean_kib": None}
        return {"peak_kib": max(self.samples), "mean_kib": round(sum(self.samples) / len(self.samples))}


def count_records(log_path):
    """PROTODETECT records and refused admissions logged so far."""
    records = refused = 0
    with open(log_path, "rb") as f:
        for line in f:
            if b"PROTODETECT {" in line:
                records += 1
                if b'"admission":"refused"' in line:
                    refused += 1
    return records, refused


def wait_health(port, timeout=30):
    deadline = time.time() + timeout
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    while time.time() < deadline:
        try:
            with opener.open("http://127.0.0.1:%d/health" % port, timeout=2):
                return
        except OSError:
            time.sleep(0.5)
    raise RuntimeError("proxy on port %d did not become healthy" % port)


def start_proxy(bindir, rundir, name, port):
    binary, extra = CONFIGS[name]
    data = rundir / ("data-load-" + name)
    shutil.rmtree(data, ignore_errors=True)
    data.mkdir(parents=True)
    log = open(rundir / ("culvert-load-%s.log" % name), "wb")
    env = clean_env(dict(extra, CULVERT_DATA_DIR=str(data)))
    proc = subprocess.Popen([TASKSET, "-c", PROXY_CPUS, str(bindir / binary), "-port", str(port),  # noqa: S603  (argv only, lab binaries)
                             "-ui-port", str(port + 1000)], env=env, stdout=log, stderr=subprocess.STDOUT)
    log.close()
    wait_health(port)
    return proc, rundir / ("culvert-load-%s.log" % name)


def vegeta(vegeta_bin, scheme, rate, duration, proxy_port, out_bin):
    target = "GET %s://%s/load\n" % (scheme, ORIGIN_HOST)
    extra = {}
    if proxy_port:
        extra = {"HTTPS_PROXY": "http://127.0.0.1:%d" % proxy_port, "HTTP_PROXY": "http://127.0.0.1:%d" % proxy_port}
    attack = [TASKSET, "-c", VEGETA_CPUS, vegeta_bin, "attack", "-insecure", "-keepalive=false",
              "-rate=%d" % rate, "-duration=%ds" % duration, "-timeout=10s", "-output=%s" % out_bin]
    subprocess.run(attack, input=target.encode(), env=clean_env(extra), check=True)  # noqa: S603  (argv only, lab binaries)
    report = subprocess.run([vegeta_bin, "report", "-type=json", str(out_bin)], check=True, capture_output=True)  # noqa: S603  (argv only, lab binaries)
    os.unlink(out_bin)
    return json.loads(report.stdout)


def summarize(report):
    lat = report["latencies"]
    return {
        "requests": report["requests"],
        "rate": round(report["rate"], 2),
        "throughput": round(report["throughput"], 2),
        "success": report["success"],
        "status_codes": report["status_codes"],
        "errors": report["errors"][:5],
        "latency_us": {k: round(lat[k] / 1000, 1) for k in ("min", "mean", "50th", "90th", "95th", "99th", "max")},
    }


def run_step(args, scheme, rate, proxy_port, proc=None, log_path=None):
    before_cpu = cpu_seconds(proc.pid) if proc else None
    before_rec = count_records(log_path) if log_path else None
    sampler = RssSampler(proc.pid) if proc else None
    if sampler:
        sampler.start()
    report = vegeta(args.vegeta, scheme, rate, args.duration, proxy_port, args.scratch / "attack.bin")
    time.sleep(1.0)  # let the last tunnels close and log their records
    step = summarize(report)
    if proc:
        step["proxy_cpu_s"] = round(cpu_seconds(proc.pid) - before_cpu, 3)
        step["proxy_cpu_s_per_1000_flows"] = round(step["proxy_cpu_s"] * 1000 / max(1, report["requests"]), 4)
        step["proxy_rss"] = sampler.stop()
    if log_path:
        after = count_records(log_path)
        step["pd_records"] = after[0] - before_rec[0]
        step["pd_refused"] = after[1] - before_rec[1]
    return step


def run(args):
    rundir, bindir = args.rundir, args.bin
    rundir.mkdir(parents=True, exist_ok=True)
    args.scratch.mkdir(parents=True, exist_ok=True)
    origin = subprocess.Popen([TASKSET, "-c", ORIGIN_CPUS, str(bindir / "loadorigin"), "-addr", ORIGIN_ADDR],  # noqa: S603  (argv only, lab binaries)
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    results = {"started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "duration_s": args.duration,
               "rates": args.rates, "rounds": args.rounds, "cpus": {"proxy": PROXY_CPUS, "vegeta": VEGETA_CPUS,
               "origin": ORIGIN_CPUS}, "steps": []}
    try:
        for rnd in range(args.rounds):
            order = ["direct"] + [list(CONFIGS)[(i + rnd) % len(CONFIGS)] for i in range(len(CONFIGS))]
            for name in order:
                proc = log_path = None
                port = 0
                if name != "direct":
                    port = 18180 + list(CONFIGS).index(name)
                    proc, log_path = start_proxy(bindir, rundir, name, port)
                    # warm-up, not recorded
                    vegeta(args.vegeta, "https", 50, 2, port, args.scratch / "attack.bin")
                    idle = rss_kib(proc.pid)
                try:
                    for scheme in ("https", "http"):
                        for rate in args.rates:
                            step = run_step(args, scheme, rate, port, proc, log_path if name == "D" else None)
                            step.update({"round": rnd + 1, "config": name, "scheme": scheme, "target_rate": rate})
                            if proc:
                                step["proxy_rss_idle_kib"] = idle
                            results["steps"].append(step)
                            print(json.dumps({k: step.get(k) for k in ("round", "config", "scheme", "target_rate",
                                  "throughput", "success", "latency_us", "proxy_cpu_s", "pd_records")}), flush=True)
                            time.sleep(args.pause)
                finally:
                    if proc:
                        proc.send_signal(signal.SIGTERM)
                        proc.wait(timeout=30)
    finally:
        origin.terminate()
        origin.wait(timeout=10)
    results["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=1) + "\n")


def self_test():
    me = os.getpid()
    assert cpu_seconds(me) >= 0
    assert rss_kib(me) > 0
    s = RssSampler(me, 0.01)
    s.start()
    time.sleep(0.05)
    got = s.stop()
    assert got["peak_kib"] >= got["mean_kib"] > 0, got
    fake = {"requests": 4, "rate": 2.0, "throughput": 1.999, "success": 1, "status_codes": {"200": 4}, "errors": [],
            "latencies": {"min": 1000, "mean": 2000, "50th": 1500, "90th": 3000, "95th": 3500, "99th": 3900,
                          "max": 4000}}
    got = summarize(fake)
    assert got["latency_us"]["50th"] == 1.5 and got["throughput"] == 2.0, got
    print("loadtest self-test: ok")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--bin", type=Path, default=Path("/home/user/culvert-lab/bin"),
                   help="directory holding culvert-A, culvert-lab and loadorigin")
    p.add_argument("--vegeta", default=os.path.expanduser("~/go/bin/vegeta"))
    p.add_argument("--rundir", type=Path, default=Path("/home/user/culvert-lab/run"))
    p.add_argument("--scratch", type=Path, default=Path("/home/user/culvert-lab/run/scratch"))
    p.add_argument("--out", type=Path, default=Path("results-loadtest/results.json"))
    p.add_argument("--rates", type=lambda s: [int(x) for x in s.split(",")], default=[100, 300, 1000])
    p.add_argument("--duration", type=int, default=20, help="seconds per step")
    p.add_argument("--rounds", type=int, default=3)
    p.add_argument("--pause", type=float, default=3.0, help="seconds between steps")
    args = p.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    run(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
