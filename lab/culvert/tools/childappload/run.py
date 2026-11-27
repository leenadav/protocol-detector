"""Culvert lab load test of child-application classification on the decrypted-request path (PRO-516).

Loopback and synthetic traffic only. vegeta (MIT, a test tool that is never shipped) sends a fixed-rate mix of five
decrypted requests through the lab Culvert build (ef94311 + culvert-lab-ef94311.patch +
culvert-lab-ef94311-childapp.patch, plus the lab-only metrics hook zz_labmetrics_lab.go) to the synthetic origin
`origin/` on 203.0.113.10 (RFC 5737, a loopback alias). Every tunnel is SSL-inspected by one Allow + Inspect rule,
so each request reaches runH1InspectLoop (HTTP/1.1) or handleInspectH2 (HTTP/2, rule stripAlpn=false).

Arms, same binary:  off = CULVERT_LAB_CHILDAPP unset   on = CULVERT_LAB_CHILDAPP=real

For every step (repetition x protocol x rate x arm) a fresh proxy with an empty data directory is started, a 5 s
warm-up runs at 100 req/s, then the measured attack runs. Recorded per step:
  vegeta latency (p50/p95/p99/max), throughput, success;
  proxy CPU: utime + stime from /proc over the attack;
  proxy heap allocations (objects, bytes) and GC cycles over the attack, from runtime/metrics via the lab hook;
  peak RSS (VmRSS every 100 ms);
  on the "on" arm: the pd blocks Culvert logged (requests classified and verdict counts), read from /api/logs.

Usage:
  python3 run.py --out results.json [--reps 3] [--rates 200,1000,3000] [--duration 60] [--protos h1,h2]
  python3 run.py --profile-out DIR [--rate 3000] [--duration 40]   (CPU and allocation profiles, off and on)
  python3 run.py --self-test
"""
import argparse
import base64
import json
import os
import shutil
import subprocess  # noqa: S404  (argv-only calls of the lab binaries, no shell)
import sys
import threading
import time
import urllib.request
from pathlib import Path

LAB = Path("/home/user/culvert-lab")
HERE = Path(__file__).resolve().parent
PROXY_PORT, UI_PORT, METRICS_PORT = 18380, 18390, 18399
PROXY_CPUS, VEGETA_CPUS = "0,1", "2"
# A fixed tunnel pool: at most CONNS connections (tunnels) per target host, kept alive, so a step measures the
# per-request cost on established tunnels and a latency spike cannot snowball into new CONNECT + TLS handshakes.
CONNS = 32
CLK_TCK = os.sysconf("SC_CLK_TCK")
TASKSET = shutil.which("taskset") or "/usr/bin/taskset"
VEGETA = shutil.which("vegeta") or str(Path.home() / "go/bin/vegeta")
ENV_DROP = ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy")
BODY = b"From: a@lab.test\r\nTo: b@lab.test\r\nSubject: lab\r\n\r\nsynthetic message body\r\n"

# The request mix, one target each, sent round-robin by vegeta. "expect" is the verdict the pd block must show.
MIX = [
    ("gmail_upload", "POST", "https://gmail.googleapis.com/upload/gmail/v1/users/me/messages?uploadType=media",
     "message/rfc822", ("gmail-uploading", "child_rule_matched")),
    ("child_drive", "GET", "https://www.googleapis.com/drive/v3/files/1AbCdEf/export?mimeType=text/plain",
     None, ("google-drive-downloading", "child_rule_matched")),
    ("parent_only", "GET", "https://gmail.googleapis.com/gmail/v1/users/me/labels",
     None, ("google-base", "no_child_rule_matched")),
    ("unowned", "GET", "https://unowned.example/upload", None, ("", "host_unowned")),
    ("non_canonical", "POST", "https://gmail.googleapis.com/upload/gmail/v1/users/me/../me/messages?uploadType=media",
     "message/rfc822", ("google-base", "path_not_canonical")),
]


def targets_jsonl():
    lines = []
    for _, method, url, ctype, _ in MIX:
        t = {"method": method, "url": url}
        if ctype:
            t["header"] = {"Content-Type": [ctype]}
            t["body"] = base64.b64encode(BODY).decode()
        lines.append(json.dumps(t))
    return "\n".join(lines) + "\n"


def clean_env(extra=None):
    env = {k: v for k, v in os.environ.items() if k not in ENV_DROP}
    env.update(extra or {})
    return env


def cpu_seconds(pid):
    text = Path("/proc/%d/stat" % pid).read_text()
    f = text[text.rindex(")") + 2:].split()
    return (int(f[11]) + int(f[12])) / CLK_TCK


def rss_mib(pid):
    for line in Path("/proc/%d/status" % pid).read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) / 1024.0
    return 0.0


def get_json(url, timeout=10):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=timeout) as r:  # noqa: S310 (loopback, lab only)
        return json.loads(r.read())


def wait_health(port, limit=60):
    t0 = time.time()
    while time.time() - t0 < limit:
        try:
            urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                "http://127.0.0.1:%d/health" % port, timeout=2).read()  # noqa: S310
            return True
        except Exception:  # noqa: BLE001 (start-up poll)
            time.sleep(0.5)
    return False


class Proxy:
    def __init__(self, run_dir, arm, proto, profile_locks=False):
        self.data = run_dir / "data-load"
        if self.data.exists():
            shutil.rmtree(self.data)
        self.data.mkdir(parents=True)
        self.secret = run_dir / "admin-load.secret"
        self.log = run_dir / "culvert-load.log"
        extra = {"CULVERT_DATA_DIR": str(self.data), "SSL_CERT_FILE": str(LAB / "certs/bundle.pem"),
                 "CULVERT_LAB_METRICS_ADDR": "127.0.0.1:%d" % METRICS_PORT}
        if arm == "on":
            extra["CULVERT_LAB_CHILDAPP"] = "real"
        if profile_locks:
            extra["CULVERT_LAB_PROFILE_LOCKS"] = "1"
        self.proc = subprocess.Popen(  # noqa: S603
            [TASKSET, "-c", PROXY_CPUS, str(LAB / "bin/culvert-lab"), "-port", str(PROXY_PORT),
             "-ui-port", str(UI_PORT)], env=clean_env(extra), stdout=self.log.open("wb"), stderr=subprocess.STDOUT,
            cwd=str(run_dir))  # Culvert writes categories.json and cluster.json into its working directory
        if not wait_health(PROXY_PORT):
            raise RuntimeError("proxy did not start")
        args = [sys.executable, str(HERE / "inspect_rule.py"), str(UI_PORT), str(self.secret)]
        if proto == "h2":
            args.append("--native-h2")
        out = subprocess.run(args, capture_output=True, text=True, check=False)  # noqa: S603
        if out.returncode != 0:
            raise RuntimeError("rule setup failed: " + out.stdout[-400:] + out.stderr[-400:])

    def metrics(self):
        return get_json("http://127.0.0.1:%d/lab/metrics" % METRICS_PORT)

    def pd_blocks(self):
        """Every pd block Culvert logged, from the admin API (lab admin on loopback)."""
        import http.cookiejar
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # the lab UI's self-signed certificate on loopback
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx),
                                         urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        base = "https://127.0.0.1:%d" % UI_PORT
        login = urllib.request.Request(base + "/api/auth/login", method="POST",  # noqa: S310
                                       data=json.dumps({"user": "admin", "pass": self.secret.read_text()}).encode(),
                                       headers={"Content-Type": "application/json"})
        op.open(login, timeout=20).read()
        blocks, offset = [], 0
        while True:
            with op.open(base + "/api/logs?limit=1000&offset=%d" % offset, timeout=60) as r:  # noqa: S310
                page = json.loads(r.read())
            logs = page.get("logs") or []
            blocks += [e["pd"] for e in logs if e.get("pd")]
            offset += len(logs)
            if not logs or offset >= page.get("total", 0):
                return blocks

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def attack(proto, rate, duration, targets, out_bin):
    env = clean_env({"HTTPS_PROXY": "http://127.0.0.1:%d" % PROXY_PORT})
    with open(out_bin, "wb") as fh:
        subprocess.run([TASKSET, "-c", VEGETA_CPUS, VEGETA, "attack", "-format=json", "-targets=" + str(targets),  # noqa: S603
                        "-insecure", "-http2=%s" % ("true" if proto == "h2" else "false"), "-rate=%d" % rate,
                        "-duration=%ds" % duration, "-timeout=10s",
                        "-connections=%d" % CONNS, "-max-connections=%d" % CONNS], env=env, stdout=fh, check=True)
    rep = subprocess.run([VEGETA, "report", "-type=json", str(out_bin)], capture_output=True, check=True)  # noqa: S603
    return json.loads(rep.stdout)


def tally(blocks):
    """Requests classified and verdict counts over the pd blocks: {(app, reason): count}."""
    req, verdicts = 0, {}
    for b in blocks:
        req += b.get("requests", 0)
        for a in b.get("apps") or []:
            key = "%s|%s" % (a.get("app", ""), ",".join(a.get("reasons") or []))
            verdicts[key] = verdicts.get(key, 0) + a.get("count", 0)
    return req, verdicts


def run_step(run_dir, rep, proto, rate, arm, duration):
    targets = run_dir / "targets.json"
    proxy = Proxy(run_dir, arm, proto)
    try:
        attack(proto, 100, 5, targets, run_dir / "warm.bin")
        time.sleep(1)
        m0, c0, pid = proxy.metrics(), cpu_seconds(proxy.proc.pid), proxy.proc.pid
        peak, stop = [0.0], threading.Event()

        def sample():
            while not stop.is_set():
                peak[0] = max(peak[0], rss_mib(pid))
                time.sleep(0.1)
        th = threading.Thread(target=sample, daemon=True)
        th.start()
        t0 = time.time()
        report = attack(proto, rate, duration, targets, run_dir / "step.bin")
        wall = time.time() - t0
        stop.set()
        th.join()
        c1, m1 = cpu_seconds(pid), proxy.metrics()
        time.sleep(2)  # tunnels close when vegeta exits; let the TUNNEL_CLOSED entries land
        pd_req, verdicts = tally(proxy.pd_blocks()) if arm == "on" else (0, {})
    finally:
        proxy.stop()
        proxy.log.write_bytes(b"".join(proxy.log.read_bytes().splitlines(keepends=True)[-50:]))
    n = report["requests"]
    lat = report["latencies"]
    d = {k: m1[k] - m0[k] for k in m0}
    return {
        "rep": rep, "proto": proto, "rate": rate, "arm": arm, "duration_s": duration, "wall_s": round(wall, 2),
        "requests": n, "throughput": report["throughput"], "success": report["success"],
        "status_codes": report["status_codes"], "errors": report.get("errors", [])[:5],
        "p50_us": lat["50th"] / 1000.0, "p95_us": lat["95th"] / 1000.0, "p99_us": lat["99th"] / 1000.0,
        "max_us": lat["max"] / 1000.0, "mean_us": lat["mean"] / 1000.0,
        "cpu_s": round(c1 - c0, 3), "cpu_us_per_req": (c1 - c0) * 1e6 / n,
        "allocs_per_req": d["/gc/heap/allocs:objects"] / n, "alloc_bytes_per_req": d["/gc/heap/allocs:bytes"] / n,
        "gc_cycles": d["/gc/cycles/total:gc-cycles"], "runtime_cpu_s": d["/cpu/classes/total:cpu-seconds"],
        "peak_rss_mib": round(peak[0], 1),
        # pd_requests covers the warm-up too (the same proxy process); the warm-up count is 100/s x 5 s.
        "pd_requests": pd_req, "pd_verdicts": verdicts,
    }


def grab_profile(url, path, timeout, res, kind):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=timeout) as r:  # noqa: S310 (loopback, lab only)
        path.write_bytes(r.read())
    res[kind] = True


def attack_into(box, proto, rate, duration, run_dir):
    box["r"] = attack(proto, rate, duration, run_dir / "targets.json", run_dir / "step.bin")


def profile(run_dir, out_dir, proto, rate, duration):
    """CPU, allocation, mutex and block profiles of the proxy while vegeta runs, for both arms. Lock profiling is
    on in both arms of this pass (it costs CPU), so the profile pass is never mixed into the measured steps."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for arm in ("off", "on"):
        proxy = Proxy(run_dir, arm, proto, profile_locks=True)
        try:
            attack(proto, 100, 5, run_dir / "targets.json", run_dir / "warm.bin")
            secs = duration - 10
            res, box = {}, {}
            base = "http://127.0.0.1:%d/debug/pprof/" % METRICS_PORT
            ths = [threading.Thread(target=grab_profile,
                                    args=(base + q % secs, out_dir / ("%s-%s-%s.pb.gz" % (kind, proto, arm)), secs + 30,
                                          res, kind))
                   for kind, q in (("cpu", "profile?seconds=%d"), ("allocs", "allocs?seconds=%d"),
                                   ("mutex", "mutex?seconds=%d"), ("block", "block?seconds=%d"))]
            lt = threading.Thread(target=attack_into, args=(box, proto, rate, duration, run_dir))
            lt.start()
            time.sleep(5)
            for t in ths:
                t.start()
            for t in ths + [lt]:
                t.join()
            print(proto, arm, "profiled", sorted(res), "requests", box["r"]["requests"], flush=True)
        finally:
            proxy.stop()


def self_test():
    assert len(MIX) == 5 and len({m[0] for m in MIX}) == 5
    lines = targets_jsonl().splitlines()
    assert len(lines) == 5 and json.loads(lines[0])["header"]["Content-Type"] == ["message/rfc822"]
    assert base64.b64decode(json.loads(lines[0])["body"]) == BODY
    req, v = tally([{"requests": 3, "apps": [{"app": "a", "reasons": ["r"], "count": 2},
                                             {"app": "", "reasons": ["host_unowned"], "count": 1}]}])
    assert req == 3 and v == {"a|r": 2, "|host_unowned": 1}
    print("childappload run self-test: ok")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--profile-out")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--rates", default="200,1000,3000")
    ap.add_argument("--rate", type=int, default=3000)
    ap.add_argument("--protos", default="h1,h2")
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    run_dir = LAB / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "targets.json").write_text(targets_jsonl())
    protos = a.protos.split(",")
    if a.profile_out:
        for proto in protos:
            profile(run_dir, Path(a.profile_out), proto, a.rate, a.duration)
        return 0
    rates = [int(r) for r in a.rates.split(",")]
    out = Path(a.out)
    results = json.loads(out.read_text()) if out.exists() else []
    done = {(r["rep"], r["proto"], r["rate"], r["arm"]) for r in results}
    for rep in range(1, a.reps + 1):
        for proto in protos:
            for rate in rates:
                arms = ("off", "on") if (rep + rates.index(rate)) % 2 else ("on", "off")  # alternate the order
                for arm in arms:
                    if (rep, proto, rate, arm) in done:
                        continue
                    r = run_step(run_dir, rep, proto, rate, arm, a.duration)
                    r["started_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    results.append(r)
                    out.write_text(json.dumps(results, indent=1))
                    print("rep %d %s %5d/s %-3s p50 %7.0f p99 %8.0f us  thr %7.1f  ok %.4f  cpu %6.1f us/req  "
                          "allocs %6.1f/req  pd %d" % (rep, proto, rate, arm, r["p50_us"], r["p99_us"], r["throughput"],
                                                       r["success"], r["cpu_us_per_req"], r["allocs_per_req"],
                                                       r["pd_requests"]), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
