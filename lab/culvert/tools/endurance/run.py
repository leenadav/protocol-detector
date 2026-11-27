"""Endurance run of the Culvert lab (PRO-540, working plan phase L6; lab/culvert/ENDURANCE.md).

Loopback and synthetic traffic only. One lab Culvert process at a time (CONNECT bypass observed by the real
detector, child-app classification on for the inspected *.googleapis.com tunnels), driven for the manifest's
duration by `load/` (endurance-load drive), with one restart of the same binary and one restart onto a binary
whose content pack is a different published release. Every 30 s the orchestrator records, per process:
RSS (/proc), Go heap and goroutines, open fds, the detector's admission counters and reservations (the lab-only
hook culverthook/), and the pd blocks of the latest log entries (content and child-app release).

    python3 run.py --manifest manifest.json --out <dir>      (the run; writes samples.jsonl and phases.json)
    python3 run.py --verdict <dir>                           (evaluates the pass conditions -> verdict.json)
    python3 run.py --self-test

Paths assume the lab layout of the lane brief (/home/user/culvert-lab). CPU pinning: proxy 0,1; driver 2; origin 3.
"""
import argparse
import http.cookiejar
import json
import os
import secrets
import shutil
import signal
import ssl
import subprocess  # noqa: S404  (argv-only calls of the lab binaries, no shell)
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

LAB = Path("/home/user/culvert-lab")
PROXY_PORT, UI_PORT, METRICS_PORT = 18480, 18490, 18499
PROXY_CPUS, DRIVER_CPUS, ORIGIN_CPUS = "0,1", "2", "3"
TASKSET = shutil.which("taskset") or "/usr/bin/taskset"
ENV_DROP = ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy")

AUTH_RULE = {"name": "lab-exempt-loopback", "ruleType": "auth",
             "subjectMatch": {"schemaVersion": 1, "all": [{"type": "cidr", "values": ["127.0.0.1/32"]}]},
             "auth": {"outcome": "Exempt", "protocol": "connect", "owner": "lab", "reason": "PRO-540 local endurance run",
                      "broadExemption": True},
             "comment": "PRO-540 lab: the load generator on loopback needs no proxy credentials."}
RULES = [
    {"name": "lab-inspect-googleapis", "action": "Allow", "sslAction": "Inspect", "destFQDN": "*.googleapis.com",
     "logTraffic": True, "comment": "PRO-540 lab: child-app path (decrypted requests)."},
    {"name": "lab-bypass-rest", "action": "Allow", "sslAction": "Bypass", "logTraffic": True,
     "comment": "PRO-540 lab: every other tunnel is a CONNECT bypass observed by the detector."},
]


def clean_env(extra=None):
    env = {k: v for k, v in os.environ.items() if k not in ENV_DROP}
    env.update(extra or {})
    return env


def plain_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get_json(url, timeout=10):
    with plain_opener().open(url, timeout=timeout) as r:  # noqa: S310 (loopback, lab only)
        return json.loads(r.read())


def rss_kib(pid):
    for line in Path("/proc/%d/status" % pid).read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return -1


def wait_health(port, limit=60):
    t0 = time.time()
    while time.time() - t0 < limit:
        try:
            with plain_opener().open("http://127.0.0.1:%d/health" % port, timeout=2) as r:  # noqa: S310
                r.read()
            return True
        except (OSError, urllib.error.URLError):
            time.sleep(0.3)
    return False


class Admin:
    """The lab admin API on loopback (self-signed UI certificate; the password lives in a mode-0600 file)."""

    def __init__(self, secret_path):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # the lab UI's self-signed certificate on loopback
        self.op = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx),
                                              urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.base = "https://127.0.0.1:%d" % UI_PORT
        self.secret = Path(secret_path)

    def call(self, method, path, body=None, raw=False, timeout=20):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method,  # noqa: S310 (loopback, lab only)
                                     headers={"Content-Type": "application/json"})
        try:
            with self.op.open(req, timeout=timeout) as r:
                out = r.read()
                if raw:
                    return r.status, out
                return r.status, (json.loads(out) if out[:1] in (b"{", b"[") else out.decode()[:200])
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()[:300]

    def setup(self, ca_out, log_traffic=True):
        """Admin, auth exemption, the two rules and the inspection CA. Culvert keeps all of it in memory in this
        configuration, so it is done again after every start (a restart is a cold start of that state)."""
        pw = "Lab-" + secrets.token_urlsafe(12) + "9aZ"
        fd = os.open(str(self.secret), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, pw.encode())
        os.close(fd)
        steps = {"setup": self.call("POST", "/api/setup/complete", {"user": "admin", "pass": pw})[0],
                 "login": self.call("POST", "/api/auth/login", {"user": "admin", "pass": pw})[0],
                 "auth_rule": self.call("POST", "/api/authpolicy", AUTH_RULE)[0]}
        for rule in RULES:
            rule = dict(rule, logTraffic=log_traffic)
            _, pol = self.call("GET", "/api/policy")
            version = pol.get("version", 0) if isinstance(pol, dict) else 0
            steps[rule["name"]] = self.call("POST", "/api/policy?ifVersion=%d" % version, rule)[0]
        _, pol = self.call("GET", "/api/policy")
        rules = pol.get("rules") if isinstance(pol, dict) else pol
        names = [r.get("name") for r in (rules or [])]
        st, pem = self.call("GET", "/api/ca-cert", raw=True)
        if st != 200 or b"BEGIN CERTIFICATE" not in pem:
            raise RuntimeError("inspection CA not available: %s %r" % (st, pem[:80]))
        tmp = Path(str(ca_out) + ".tmp")
        tmp.write_bytes(pem)
        tmp.replace(ca_out)
        want = [r["name"] for r in RULES]
        if [n for n in names if n in want] != want:  # both rules, the inspect rule first
            raise RuntimeError("rules not in place: %r %r" % (steps, names))
        return steps, names

    def pd_blocks(self, limit=1000):
        """pd blocks (child-app path) of the latest feed entries, with the entry time."""
        st, page = self.call("GET", "/api/logs?limit=%d&offset=0" % limit, timeout=60)
        if st != 200 or not isinstance(page, dict):
            return []
        return [{"time": e.get("time") or e.get("ts"), "pd": e["pd"]} for e in page.get("logs") or [] if e.get("pd")]


class Proxy:
    def __init__(self, run_dir, binary, label, log_traffic=True):
        self.label, self.binary = label, binary
        self.data = run_dir / "data-endurance"
        self.data.mkdir(parents=True, exist_ok=True)
        self.log_path = run_dir / ("culvert-%s.log" % label)
        self.log_fh = self.log_path.open("wb")
        env = clean_env({"CULVERT_DATA_DIR": str(self.data), "SSL_CERT_FILE": str(run_dir / "certs/ca.pem"),
                         "CULVERT_LAB_METRICS_ADDR": "127.0.0.1:%d" % METRICS_PORT,
                         "CULVERT_LAB_PROTODETECT": "real", "CULVERT_LAB_PD_WINDOW_MS": "10000",
                         "CULVERT_LAB_CHILDAPP": "real"})
        self.t_start = time.time()
        self.proc = subprocess.Popen(  # noqa: S603
            [TASKSET, "-c", PROXY_CPUS, str(LAB / "bin" / binary), "-port", str(PROXY_PORT), "-ui-port", str(UI_PORT)],
            env=env, stdout=self.log_fh, stderr=subprocess.STDOUT, cwd=str(run_dir))
        try:
            if not wait_health(PROXY_PORT):
                raise RuntimeError("proxy did not start")
            self.admin = Admin(run_dir / "admin-endurance.secret")
            self.setup_steps, self.rules = self.admin.setup(run_dir / "inspect-ca.pem", log_traffic)
        except BaseException:
            self.stop()
            raise
        self.t_ready = time.time()

    def sample(self, gc=False):
        m = get_json("http://127.0.0.1:%d/lab/endurance%s" % (METRICS_PORT, "?gc=1" if gc else ""))
        m["rss_kib"] = rss_kib(self.proc.pid)
        m["pid"], m["proc"], m["binary"] = self.proc.pid, self.label, self.binary
        return m

    def heap_profile(self, path):
        with plain_opener().open("http://127.0.0.1:%d/debug/pprof/heap" % METRICS_PORT, timeout=30) as r:  # noqa: S310
            path.write_bytes(r.read())

    def goroutine_dump(self, path):
        url = "http://127.0.0.1:%d/debug/pprof/goroutine?debug=1" % METRICS_PORT
        with plain_opener().open(url, timeout=30) as r:  # noqa: S310
            path.write_bytes(r.read())

    def stop(self):
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log_fh.close()
        return self.proc.returncode


def scan_log(path):
    """Counts from a Culvert log: PROTODETECT records by direction outcome, panics, admission refusals and the
    engine counters of the last record."""
    out = {"records": 0, "refused": 0, "outcomes": {}, "panic_lines": 0, "last_engine_stats": None, "signals": {}}
    with open(path, "rb") as fh:
        for raw in fh:
            line = raw.decode("utf-8", "replace")
            if "panic" in line.lower() and "PROTODETECT" not in line:
                out["panic_lines"] += 1
            i = line.find("PROTODETECT {")
            if i < 0:
                continue
            try:
                rec = json.loads(line[i + len("PROTODETECT "):])
            except ValueError:
                continue
            out["records"] += 1
            if rec.get("admission") == "refused":
                out["refused"] += 1
            for side in ("client", "server"):
                d = rec.get(side) or {}
                key = "%s:%s/%s/%s" % (side, d.get("outcome", ""), d.get("family", ""), d.get("reason", ""))
                out["outcomes"][key] = out["outcomes"].get(key, 0) + 1
            for s in rec.get("signals") or []:
                out["signals"][s] = out["signals"].get(s, 0) + 1
            out["last_engine_stats"] = rec.get("engine_stats")
    return out


def releases(blocks):
    tally = {}
    for b in blocks:
        pd = b["pd"]
        key = "content=%s child=%s" % (pd.get("content_release", ""), pd.get("child_release", ""))
        tally[key] = tally.get(key, 0) + 1
    return tally


def run(manifest, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    run_dir = LAB / "run-endurance"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    samples_fh = (out_dir / "samples.jsonl").open("w")
    phases = {"manifest": manifest, "events": [], "procs": {}}

    def event(name, **kw):
        e = dict(kw, name=name, t_unix=round(time.time(), 3))
        phases["events"].append(e)
        print(time.strftime("%H:%M:%S"), name, json.dumps(kw)[:300], flush=True)

    def record(proxy, phase, gc=False, blocks=True):
        try:
            s = proxy.sample(gc=gc)
        except (OSError, urllib.error.URLError, ValueError) as e:
            s = {"error": str(e)[:200], "proc": proxy.label}
        s["t_unix"], s["phase"] = round(time.time(), 3), phase
        if blocks and "error" not in s:
            try:
                s["pd_releases"] = releases(proxy.admin.pd_blocks())
            except (OSError, urllib.error.URLError, ValueError) as e:
                s["pd_releases_error"] = str(e)[:200]
        samples_fh.write(json.dumps(s, sort_keys=True) + "\n")
        samples_fh.flush()
        return s

    origin = subprocess.Popen(  # noqa: S603
        [TASKSET, "-c", ORIGIN_CPUS, str(LAB / "bin/endurance-load"), "origin", "-addr", "203.0.113.10",
         "-certs", str(run_dir / "certs")], stdout=(run_dir / "origin.log").open("wb"), stderr=subprocess.STDOUT)
    time.sleep(1.5)
    proxy = None
    try:
        # Reference baselines of both binaries, idle, each in a fresh process (not part of the pass conditions).
        for label, binary in (("ref-v8", manifest["binary_before"]), ("ref-v9", manifest["binary_after"])):
            p = Proxy(run_dir, binary, label)
            time.sleep(manifest["idle_s"])
            for _ in range(3):
                record(p, "reference-idle", gc=True)
                time.sleep(5)
            phases["procs"][label] = {"binary": binary, "rc": p.stop(), "log": scan_log(p.log_path)}
            shutil.rmtree(run_dir / "data-endurance", ignore_errors=True)
        # The run: process 1.
        proxy = Proxy(run_dir, manifest["binary_before"], "p1")
        event("proc_start", proc="p1", binary=proxy.binary, setup=proxy.setup_steps)
        time.sleep(manifest["idle_s"])
        base = []
        for _ in range(3):
            base.append(record(proxy, "baseline", gc=True))
            time.sleep(5)
        proxy.heap_profile(out_dir / "heap-p1-baseline.pb.gz")
        event("baseline", goroutines=[b.get("goroutines") for b in base], heap_live=[b.get("heap_live") for b in base])
        drv_out = out_dir / "driver.jsonl"
        corpus = ",".join(manifest["corpus_dirs"])
        driver = subprocess.Popen(  # noqa: S603
            [TASKSET, "-c", DRIVER_CPUS, str(LAB / "bin/endurance-load"), "drive", "-proxy", "127.0.0.1:%d" % PROXY_PORT,
             "-duration", "%ds" % manifest["load_s"], "-interval", "30s", "-ca", str(run_dir / "certs/ca.pem"),
             "-inspect-ca", str(run_dir / "inspect-ca.pem"), "-corpus", corpus, "-out", str(drv_out)],
            stdout=(run_dir / "driver.log").open("wb"), stderr=subprocess.STDOUT)
        t0 = time.time()
        event("load_start")
        plan = sorted(manifest["actions"], key=lambda a: a["at_s"])
        next_sample = t0 + manifest["sample_s"]
        while driver.poll() is None:
            now = time.time()
            if plan and now - t0 >= plan[0]["at_s"]:
                act = plan.pop(0)
                record(proxy, "pre-" + act["name"])
                proxy.heap_profile(out_dir / ("heap-%s-before-%s.pb.gz" % (proxy.label, act["name"])))
                rc = proxy.stop()
                t_down = time.time()
                phases["procs"][proxy.label] = {"binary": proxy.binary, "rc": rc, "log": scan_log(proxy.log_path),
                                                "t_start": proxy.t_start, "t_ready": proxy.t_ready, "t_stop": t_down}
                event("proc_stop", proc=proxy.label, rc=rc, action=act["name"])
                proxy = Proxy(run_dir, act["binary"], act["proc"])
                event("proc_start", proc=proxy.label, binary=proxy.binary, setup=proxy.setup_steps,
                      downtime_s=round(proxy.t_ready - t_down, 2))
                continue
            if now >= next_sample:
                record(proxy, "load")
                next_sample += manifest["sample_s"]
            time.sleep(0.2)
        t_stop = time.time()
        event("load_stop", driver_rc=driver.returncode, load_s=round(t_stop - t0, 1))
        # Recovery: forced-GC samples every 5 s for 60 s, then 30 s samples for 2 more minutes.
        while time.time() - t_stop < 60:
            record(proxy, "recovery", gc=True, blocks=False)
            time.sleep(5)
        record(proxy, "recovery", gc=True)
        proxy.heap_profile(out_dir / ("heap-%s-recovery.pb.gz" % proxy.label))
        while time.time() - t_stop < manifest["post_s"]:
            time.sleep(manifest["sample_s"])
            record(proxy, "post", gc=True, blocks=False)
    finally:
        if proxy is not None:
            rc = proxy.stop()
            info = phases["procs"].setdefault(proxy.label, {"binary": proxy.binary})
            info.update({"rc": rc, "log": scan_log(proxy.log_path), "t_start": proxy.t_start, "t_ready": proxy.t_ready,
                         "t_stop": time.time()})
        origin.terminate()
        origin.wait()
        samples_fh.close()
        (out_dir / "phases.json").write_text(json.dumps(phases, indent=1, sort_keys=True))
        for p in run_dir.glob("culvert-p*.log"):
            lines = p.read_bytes().splitlines(keepends=True)
            keep = [ln for ln in lines if b"PROTODETECT" not in ln][-200:]
            (out_dir / (p.stem + "-tail.log")).write_bytes(b"".join(keep))


# ---------- diagnostics (after the run; not pass conditions) ----------

def diag(manifest, out_dir, idle_s=300, load_s=120):
    """D1: no load at all, goroutines and live heap every 15 s for idle_s, goroutine dumps at 60 s and at the end.
    D2/D3: baseline, load_s of the same mix, 60 s of recovery, with the rules' traffic logging off (D2) and on
    (D3). Same binary (culvert-lab-v9) throughout."""
    out_dir.mkdir(parents=True, exist_ok=True)
    run_dir = LAB / "run-diag"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    binary = manifest["binary_after"]
    fh = (out_dir / "diag-samples.jsonl").open("w")
    origin = subprocess.Popen(  # noqa: S603
        [TASKSET, "-c", ORIGIN_CPUS, str(LAB / "bin/endurance-load"), "origin", "-addr", "203.0.113.10",
         "-certs", str(run_dir / "certs")], stdout=(run_dir / "origin.log").open("wb"), stderr=subprocess.STDOUT)
    time.sleep(1.5)

    def rec(p, case, phase, t0):
        s = p.sample(gc=True)
        s.update(case=case, phase=phase, t_rel_s=round(time.time() - t0, 1), t_unix=round(time.time(), 3))
        fh.write(json.dumps(s, sort_keys=True) + "\n")
        fh.flush()
        print(case, phase, s["t_rel_s"], s["goroutines"], s["heap_live"], flush=True)

    try:
        p = Proxy(run_dir, binary, "d1")
        t0 = p.t_ready
        try:
            while time.time() - t0 < idle_s:
                rec(p, "D1-idle", "idle", t0)
                if abs(time.time() - t0 - 60) < 8 and not (out_dir / "diag-D1-goroutines-60s.txt").exists():
                    p.goroutine_dump(out_dir / "diag-D1-goroutines-60s.txt")
                time.sleep(15)
            p.goroutine_dump(out_dir / "diag-D1-goroutines-end.txt")
        finally:
            p.stop()
        for case, log_traffic in (("D2-log-off", False), ("D3-log-on", True)):
            shutil.rmtree(run_dir / "data-endurance", ignore_errors=True)
            p = Proxy(run_dir, binary, case, log_traffic=log_traffic)
            t0 = p.t_ready
            try:
                time.sleep(manifest["idle_s"])
                for _ in range(3):
                    rec(p, case, "baseline", t0)
                    time.sleep(5)
                drv = subprocess.run(  # noqa: S603
                    [TASKSET, "-c", DRIVER_CPUS, str(LAB / "bin/endurance-load"), "drive", "-proxy",
                     "127.0.0.1:%d" % PROXY_PORT, "-duration", "%ds" % load_s, "-interval", "30s",
                     "-ca", str(run_dir / "certs/ca.pem"), "-inspect-ca", str(run_dir / "inspect-ca.pem"),
                     "-corpus", ",".join(manifest["corpus_dirs"]), "-out", str(out_dir / ("diag-%s-driver.jsonl" % case))],
                    stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=False)
                t_stop = time.time()
                while time.time() - t_stop < 60:
                    rec(p, case, "recovery", t0)
                    time.sleep(5)
                rec(p, case, "recovery", t0)
                print(case, "driver rc", drv.returncode, flush=True)
            finally:
                p.stop()
    finally:
        origin.terminate()
        origin.wait()
        fh.close()


# ---------- verdict ----------

def load_samples(d):
    """samples.jsonl as written by the run, or samples.json (the same rows as one JSON array, as committed:
    the repository ignores *.jsonl)."""
    if (d / "samples.jsonl").exists():
        return [json.loads(ln) for ln in (d / "samples.jsonl").read_text().splitlines() if ln.strip()]
    return json.loads((d / "samples.json").read_text())


def slope_per_min(points):
    """Least-squares slope of (t_s, y) points, in y per minute."""
    n = len(points)
    if n < 3:
        return None
    mx = sum(p[0] for p in points) / n
    my = sum(p[1] for p in points) / n
    sxx = sum((p[0] - mx) ** 2 for p in points)
    return 60.0 * sum((p[0] - mx) * (p[1] - my) for p in points) / sxx if sxx else None


def verdict(d):
    samples, phases = load_samples(d), json.loads((d / "phases.json").read_text())
    th = phases["manifest"]["thresholds"]
    ev = {e["name"]: e for e in phases["events"]}
    stop_t = ev["load_stop"]["t_unix"]
    base = [s for s in samples if s.get("phase") == "baseline" and "error" not in s]
    b_gor = sorted(s["goroutines"] for s in base)[len(base) // 2]
    b_heap = sorted(s["heap_live"] for s in base)[len(base) // 2]
    rec = [s for s in samples if s.get("phase") == "recovery" and "error" not in s]
    out = {"baseline": {"goroutines": b_gor, "heap_live": b_heap}}

    def within(v, b):
        return abs(v - b) <= th["recovery_pct"] / 100.0 * b

    first_ok = None
    for s in rec:
        if within(s["goroutines"], b_gor) and within(s["heap_live"], b_heap):
            first_ok = round(s["t_unix"] - stop_t, 1)
            break
    last = rec[-1] if rec else None
    out["recovery"] = {
        "samples": [{"t_after_stop_s": round(s["t_unix"] - stop_t, 1), "goroutines": s["goroutines"],
                     "heap_live": s["heap_live"], "heap_inuse": s["heap_inuse"], "open_fds": s["open_fds"],
                     "rss_kib": s["rss_kib"], "pd_active": (s.get("pd_engine_stats") or {}).get("active"),
                     "pd_reserved_bytes": (s.get("pd_engine_stats") or {}).get("reserved_bytes")} for s in rec],
        "first_within_s": first_ok,
        "pass": first_ok is not None and first_ok <= th["recovery_within_s"]
        and within(last["goroutines"], b_gor) and within(last["heap_live"], b_heap),
    }
    # Steady phase: load samples of the last process, from steady_skip_s after it became ready.
    procs = phases["procs"]
    slopes = {}
    for label in sorted(k for k in procs if k.startswith("p")):
        info = procs[label]
        pts = [s for s in samples if s.get("proc") == label and s.get("phase") == "load" and "error" not in s
               and s["t_unix"] >= info.get("t_ready", 0) + th["steady_skip_s"]]
        if len(pts) < 3:
            continue
        t0 = pts[0]["t_unix"]
        sl = {k: slope_per_min([(s["t_unix"] - t0, s[k]) for s in pts]) for k in ("goroutines", "heap_live", "rss_kib", "open_fds")}
        sl["pd_active"] = slope_per_min([(s["t_unix"] - t0, s["pd_engine_stats"]["active"]) for s in pts])
        means = {k: sum(s[k] for s in pts) / len(pts) for k in ("goroutines", "heap_live", "rss_kib", "open_fds")}
        rel = {k: (100.0 * sl[k] / means[k] if means[k] else 0.0) for k in means}
        slopes[label] = {"n": len(pts), "span_min": round((pts[-1]["t_unix"] - t0) / 60, 1), "slope_per_min": sl,
                         "slope_pct_of_mean_per_min": rel,
                         "pass": all(abs(v) <= th["steady_slope_pct_per_min"] for v in rel.values())}
    out["steady"] = {"per_proc": slopes, "pass": bool(slopes) and all(v["pass"] for v in slopes.values())}
    # Panics and leaked reservations.
    panics = {k: {"engine_panics": ((v.get("log") or {}).get("last_engine_stats") or {}).get("panics"),
                  "panic_lines": (v.get("log") or {}).get("panic_lines"), "rc": v.get("rc")} for k, v in procs.items()}
    last_st = (last or {}).get("pd_engine_stats") or {}
    out["panics"] = {"per_proc": panics, "pass": all((v["engine_panics"] or 0) == 0 and v["panic_lines"] == 0
                                                     for v in panics.values())}
    out["reservations"] = {"after_load": {k: last_st.get(k) for k in ("active", "reserved_bytes", "retained_bytes")},
                           "pass": bool(last_st) and last_st.get("active") == 0 and last_st.get("reserved_bytes") == 0
                           and last_st.get("retained_bytes") == 0}
    # Versions: every pd block seen in a process's samples carries that process's expected release.
    exp = phases["manifest"]["expected_release"]
    ver = {}
    for label in sorted(k for k in procs if k.startswith("p")):
        seen = {}
        for s in samples:
            if s.get("proc") == label:
                for key, n in (s.get("pd_releases") or {}).items():
                    seen[key] = max(seen.get(key, 0), n)
        want = exp[procs[label]["binary"]]
        ver[label] = {"binary": procs[label]["binary"], "expected": want, "seen": seen,
                      "pass": bool(seen) and set(seen) == {want}}
    out["versions"] = {"per_proc": ver, "pass": bool(ver) and all(v["pass"] for v in ver.values())}
    out["all_pass"] = all(out[k]["pass"] for k in ("recovery", "steady", "panics", "reservations", "versions"))
    (d / "verdict.json").write_text(json.dumps(out, indent=1, sort_keys=True))
    return out


def self_test():
    assert abs(slope_per_min([(0, 0), (60, 1), (120, 2)]) - 1.0) < 1e-9
    assert slope_per_min([(0, 1), (1, 1)]) is None
    assert releases([{"pd": {"content_release": "2026.11.9", "child_release": "2026.11.1"}}] * 2) == \
        {"content=2026.11.9 child=2026.11.1": 2}
    assert [r["name"] for r in RULES] == ["lab-inspect-googleapis", "lab-bypass-rest"]
    assert RULES[0]["sslAction"] == "Inspect" and RULES[1]["sslAction"] == "Bypass"
    print("endurance run self-test: ok")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest")
    ap.add_argument("--out")
    ap.add_argument("--verdict")
    ap.add_argument("--diag", action="store_true", help="the diagnostics D1-D3 (with --manifest and --out)")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        self_test()
        return 0
    if a.verdict:
        print(json.dumps(verdict(Path(a.verdict)), indent=1, sort_keys=True))
        return 0
    if a.diag:
        diag(json.loads(Path(a.manifest).read_text()), Path(a.out))
        return 0
    run(json.loads(Path(a.manifest).read_text()), Path(a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
