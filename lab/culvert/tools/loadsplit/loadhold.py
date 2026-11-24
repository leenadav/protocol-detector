"""Memory per 1,000 concurrent tunnels in the plan's three memory states (PRO-269, working plan 8.3).

Opens N CONNECT bypass tunnels to origin.lab.test:443 through one fresh proxy and keeps them silent, so on the
observe-mode build every tunnel holds a detector flow until its observation window ends. The proxy's RSS is the
median of 10 samples over 1 s:

  idle       before the tunnels are opened
  open       all N tunnels open, within the observation window (on D: actively observing)
  after      the window has ended and the tunnels are still open (on D: flows finished, tunnel held)

Builds and paths as in loadtest.py. Needs the load origin running (loadtest.py starts and stops its own; this
script starts one too). Loopback and synthetic only.

  python3 loadhold.py --out <dir> [--tunnels 1000] [--window-ms 10000] [--rounds 3]
"""
import argparse, json, os, socket, statistics, subprocess, time

import loadtest

PROXY = ("127.0.0.1", loadtest.PORT)


def settle_rss(pid):
    samples = []
    for _ in range(10):
        samples.append(loadtest.rss_kib(pid))
        time.sleep(0.1)
    return statistics.median(samples) / 1024


def open_tunnels(n):
    socks = []
    for _ in range(n):
        s = socket.create_connection(PROXY, timeout=10)
        s.sendall(b"CONNECT origin.lab.test:443 HTTP/1.1\r\nHost: origin.lab.test:443\r\n\r\n")
        reply = b""
        while b"\r\n\r\n" not in reply:
            chunk = s.recv(1024)
            if not chunk:
                raise OSError("proxy closed a CONNECT before replying")
            reply += chunk
        if not reply.startswith(b"HTTP/1.1 200"):
            raise OSError(f"CONNECT refused: {reply[:60]!r}")
        socks.append(s)
    return socks


def hold(lab, run_dir, build, n, window_ms):
    loadtest.BUILDS["D"][1]["CULVERT_LAB_PD_WINDOW_MS"] = str(window_ms)
    loadtest.drain_time_wait()
    p, log = loadtest.start_proxy(lab, build, run_dir)
    socks = []
    try:
        time.sleep(1)
        idle = settle_rss(p.pid)
        t0 = time.time()
        socks = open_tunnels(n)
        opened_s = time.time() - t0
        time.sleep(1)
        during = settle_rss(p.pid)
        if time.time() - t0 > window_ms / 1000 - 0.5:
            raise SystemExit(f"opening {n} tunnels took {opened_s:.1f} s, past the window; raise --window-ms")
        time.sleep(max(0.0, window_ms / 1000 - (time.time() - t0)) + 2)
        after = settle_rss(p.pid)
        alive = sum(1 for s in socks if s.fileno() >= 0)
    finally:
        for s in socks:
            s.close()
        time.sleep(window_ms / 1000 + 1 if build == "D" else 1)  # let the last records be written
        loadtest.stop_proxy(p, log)
    _, pd, refused = loadtest.log_counts(log.name)
    return {"build": build, "tunnels": n, "open_s": opened_s, "rss_idle_mib": idle, "rss_open_mib": during,
            "rss_after_window_mib": after, "per_tunnel_open_kib": (during - idle) * 1024 / n,
            "per_tunnel_after_kib": (after - idle) * 1024 / n, "alive": alive, "pd_records": pd,
            "pd_refused": refused}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lab", default="/home/user/culvert-lab")
    ap.add_argument("--out", required=True)
    ap.add_argument("--tunnels", type=int, default=1000)
    ap.add_argument("--window-ms", type=int, default=10000)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--builds", default="A,B,D")
    a = ap.parse_args()
    run_dir = os.path.join(a.lab, "run")
    os.makedirs(a.out, exist_ok=True)
    origin = subprocess.Popen(["taskset", "-c", loadtest.ORIGIN_CPUS, os.path.join(a.lab, "bin", "loadorigin-split"),  # noqa: S603, S607  (fixed argv, lab binary; loopback lab only)
                               "-cert", os.path.join(run_dir, "origin.pem")],
                              stdout=open(os.path.join(run_dir, "loadorigin.log"), "w"), stderr=subprocess.STDOUT)
    time.sleep(1)
    rows = []
    try:
        builds = a.builds.split(",")
        for rnd in range(a.rounds):
            for build in builds[rnd % len(builds):] + builds[:rnd % len(builds)]:
                r = dict(hold(a.lab, run_dir, build, a.tunnels, a.window_ms), round=rnd, window_ms=a.window_ms)
                rows.append(r)
                print(f"round {rnd} {build}: idle {r['rss_idle_mib']:.1f} open {r['rss_open_mib']:.1f}"
                      f" after {r['rss_after_window_mib']:.1f} MiB; per tunnel open {r['per_tunnel_open_kib']:.1f}"
                      f" after {r['per_tunnel_after_kib']:.1f} KiB; pd {r['pd_records']}", flush=True)
                with open(os.path.join(a.out, "hold.json"), "w") as f:
                    json.dump(rows, f, indent=1)
    finally:
        origin.terminate()


if __name__ == "__main__":
    main()
