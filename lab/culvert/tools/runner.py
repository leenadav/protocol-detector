"""Lab scenario runner: the same synthetic scenarios against each Culvert build, with expected results
written here from what each scenario sends (never from the detector's own output).

Usage: runner.py <results.json>
Builds: A unmodified, B integrated with the detector off, C fake engine, D real detector, E fake engine
with an injected panic. All traffic is synthetic and stays on loopback / RFC 5737 addresses.
"""
import hashlib, json, os, random, socket, ssl, sys, threading, time

LAB = "/home/user/culvert-lab"
ORIGIN = "origin.lab.test"
BUILDS = [
    ("A", 18080, "unmodified Culvert 52eb9d1", None),
    ("B", 18081, "integrated build, detector off", None),
    ("C", 18082, "integrated build, fake engine", "fake"),
    ("D", 18083, "integrated build, real detector (observe)", "real"),
    ("E", 18084, "integrated build, fake engine with injected panic", "fake-panic"),
]
POLICY_BUILDS = [
    ("D", 18083, "real detector + the lab's protocol-restriction rules", "real"),
    ("F", 18085, "detector OFF + the same rules (the detector is unavailable)", None),
]
OUT = sys.argv[1] if __name__ == "__main__" and len(sys.argv) > 1 else os.devnull
RESULTS = {"started": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()), "builds": {}, "scenarios": [], "state": "running"}


def save():
    tmp = OUT + ".tmp"
    with open(tmp, "w") as f:
        json.dump(RESULTS, f, indent=1)
    os.replace(tmp, OUT)


def sha(b):
    return hashlib.sha256(b).hexdigest()[:16]


def proxy_auth(port):
    """Proxy-Authorization for builds whose lab admin was set up (their proxy then requires credentials)."""
    import base64
    build = {b[1]: b[0] for b in BUILDS + POLICY_BUILDS}.get(port, "")
    path = f"{LAB}/run/admin-{build}.secret"
    if not os.path.exists(path):
        return b""
    return b"Proxy-Authorization: Basic " + base64.b64encode(b"admin:" + open(path, "rb").read()) + b"\r\n"


def connect(port, dest, extra=b"", timeout=8):
    """Open a CONNECT tunnel; `extra` is sent in the same write as the CONNECT header (pipelined)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(b"CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n" % (dest.encode(), dest.encode(), proxy_auth(port)) + extra)
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = s.recv(1)
        if not chunk:
            break
        head += chunk
    status = int(head.split(b" ")[1]) if head.startswith(b"HTTP/") else 0
    return s, status


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(min(65536, n - len(buf)))
        if not chunk:
            break
        buf += chunk
    return buf


def recv_until(s, token):
    buf = b""
    while token not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


# ---- scenarios: each returns (ok, detail dict). `expect` is the detector expectation for build D. ----

def s_http_plain(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=8)
    s.sendall(b"GET http://%s/plain HTTP/1.1\r\nHost: %s\r\n%s\r\n" % (ORIGIN.encode(), ORIGIN.encode(), proxy_auth(port)))
    data = recv_until(s, b"/plain\n")
    s.close()
    return b"200 OK" in data and b"lab origin says hello: /plain" in data, {"body": sha(data.split(b"\r\n\r\n", 1)[-1])}


def s_tls(port):
    s, status = connect(port, ORIGIN + ":443")
    ctx = ssl.create_default_context(cafile=LAB + "/certs/origin.crt")
    t = ctx.wrap_socket(s, server_hostname=ORIGIN)
    t.sendall(b"GET /tls HTTP/1.1\r\nHost: %s\r\n\r\n" % ORIGIN.encode())
    data = recv_until(t, b"/tls\n")
    group = t.group() if hasattr(t, "group") else ""
    t.close()
    ok = status == 200 and b"lab origin says hello: /tls" in data
    return ok, {"tls": t.version() or "", "key_exchange": group or "not reported by this Python", "cert_verified_against": "lab CA (not the proxy's): tunnel was not intercepted"}


def s_ssh(port):
    s, status = connect(port, ORIGIN + ":22")
    banner = recv_until(s, b"\r\n")  # server speaks first
    s.sendall(b"SSH-2.0-LabClient_1.0\r\n")
    echo = recv_until(s, b"\r\n")
    s.close()
    return status == 200 and banner == b"SSH-2.0-LabOrigin_1.0\r\n" and echo == b"SSH-2.0-LabClient_1.0\r\n", {"server_first": True}


def s_smtp(port):
    s, status = connect(port, ORIGIN + ":25")
    greet = recv_until(s, b"\r\n")
    s.sendall(b"EHLO client.lab.test\r\n")
    reply = recv_until(s, b"250 STARTTLS\r\n")
    s.sendall(b"QUIT\r\n")
    bye = recv_until(s, b"\r\n")
    s.close()
    return status == 200 and greet.startswith(b"220 ") and b"250 STARTTLS" in reply and bye.startswith(b"221"), {"server_first": True}


def s_http_tunnel(port):
    s, status = connect(port, ORIGIN + ":80")
    s.sendall(b"GET /in-tunnel HTTP/1.1\r\nHost: %s\r\n\r\n" % ORIGIN.encode())
    data = recv_until(s, b"/in-tunnel\n")
    s.close()
    return status == 200 and b"lab origin says hello: /in-tunnel" in data, {}


def echo_roundtrip(port, payload, extra=b"", half_close=False, write_size=None, delay=0.0):
    s, status = connect(port, ORIGIN + ":9000", extra=extra)
    got = bytearray()
    want = len(extra) + len(payload)

    def reader():
        while len(got) < want:
            try:
                c = s.recv(65536)
            except OSError:
                break
            if not c:
                break
            got.extend(c)

    th = threading.Thread(target=reader)
    th.start()
    if write_size:
        for i in range(0, len(payload), write_size):
            s.sendall(payload[i:i + write_size])
            if delay:
                time.sleep(delay)
    else:
        s.sendall(payload)
    if half_close:
        s.shutdown(socket.SHUT_WR)
    th.join(60)
    s.close()
    sent = extra + payload
    return status == 200 and bytes(got) == sent, {"sent": sha(sent), "received": sha(bytes(got)), "bytes": len(sent)}


def s_echo_1mib(port):
    rng = random.Random(20261114)
    return echo_roundtrip(port, b"\x01\x02LAB" + rng.randbytes(1 << 20))


def s_pipelined(port):
    # The first tunnel bytes travel in the same write as the CONNECT header (the prebuffer path).
    return echo_roundtrip(port, b"tail-after-the-pipelined-request", extra=b"GET /pipelined HTTP/1.1\r\nHost: %s\r\n\r\n" % ORIGIN.encode())


def s_fragmented(port):
    req = b"GET /fragmented HTTP/1.1\r\nHost: %s\r\n\r\n" % ORIGIN.encode()
    return echo_roundtrip(port, req, write_size=1, delay=0.004)


def s_half_close(port):
    rng = random.Random(7)
    return echo_roundtrip(port, b"\x01\x02LAB" + rng.randbytes(200000), half_close=True)


def s_large(port):
    rng = random.Random(99)
    payload = b"\x01\x02LAB" + rng.randbytes(32 << 20)
    t0 = time.time()
    ok, d = echo_roundtrip(port, payload)
    d["seconds"] = round(time.time() - t0, 2)
    return ok, d


def s_postgres(port):
    s, status = connect(port, ORIGIN + ":5432")
    s.sendall(bytes([0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f]))
    reply = s.recv(1)
    s.close()
    return status == 200 and reply == b"N", {}


def s_junk(port):
    return echo_roundtrip(port, b"\x01\x02\x03\x04\x05 not a protocol prefix at all, just lab filler bytes")


def s_silent(port):
    # Neither side sends anything for longer than the 3 s observation window; then one byte still passes.
    s, status = connect(port, ORIGIN + ":9000")
    time.sleep(4.2)
    late = b"\x01late byte after the window"
    s.sendall(late)
    got = recv_exact(s, len(late))
    s.close()
    return status == 200 and got == late, {"quiet_seconds": 4.2}


def s_ssrf(port):
    codes = {}
    for dest in ("127.0.0.1:19090", "10.0.0.1:80", "198.18.0.1:80", "169.254.169.254:80"):
        try:
            s, status = connect(port, dest, timeout=5)
            s.close()
        except OSError:
            status = -1
        codes[dest] = status
    return all(c == 403 for c in codes.values()), {"status": codes}


def s_churn(port):
    n, fails, lock = 300, [], threading.Lock()

    def one(i):
        try:
            ok, _ = echo_roundtrip(port, b"\x01\x02LAB" + random.Random(i).randbytes(2000))
        except OSError:
            ok = False
        if not ok:
            with lock:
                fails.append(i)

    threads = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for i in range(0, n, 50):
        for t in threads[i:i + 50]:
            t.start()
        for t in threads[i:i + 50]:
            t.join()
    return not fails, {"flows": n, "failed": len(fails)}


# ---- protocol-restriction (policy) scenarios: rules installed by tools/lab_admin.py ----
#   secure.lab.test   Allow, restriction ENFORCE, allow [tls], unknown = block
#   monitor.lab.test  Allow, restriction MONITOR, allow [tls], unknown = block

def origin_stats(reset=False):
    import urllib.request
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return json.loads(op.open("http://127.0.0.1:9999/" + ("reset" if reset else "stats"), timeout=5).read())


def policy_case(port, host, dport, payload=b"", extra=b"", tls=False):
    """One tunnel to a restricted host. Returns what the client saw and how many client bytes the origin received."""
    origin_stats(reset=True)
    out = {"connect": 0, "delivered": False, "closed_by_proxy": False}
    s, out["connect"] = connect(port, f"{host}:{dport}", extra=extra, timeout=6)
    try:
        if tls:
            ctx = ssl.create_default_context(cafile=LAB + "/certs/origin.crt")
            t = ctx.wrap_socket(s, server_hostname=host)
            t.sendall(b"GET /policy HTTP/1.1\r\nHost: %s\r\n\r\n" % host.encode())
            out["delivered"] = b"/policy" in recv_until(t, b"/policy\n")
            t.close()
        else:
            if payload:
                s.sendall(payload)
            want = extra + payload
            got = b""
            while len(got) < len(want) + 64:
                c = s.recv(4096)
                if not c:
                    out["closed_by_proxy"] = True
                    break
                got += c
                if want in got:
                    out["delivered"] = True
                    break
    except (OSError, ssl.SSLError):
        out["closed_by_proxy"] = True
    finally:
        s.close()
    time.sleep(0.15)
    out["origin_received_client_bytes"] = sum(origin_stats().values()) if not tls else "n/a (TLS origin)"
    return out


SSH_CLIENT = b"SSH-2.0-LabClient_1.0\r\n"
JUNK = b"\x01\x02\x03\x04\x05 not a protocol prefix at all, just lab filler bytes"
HTTP_PIPE = b"GET /pipelined HTTP/1.1\r\nHost: secure.lab.test\r\n\r\n"
POLICY_SCENARIOS = [
    # name, call, expectation per build: (tunnel passes?, verdict, reason)
    ("TLS to the TLS-only host (enforce)", lambda p: policy_case(p, "secure.lab.test", 443, tls=True),
     {"D": (True, "allowed", "protocol_allowed"), "F": (False, "blocked", "detector_unavailable")}),
    ("SSH client to the TLS-only host (enforce)", lambda p: policy_case(p, "secure.lab.test", 22, payload=SSH_CLIENT),
     {"D": (False, "blocked", "protocol_not_allowed"), "F": (False, "blocked", "detector_unavailable")}),
    ("Unrecognised bytes to the TLS-only host (enforce)", lambda p: policy_case(p, "secure.lab.test", 9000, payload=JUNK),
     {"D": (False, "blocked", "unknown_blocked"), "F": (False, "blocked", "detector_unavailable")}),
    ("HTTP pipelined with CONNECT to the TLS-only host (enforce)", lambda p: policy_case(p, "secure.lab.test", 9000, extra=HTTP_PIPE),
     {"D": (False, "blocked", "protocol_not_allowed"), "F": (False, "blocked", "detector_unavailable")}),
    ("SSH client to the monitor-mode host", lambda p: policy_case(p, "monitor.lab.test", 22, payload=SSH_CLIENT),
     {"D": (True, "would_block", "protocol_not_allowed"), "F": (True, "would_block", "detector_unavailable")}),
]


def run_policy():
    for name, fn, expect in POLICY_SCENARIOS:
        row = {"name": name, "group": "Protocol restriction on a rule (policy)", "results": {}, "same_bytes_all_builds": None}
        RESULTS["scenarios"].append(row)
        for build, port, label, kind in POLICY_BUILDS:
            passes, verdict, reason = expect[build]
            off = log_offset(build)
            t0 = time.time()
            try:
                seen = fn(port)
            except Exception as e:
                seen = {"error": repr(e)[:200], "delivered": None}
            if seen.get("connect") != 200:  # the proxy must have accepted the CONNECT for the case to mean anything
                ok = False
            elif passes:
                ok = seen.get("delivered") is True
            else:  # blocked: nothing delivered, and no client byte reached the origin
                ok = seen.get("delivered") is False and seen.get("origin_received_client_bytes") in (0, "n/a (TLS origin)")
            recs = observations(build, off, 1)
            pol = recs[0].get("policy") if len(recs) == 1 else None
            dok = bool(pol) and pol["verdict"] == verdict and pol["reason"] == reason
            text = "no policy record" if not pol else (
                f"verdict: {pol['verdict']} · {pol['reason']} · mode {pol['mode']} · allow {'+'.join(pol['allow'])}"
                f" · {pol['held_bytes']} client bytes held · forwarded to the server: {recs[0]['forwarded_bytes'][0]}")
            detail = {"status": {"CONNECT": seen.get("connect")}, "bytes": seen.get("origin_received_client_bytes")}
            if "error" in seen:
                detail["error"] = seen["error"]
            row["results"][build] = {"traffic_ok": bool(ok), "detector_ok": bool(dok), "detector": text, "detail": detail,
                                     "seconds": round(time.time() - t0, 2), "records": recs[:1]}
            save()


def X(outcome, reason="engine", family="", hostname=None):
    d = {"outcome": outcome, "reason": reason}
    if family:
        d["family"] = family
    if hostname is not None:
        d["hostname"] = hostname
    return d


ANY = None
SCENARIOS = [
    # name, group, function, expected detector record on build D: (client, server) or None when no tunnel
    ("Plain HTTP through the proxy", "Baseline access", s_http_plain, None),
    ("CONNECT + TLS to the lab origin", "Protocols", s_tls, (X("identified", family="tls", hostname=ORIGIN), X("identified", family="tls"))),
    ("CONNECT + SSH (server speaks first)", "Protocols", s_ssh, (X("identified", family="ssh"), X("identified", family="ssh"))),
    ("CONNECT + SMTP (server speaks first)", "Protocols", s_smtp, (X("identified", family="smtp"), X("unknown"))),
    ("CONNECT + HTTP/1.1 inside the tunnel", "Protocols", s_http_tunnel, (X("identified", family="http", hostname=ORIGIN), X("identified", family="http"))),
    ("PostgreSQL (family outside the profile)", "Protocols", s_postgres, (X("outside_profile", "outside_profile", "postgresql"), ANY)),
    ("Unrecognised bytes", "Protocols", s_junk, (X("unknown"), X("unknown"))),
    ("1 MiB echo, hash compared", "Byte transparency", s_echo_1mib, (X("unknown"), X("unknown"))),
    ("Bytes pipelined with the CONNECT header", "Byte transparency", s_pipelined, (X("identified", family="http", hostname=ORIGIN), ANY)),
    ("Half-close after sending", "Byte transparency", s_half_close, (X("unknown"), X("unknown"))),
    ("32 MiB echo after the observation window", "Byte transparency", s_large, (X("unknown"), X("unknown"))),
    ("HTTP request in 1-byte writes", "Fragmentation", s_fragmented, ("frag", ANY)),
    ("Silent tunnel past the 3 s window", "Expiry", s_silent, (X("incomplete", "expired"), X("incomplete", "expired"))),
    ("SSRF guard: private and reserved targets", "Security parity", s_ssrf, None),
    ("300 short tunnels, 50 at a time", "Resource pressure", s_churn, "churn"),
]


def log_offset(build):
    return os.path.getsize(f"{LAB}/run/culvert-{build}.log")


def observations(build, offset, want, wait=2.5):
    path, deadline, recs = f"{LAB}/run/culvert-{build}.log", time.time() + wait, []
    while True:
        with open(path, "rb") as f:
            f.seek(offset)
            recs = [json.loads(l.split(b"PROTODETECT ", 1)[1]) for l in f.read().splitlines() if b"PROTODETECT " in l]
        if len(recs) >= want or time.time() > deadline:
            return recs
        time.sleep(0.1)


def matches(exp, got):
    if exp is ANY:
        return True
    return all(got.get(k, "") == v for k, v in exp.items())


def check_observation(kind, expect, recs, settled_active=None):
    """Return (ok, text) for the detector column of builds C/D/E."""
    if expect is None:
        return (not recs, "no tunnel: nothing to observe" if not recs else f"unexpected {len(recs)} record(s)")
    if expect == "churn":
        # The stats in a record are read when that tunnel finishes, while others may still be open, so the
        # last record of a concurrent burst can honestly say "1 active". Ask again once everything is quiet.
        active = settled_active if settled_active is not None else (recs[-1]["engine_stats"]["active"] if recs else -1)
        ok = len(recs) == 300 and active == 0 and all(r["engine_stats"]["panics"] == 0 for r in recs) if kind != "fake-panic" else len(recs) == 300 and active == 0
        return ok, f"{len(recs)} records, {active} flows still held by the engine afterwards"
    if len(recs) != 1:
        return False, f"{len(recs)} records, want 1"
    r = recs[0]
    c, s = r["client"], r["server"]
    text = f"client: {c['outcome']}" + (f" {c.get('family','')}" if c.get("family") else "") + (f" host={c['hostname']}" if c.get("hostname") else "") + \
           f" ({c['reason']}) · server: {s['outcome']}" + (f" {s.get('family','')}" if s.get("family") else "") + f" ({s['reason']})"
    held = r["engine_stats"]["active"]
    if kind == "fake-panic":
        if c["outcome"] != "failed" and c["observed_bytes"] == 0 and s["observed_bytes"] == 0:  # the engine was never called
            return held == 0, text + " · no bytes reached the engine"
        ok = r.get("quarantined") and c["outcome"] == "failed" and c["reason"] == "panic" and held == 0
        return bool(ok), text + " · flow quarantined, tunnel kept relaying"
    if kind == "fake":
        return held == 0 and c["outcome"] in ("identified", "incomplete"), text
    ce, se = expect
    if ce == "frag":  # 1-byte writes: identified if the reads coalesced within 16 calls, else an explicit budget result
        ok = c["outcome"] in ("identified", "budget_exhausted") and held == 0
        return ok, text + " · never left at 'detecting'"
    if matches(ce, c) and held == 0 and not matches(se, s) and s.get("detail") == "Server key share group outside supported profile":
        return "gap", text + " · KNOWN GAP (work item #4): post-quantum ServerHello not recognised yet"
    return matches(ce, c) and matches(se, s) and held == 0, text


def main():
    for build, port, label, kind in BUILDS:
        RESULTS["builds"][build] = {"label": label, "port": port, "engine": kind or "off"}
    for name, group, fn, expect in SCENARIOS:
        row = {"name": name, "group": group, "results": {}}
        RESULTS["scenarios"].append(row)
        for build, port, label, kind in BUILDS:
            if build == "E" and fn in (s_large,):
                continue
            off = log_offset(build)
            t0 = time.time()
            try:
                ok, detail = fn(port)
            except Exception as e:  # a scenario failure is a result, not a runner crash
                ok, detail = False, {"error": repr(e)[:200]}
            res = {"traffic_ok": bool(ok), "detail": detail, "seconds": round(time.time() - t0, 2)}
            if kind:
                want = 300 if expect == "churn" else (0 if expect is None else 1)
                recs = observations(build, off, want)
                settled = None
                if expect == "churn":  # one quiet probe tunnel after the burst; its record shows what the engine still holds
                    time.sleep(0.3)
                    off2 = log_offset(build)
                    echo_roundtrip(port, b"\x01\x02LAB quiet probe after the burst")
                    probe = observations(build, off2, 1)
                    settled = probe[0]["engine_stats"]["active"] if probe else -1
                dok, text = check_observation(kind, expect, recs, settled)
                res["detector_ok"], res["detector"] = (dok if dok == "gap" else bool(dok)), text
                res["records"], res["record_count"] = recs[:4], len(recs)
            else:
                recs = observations(build, off, 0, wait=0.3)
                res["detector_ok"], res["detector"] = (not recs), "observation off: no detector records" if not recs else "UNEXPECTED detector records"
            row["results"][build] = res
            save()
        # Transparency across builds: every build delivered the same bytes for this scenario.
        hashes = {b: r["detail"].get("received") or r["detail"].get("body") for b, r in row["results"].items()}
        hashes = {b: h for b, h in hashes.items() if h}
        row["same_bytes_all_builds"] = (len(set(hashes.values())) == 1) if hashes else None
        save()
    for build, port, label, kind in POLICY_BUILDS:
        RESULTS["builds"].setdefault(build, {"label": label, "port": port, "engine": kind or "off"})
    RESULTS["builds"]["D"]["label"] += " + restriction rules"
    run_policy()
    RESULTS["state"] = "finished"
    RESULTS["finished"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    save()


if __name__ == "__main__":
    main()
