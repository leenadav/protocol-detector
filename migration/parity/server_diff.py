#!/usr/bin/env python3
"""Migration C14/C15: `protodetect serve` against presentation/server.py, request for request.

Both services run on 127.0.0.1 with the same environment: the Go binary is installed for the reference
(PROTODETECT_GO_BINARY), as it is in the product, and a stand-in `tcpdump` first on PATH plays a generated
capture instead of capturing anything (no interface is opened; nothing leaves the host). The same raw
requests go to both, in the same order, from the same script:

  * the static page, the read endpoints and cursor reads with valid, invalid and huge query values;
  * Host and Origin checks, malformed request lines and header blocks, unsupported methods, HTTP/0.9;
  * live control with a missing or wrong token, bad lengths and bodies (mutated JSON), every refusal of
    start(), and two runs: one held open (already running, heartbeats for the run and a stale one, cursor
    reads, stop and reset naming a stale run, then the run) and one that ends by itself (final log, reset);
  * analysis and decryption, synchronous and as jobs, on generated captures (analyze_diff, decrypt_diff)
    and on malformed requests; admission control (two running, four queued, the seventh refused), cancel of
    a queued, a finished and an unknown job; the job counters;
  * the handler pool: eight idle connections hold every slot and the ninth request is answered 503.

Answers are compared as the status line, the headers (Server and Date aside) and the body. JSON bodies are
compared after replacing what differs by construction: tokens, run, job and instance ids (by order of
appearance), monotonic times, the lease countdown, wall-clock durations of a run or an analysis, the
measurements of telemetry duration histograms (their keys, sample counts and every counter are compared;
Normalizer.histogram), and the "python" field of the health report (the Go service runs no interpreter). The demo capture and showcase are
random in the reference itself, and the Go service makes them with its own embedded capture and TLS stack
(PRO-402): their answers are compared by shape. Python 3.13 texts are the reference.
"""
import argparse
import base64
import json
import os
import random
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import analyze_diff  # noqa: E402
import control_diff  # noqa: E402

FAKE_TCPDUMP = """#!/bin/sh
# Stand-in for tcpdump in the server differential: plays a generated capture; never opens an interface.
cat "$PROTODETECT_FAKE_DIR/capture.pcap"
if [ "$(cat "$PROTODETECT_FAKE_DIR/mode")" = hold ]; then
  trap 'echo "0 packets dropped by kernel" >&2; exit 0' INT TERM
  while :; do sleep 0.1; done
fi
echo "0 packets dropped by kernel" >&2
"""


class Service:
    def __init__(self, name, argv, env):
        self.name = name
        self.process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, cwd=str(ROOT))  # noqa: S603
        line = self.process.stdout.readline().decode("ascii", "replace")
        match = re.search(r"http://127\.0\.0\.1:(\d+)", line)
        if not match:
            raise RuntimeError("{} did not start: {!r}".format(name, line))
        self.port = int(match.group(1))
        self.token = None

    def raw(self, data, hold=False, timeout=60):
        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as connection:
            connection.sendall(data)
            if not hold:
                try:
                    connection.shutdown(socket.SHUT_WR)
                except OSError:          # the service answered and closed first (a full pool's 503): read what it sent
                    pass
            chunks = []
            while True:
                try:
                    chunk = connection.recv(65536)
                except (ConnectionResetError, socket.timeout):
                    break
                if not chunk:
                    break
                chunks.append(chunk)
        return b"".join(chunks)

    def request(self, method, path, headers=(), body=b"", host=True, token=False):
        lines = ["{} {} HTTP/1.1".format(method, path)]
        if host:
            lines.append("Host: 127.0.0.1:{}".format(self.port))
        if token:
            lines.append("X-Live-Token: " + self.token)
        for header in headers:
            lines.append(header.replace("{PORT}", str(self.port)).replace("{TOKEN}", self.token or ""))
        if body is not None and not any(h.lower().startswith("content-length") for h in headers):
            lines.append("Content-Length: {}".format(len(body)))
        return self.raw(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + (body or b""))

    def json(self, method, path, **kwargs):
        head, body = split(self.request(method, path, **kwargs))
        return json.loads(body, object_pairs_hook=OrderedDict)

    def stop(self):
        self.process.send_signal(2)
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()


def split(response):
    if response.startswith(b"HTTP/"):
        head, _, body = response.partition(b"\r\n\r\n")
        return head.decode("latin-1"), body
    return "", response


LIVE_SESSION_ID = re.compile(r"L-[0-9]{6}")
VOLATILE_IDS = ("token", "run_id", "capture_id", "id", "instance")
VOLATILE_TIMES = ("submitted", "started", "finished", "uptime_seconds", "processing_ms", "elapsed_seconds", "first_seconds",
                  "stable_seconds")
STAGE_HISTOGRAM, DURATION_SUFFIX = "stage_seconds.", "_seconds"   # protocol_adapters/observability.py
DURATION_MEASUREMENTS = ("sum", "min", "max", "p50", "p95", "p99")
TIMED_COUNTS = ("stage_seconds.tick",)


def measured(value):
    """Only a measured number becomes a marker: a null or any other value in its place is compared as it is
    (PRO-261, from PR #99: a Go histogram with a null minimum must not equal one with a number)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


class Normalizer:
    """Per-service replacement of ids by order of appearance, and of times by a marker."""

    def __init__(self):
        self.ids = {}

    def value(self, key, value):
        # A live session's id is "L-" and six digits (L-{:06d}, kept as it is); a job id is random base64url and can
        # itself begin with "L-" (about 1 in 4096), which the earlier prefix test left unreplaced (2026-11-18).
        if key in VOLATILE_IDS and isinstance(value, str) and (key != "id" or not LIVE_SESSION_ID.fullmatch(value)):
            return self.ids.setdefault(value, "<id{}>".format(len(self.ids)))
        if key in VOLATILE_TIMES and isinstance(value, (int, float)) and not isinstance(value, bool):
            return "<time>"
        if key in ("start", "end") and isinstance(value, float):
            return "<time>"                                # a live session's clock readings (the log page's start is an int)
        if key == "lease_seconds_left" and value is not None:
            return "<lease>"
        if key == "python":
            return "<interpreter>"
        if key == "histograms" and isinstance(value, dict):
            return OrderedDict((name, self.histogram(name, h)) for name, h in value.items())
        return self.walk(value)

    def histogram(self, name, value):
        """A duration histogram keeps its keys, sample count and bucket bounds; only its measurements (sum, min,
        max, quantiles, per-bucket counts) are replaced (Codex PRO-21: the whole telemetry value used to be one
        constant, so counters, sample counts and every other field were never compared). The services' live
        runs read the wall clock (no replay clock), so every *_seconds histogram is a wall-clock measurement
        here. The one sample count that is itself a timing is stage_seconds.tick's: the live loop ticks on
        every wake-up and every idle 0.25 s, so a held run's tick count grows with elapsed time."""
        if not (isinstance(value, dict) and (name.startswith(STAGE_HISTOGRAM) or name.endswith(DURATION_SUFFIX))):
            return self.walk(value)
        out = OrderedDict()
        for key, item in value.items():
            if key == "buckets" and isinstance(item, list):
                out[key] = [[pair[0], "<time>"] + pair[2:] if isinstance(pair, list) and len(pair) > 1 and measured(pair[1])
                            else self.walk(pair) for pair in item]
            elif (key in DURATION_MEASUREMENTS or (key == "count" and name in TIMED_COUNTS)) and measured(item):
                out[key] = "<time>"
            else:
                out[key] = self.walk(item)
        return out

    def walk(self, value):
        if isinstance(value, dict):
            return OrderedDict((k, self.value(k, v)) for k, v in value.items())
        if isinstance(value, list):
            return [self.walk(v) for v in value]
        if isinstance(value, str) and value in self.ids:
            return self.ids[value]
        return value


def observed(response, normalizer, shape_only=False):
    head, body = split(response)
    lines = [line for line in head.split("\r\n") if not re.match(r"(?i)(server|date):", line)]
    try:
        document = json.loads(body, object_pairs_hook=OrderedDict) if body else None
    except ValueError:
        document = None
    if document is not None and ("application/json" in head or not head):
        lines = [line for line in lines if not line.lower().startswith("content-length:")]
        if shape_only:
            document = shape(document)
        return "\n".join(lines) + "\n" + json.dumps(normalizer.walk(document))
    return "\n".join(lines) + "\n" + (body.decode("latin-1") if not shape_only else "<{} bytes>".format(bool(body)))


def shape(value):
    if isinstance(value, dict):
        return OrderedDict((k, shape(v) if k in ("meta",) else type(v).__name__) for k, v in value.items())
    return type(value).__name__


class Run:
    def __init__(self, services):
        self.services = services
        self.normalizers = {s.name: Normalizer() for s in services}
        self.failures, self.compared = [], 0

    def same(self, label, action, shape_only=False):
        """Run action(service) on each service and compare what each answered."""
        answers = []
        for service in self.services:
            answers.append(observed(action(service), self.normalizers[service.name], shape_only))
        self.compared += 1
        if answers[0] != answers[1]:
            at = next((i for i, (x, y) in enumerate(zip(*answers)) if x != y), min(map(len, answers)))
            self.failures.append("{} (at {}):\n  reference: {!r}\n  go:        {!r}".format(
                label, at, answers[0][max(0, at - 150):at + 150], answers[1][max(0, at - 150):at + 150]))
        return answers[0]


class ProbeError(RuntimeError):
    """A wait that timed out or a probe whose precondition did not hold (Codex PRO-21): the answers that would
    follow compare two services that never reached the state the script is about, so the run fails instead."""


def wait_until(service, predicate, timeout=20.0, what="the expected live state"):
    deadline = time.monotonic() + timeout
    state = None
    while time.monotonic() < deadline:
        state = service.json("GET", "/api/live/state")
        if predicate(state):
            return state
        time.sleep(0.2)
    raise ProbeError("{}: live state did not reach {} within {} s (last state {})".format(
        service.name, what, timeout, None if state is None else state.get("state")))


def poll_job(service, job_id, timeout=60.0):
    deadline = time.monotonic() + timeout
    state = None
    while time.monotonic() < deadline:
        response = service.request("GET", "/api/jobs/" + job_id)
        head, body = split(response)
        state = json.loads(body).get("state")
        if state not in ("queued", "running"):
            return response
        time.sleep(0.1)
    raise ProbeError("{}: job {} still {} after {} s".format(service.name, job_id, state, timeout))


def status_of(response):
    match = re.match(r"HTTP/\d\.\d (\d{3}) ", split(response)[0])
    return int(match.group(1)) if match else None


def admission_problems(answers):
    """The admission script's precondition: of seven demo jobs submitted at once, two run, four queue and the
    seventh is refused (429). Without it the seven answers compare nothing about admission."""
    problems = []
    if len(answers) != 7:
        return ["{} admission answers, expected 7".format(len(answers))]
    for index, response in enumerate(answers):
        want = ("running" if index < 2 else "queued") if index < 6 else None
        status = status_of(response)
        if want is None:
            if status != 429:
                problems.append("submission 7 answered {}, expected 429".format(status))
            continue
        try:
            state = json.loads(split(response)[1]).get("state") if status == 202 else None
        except ValueError:
            state = None
        if status != 202 or state != want:
            problems.append("submission {} answered {} {}, expected 202 {}".format(index + 1, status, state, want))
    return problems


def pool_problem(response):
    """The handler-pool probe's precondition: with every slot held, the ninth connection is answered 503."""
    status = status_of(response)
    return None if status == 503 else "the ninth connection was answered {}, expected 503 (pool not full)".format(status)


def static_and_reads(run, rng):
    for path in ["/", "/app.js", "/store.js", "/live.js", "/decrypt.js", "/styles.css", "/index.html", "/nope", "/api/live/status",
                 "/api/live/state", "/api/live/events", "/api/jobs/none", "/api/jobs/", "/api/server", "/api/health", "/api/catalog",
                 "/api/live/interfaces", "/?x=1#f", "http://127.0.0.1:1/api/live/state", "//api/live/state", "\x01/api/live/state",
                 "/api/live/state?", "http://[::1]/api/live/state", "http://[x/api/server", "/api/live/events?cursor=1&cursor=x"]:
        run.same("GET " + repr(path), lambda s, p=path: s.request("GET", p))
    run.same("GET /api/sample", lambda s: s.request("GET", "/api/sample"), shape_only=True)
    values = ["0", "1", "-1", "+3", "5_0", "1__0", " 7 ", "x", "", "99999999999999999999999999", "0x10", "%35", "1e3", "10000",
              "10001", "\xa05", "\x1c5", "1" * 4301, "'q'"]
    for _ in range(30):
        query = "&".join("{}={}".format(rng.choice(["cursor", "limit", "other"]), rng.choice(values)) for _ in range(rng.randint(0, 3)))
        run.same("events " + repr(query[:80]), lambda s, q=query: s.request("GET", "/api/live/events?" + q))


def framing(run):
    def raw(data):
        return lambda s: s.raw(data.replace(b"{PORT}", str(s.port).encode()))
    cases = [b"", b"\r\n", b"GET", b"GET /\r\n", b"POST /\r\n\r\n", b"GET / HTTP/1.1 x\r\nHost: 127.0.0.1:{PORT}\r\n\r\n",
             b"GET / FOO/1.1\r\n\r\n", b"GET / HTTP/1\r\n\r\n", b"GET / HTTP/1.1.1\r\n\r\n", b"GET / HTTP/2.0\r\n\r\n",
             b"GET / HTTP/12345678901.0\r\n\r\n", b"GET / HTTP/a.1\r\n\r\n", b"GET / HTTP/1.\xb2\r\n\r\n",
             b"PUT / HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n\r\n", b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n\r\n",
             b"get / HTTP/1.1\r\n\r\n", b"GET /api/live/state HTTP/1.0\r\nHost: 127.0.0.1:{PORT}\r\n\r\n",
             b"GET /api/live/state HTTP/1.1\r\nhost: 127.0.0.1:{PORT}\r\n\r\n",
             b"GET /api/live/state HTTP/1.1\r\nHost: 127.0.0.1:{PORT} \r\n\r\n",
             b"GET /api/live/state HTTP/1.1\r\nHost:127.0.0.1:{PORT}\r\n\r\n",
             b"GET /api/live/state HTTP/1.1\r\nHost: wrong\r\nHost: 127.0.0.1:{PORT}\r\n\r\n",
             b"GET /api/live/state HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nHost: wrong\r\n\r\n",
             b"GET /api/live/state HTTP/1.1\r\nX: 1\r\n Host: folded\r\nHost: 127.0.0.1:{PORT}\r\n\r\n",
             b"GET /api/live/state HTTP/1.1\r\nBad Header\r\nHost: 127.0.0.1:{PORT}\r\n\r\n",
             b"GET /api/live/state HTTP/1.1\r\nFrom someone\r\nHost: 127.0.0.1:{PORT}\r\n\r\n",
             b"GET /api/live/state HTTP/1.1\r\n:x\r\nHost: 127.0.0.1:{PORT}\r\n\r\n",
             b"GET /api/live/state HTTP/1.1\r\nA: b\rHost: 127.0.0.1:{PORT}\r\n\r\n",
             b"GET /api/live/state HTTP/1.1\nHost: 127.0.0.1:{PORT}\n\n",
             b"GET /api/live/state HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nOrigin: http://127.0.0.1:{PORT}\r\n\r\n",
             b"GET /api/live/state HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nOrigin: http://evil.example\r\n\r\n",
             b"GET /api/live/state HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nOrigin: \r\n\r\n",
             b"GET /api/live/state HTTP/1.1\r\n\r\n", b"GET /api/live/state HTTP/1.1\r\nHost: localhost:{PORT}\r\n\r\n",
             b"GET /a\xe9 HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n\r\n", b"G\xe9T / HTTP/1.1\r\n\r\n",
             b"GET /\xa0x HTTP/1.1\r\n\r\n", b"GET / HTTP/1.1\r\nHost: 127.0.0.1:{PORT}",
             b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\n\r\n",
             b"GET / HTTP/1.1\r\nX: " + b"a" * 70000 + b"\r\n\r\n",
             b"GET / HTTP/1.1\r\n" + b"X: 1\r\n" * 101 + b"\r\n",
             b"GET / HTTP/1.1\r\n" + b"X: 1\r\n" * 99 + b"\r\n"]
    for data in cases:
        run.same("raw " + repr(data[:70]), raw(data))


def live_control_refusals(run, rng):
    def post(path, body, headers=(), token=True):
        return lambda s: s.request("POST", path, headers=list(headers), body=body, token=token)
    for path in ("/api/live/start", "/api/live/stop", "/api/live/heartbeat", "/api/live/reset"):
        run.same("no token " + path, post(path, b"{}", token=False))
        run.same("wrong token " + path, post(path, b"{}", ["X-Live-Token: nope"], token=False))
        for length in ("abc", "-1", "1025", " 5 ", "1_0", "", "+0"):
            run.same("length {!r} {}".format(length, path), post(path, b"{}", ["Content-Length: " + length]))
        run.same("chunked " + path, post(path, b"{}", ["Transfer-Encoding: chunked"]))
        run.same("short body " + path, post(path, b"{}", ["Content-Length: 9"]))
    for doc in control_diff.json_documents(rng, 60):
        if len(doc) <= 1024:
            run.same("start body " + repr(doc[:60]), post("/api/live/start", doc))
            run.same("stop body " + repr(doc[:60]), post("/api/live/stop", doc))
    options = [{}, {"interface": None}, {"interface": "nope0"}, {"interface": 5}, {"interface": "lo", "duration": True},
               {"interface": "lo", "duration": 4}, {"interface": "lo", "duration": 601}, {"interface": "lo", "duration": 30.0},
               {"interface": "lo", "duration": "30"}, {"interface": "lo", "duration": 10 ** 30}, {"interface": "lo", "scope": "x"},
               {"interface": "lo", "scope": None}, {"interface": "eth0", "scope": "synthetic"},
               {"interface": "lo", "scope": "synthetic", "keylog_path": "relative"},
               {"interface": "lo", "scope": "synthetic", "keylog_path": 5},
               {"interface": "lo", "scope": "synthetic", "keylog_path": "/" + "k" * 1024},
               {"interface": "lo", "scope": "synthetic", "keylog_path": "/absolute/keys.log", "duration": 121}, [], "x", 5]
    for option in options:
        body = json.dumps(option).encode()
        run.same("start " + body.decode()[:80], post("/api/live/start", body))
    for body in (b'{"run_id": null}', b'{"run_id": "x"}', b'{"run_id": 5}', b"{}", b""):
        for path in ("/api/live/stop", "/api/live/heartbeat", "/api/live/reset"):
            run.same("idle {} {!r}".format(path, body), post(path, body))


def live_runs(run, fake):
    def post(path, body):
        return lambda s: s.request("POST", path, body=json.dumps(body).encode(), token=True)
    start = {"interface": "lo", "duration": 30, "scope": "synthetic"}
    (fake / "mode").write_text("hold")
    run_ids = {}
    for service in run.services:                           # held run: everything while it runs, then stop and reset
        response = service.request("POST", "/api/live/start", body=json.dumps(start).encode(), token=True)
        run_ids[service.name] = json.loads(split(response)[1])["run_id"]
        run.normalizers[service.name].walk(json.loads(split(response)[1], object_pairs_hook=OrderedDict))
        wait_until(service, lambda state: state.get("events_total", 0) > 0 or state.get("sessions_total", 0) > 0, 15, "its first event or session")
        time.sleep(1.5)                                    # the stand-in has written the whole capture by now
    run.same("start while running", post("/api/live/start", start))
    run.same("heartbeat stale", post("/api/live/heartbeat", {"run_id": "stale"}))
    run.same("heartbeat run", lambda s: s.request("POST", "/api/live/heartbeat", body=json.dumps({"run_id": run_ids[s.name]}).encode(), token=True))
    for cursor, limit in ((0, 500), (0, 3), (2, 2), (10 ** 9, 5), (10 ** 30, 5)):
        run.same("running events {} {}".format(cursor, limit), lambda s, c=cursor, n=limit: s.request("GET", "/api/live/events?cursor={}&limit={}".format(c, n)))
    run.same("running state", lambda s: s.request("GET", "/api/live/state"))
    run.same("stop stale", post("/api/live/stop", {"run_id": "stale"}))
    run.same("reset stale", post("/api/live/reset", {"run_id": "stale"}))
    run.same("state after stale", lambda s: s.request("GET", "/api/live/state"))
    for service in run.services:
        service.request("POST", "/api/live/stop", body=json.dumps({"run_id": run_ids[service.name]}).encode(), token=True)
        wait_until(service, lambda state: state["state"] in ("stopped", "failed"), 20, "stopped after stop")
    run.same("stopped status", lambda s: s.request("GET", "/api/live/status"))
    run.same("stopped events", lambda s: s.request("GET", "/api/live/events?cursor=0&limit=10000"))
    run.same("heartbeat stopped", lambda s: s.request("POST", "/api/live/heartbeat", body=json.dumps({"run_id": run_ids[s.name]}).encode(), token=True))
    run.same("reset run", lambda s: s.request("POST", "/api/live/reset", body=json.dumps({"run_id": run_ids[s.name]}).encode(), token=True))
    run.same("reset again", lambda s: s.request("POST", "/api/live/reset", body=json.dumps({"run_id": run_ids[s.name]}).encode(), token=True))
    run.same("after reset", lambda s: s.request("GET", "/api/live/events"))
    (fake / "mode").write_text("finish")                    # a run that ends by itself
    for service in run.services:
        response = service.request("POST", "/api/live/start", body=json.dumps(dict(start, duration=5)).encode(), token=True)
        run.normalizers[service.name].walk(json.loads(split(response)[1], object_pairs_hook=OrderedDict))
        wait_until(service, lambda state: state["state"] in ("stopped", "failed"), 20, "the end of a run that finishes by itself")
    run.same("finished status", lambda s: s.request("GET", "/api/live/status"))
    run.same("finished events", lambda s: s.request("GET", "/api/live/events?cursor=1&limit=7"))
    run.same("finished state", lambda s: s.request("GET", "/api/live/state"))


def analyses(run, rng, sessions, folder, count):
    import decrypt_diff
    generator = decrypt_diff.Generator(rng.randint(1, 10 ** 6))

    def post(path, body, headers=(), token=True):
        return lambda s: s.request("POST", path, headers=list(headers), body=body, token=token)

    for index in range(count):
        path = folder / "analysis-{}".format(index)
        analyze_diff.write_capture(rng, path, analyze_diff.stress_records(rng) if index % 3 == 2 else analyze_diff.records_for(rng, sessions))
        data = path.read_bytes()
        if index % 4 == 1:
            data = data[: rng.randint(1, len(data))]             # truncated captures are refused in the reference's words
        run.same("analyze {}".format(index), post("/api/analyze", data, token=False))
        capture, keylog = generator.capture()
        body = json.dumps({"capture": base64.b64encode(capture).decode(), "keylog": keylog}).encode()
        run.same("decrypt {}".format(index), post("/api/decrypt", body))
        for service in run.services:
            pass
        run.same("decrypt job {}".format(index), lambda s, b=body: poll_job(s, json.loads(split(
            s.request("POST", "/api/jobs?kind=decrypt", body=b, token=True))[1])["id"]))
        run.same("analyze job {}".format(index), lambda s, d=data: poll_job(s, json.loads(split(
            s.request("POST", "/api/jobs", headers=["X-Job-Kind: analyze"], body=d, token=True))[1])["id"]))
    bad = [b"[]", b'"x"', b"{}", b'{"capture": 5}', b'{"capture": "Zm9v"}', b'{"capture": "ab=c", "keylog": ""}', b'{"capture": "abc"}',
           b'{"capture": "a", "keylog": ""}', b'{"capture": "====", "keylog": ""}', b'{"capture": "Zm9v=", "keylog": ""}',
           b'{"capture": "Zm9v\\n", "keylog": ""}', '{"capture": "é"}'.encode(), b'{"capture": "", "keylog": 5}',
           b'{"capture": "", "keylog": ""}', b'{"capture": "", "keylog": null}', b"\xff", b"", b"{", b'{"capture": "Zm9vYmFy", "keylog": "x"}',
           b'{"capture": "Zm9vYg==", "keylog": "CLIENT_RANDOM 00 11"}', b'{"capture": "Zm9vYg==x", "keylog": ""}']
    for body in bad:
        run.same("bad decrypt " + repr(body[:50]), post("/api/decrypt", body))
    for headers, body, path in (([], b"", "/api/analyze"), (["Transfer-Encoding: chunked"], b"x", "/api/analyze"),
                                (["Content-Length: x"], b"x", "/api/analyze"), (["Content-Length: 9000000"], b"x", "/api/analyze"),
                                (["Content-Length: -1"], b"x", "/api/analyze"), (["Content-Length: 5"], b"x", "/api/analyze"),
                                ([], b"\x00" * 24, "/api/analyze"), ([], b"x", "/api/decrypt/demo?x"),
                                (["Content-Length: 13000000"], b"x", "/api/decrypt"), (["Transfer-Encoding: x"], b"x", "/api/decrypt")):
        # The decryption showcase is made by each service's own TLS stack (PRO-402): compared by shape, as below.
        run.same("{} {} {!r}".format(path, headers, body[:20]), post(path, body, headers), shape_only=path.startswith("/api/decrypt/demo"))
    for headers, path, body in ((["X-Live-Token: no"], "/api/jobs", b"x"), ([], "/api/jobs?kind=nope", b"x"), ([], "/api/jobs", b"x"),
                                ([], "/api/jobs?kind=analyze", b""), (["X-Job-Kind: decrypt"], "/api/jobs?kind=analyze&x=1", b"x"),
                                ([], "/api/jobs/x", b""), ([], "/api/jobs/cancel", b""), ([], "/api/jobsx", b""),
                                ([], "/api/jobs/unknown/cancel", b""), (["Content-Length: 9000000"], "/api/jobs?kind=analyze", b"x"),
                                (["Content-Length: 9000000"], "/api/jobs?kind=decrypt", b"x")):
        run.same("jobs {} {}".format(path, headers), post(path, body, headers, token=not headers or "X-Live-Token" not in headers[0]))
    run.same("demo", post("/api/demo", b"", token=False), shape_only=True)
    run.same("decrypt demo", post("/api/decrypt/demo", b""), shape_only=True)


def admission(run):
    submitted = {}
    for service in run.services:                         # seven submissions in a row: two run, four queue, one refused
        answers = []
        for _ in range(7):
            answers.append(service.request("POST", "/api/jobs?kind=demo", body=b"", token=True))
        submitted[service.name] = answers
        problems = admission_problems(answers)
        if problems:
            raise ProbeError("{}: admission did not hold: {}".format(service.name, "; ".join(problems)))
    for i in range(7):
        run.same("admission {}".format(i), lambda s, k=i: submitted[s.name][k], shape_only=False)
    ids = {s.name: [str(json.loads(split(a)[1]).get("id")) for a in submitted[s.name]] for s in run.services}
    run.same("cancel queued", lambda s: s.request("POST", "/api/jobs/{}/cancel".format(ids[s.name][5]), body=b"", token=True))
    run.same("cancel queued again", lambda s: s.request("POST", "/api/jobs/{}/cancel".format(ids[s.name][5]), body=b"", token=True))
    run.same("job cancelled", lambda s: s.request("GET", "/api/jobs/" + ids[s.name][5]))
    for service in run.services:
        for job_id in ids[service.name][:5]:
            poll_job(service, job_id, 120)
    run.same("cancel finished", lambda s: s.request("POST", "/api/jobs/{}/cancel".format(ids[s.name][0]), body=b"", token=True),
             shape_only=True)
    run.same("finished job", lambda s: s.request("GET", "/api/jobs/" + ids[s.name][1]), shape_only=True)
    run.same("server counters", lambda s: s.request("GET", "/api/server"))


def handler_pool(run):
    for service in run.services:
        idle = [socket.create_connection(("127.0.0.1", service.port), timeout=30) for _ in range(8)]
        time.sleep(0.3)
        service.pool_answer = service.raw("GET /api/live/state HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n".format(service.port).encode())
        for connection in idle:
            connection.close()
        time.sleep(0.3)
        problem = pool_problem(service.pool_answer)
        if problem:
            raise ProbeError("{}: {}".format(service.name, problem))
    run.same("ninth connection", lambda s: s.pool_answer)
    run.same("after the pool", lambda s: s.request("GET", "/api/server"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", required=True, help="the Go protodetect binary")
    parser.add_argument("--count", type=int, default=12, help="generated captures for analysis and decryption")
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args(argv)
    try:
        import cryptography  # noqa: F401
    except ImportError:
        print("server parity FAILED: the decryption cases need the `cryptography` package "
              "(python3 -m pip install --require-hashes -r presentation/requirements-decryption.lock.txt)")
        return 1
    binary = str(Path(args.binary).resolve())
    rng = random.Random(args.seed)
    sessions = [case for case in json.loads((ROOT / "migration/fixtures/cases.json").read_text(encoding="utf-8"))["cases"] if case["kind"] == "session"]
    with tempfile.TemporaryDirectory() as folder:
        folder = Path(folder)
        fake = folder / "fake"
        fake.mkdir()
        tcpdump = fake / "tcpdump"
        tcpdump.write_text(FAKE_TCPDUMP)
        tcpdump.chmod(tcpdump.stat().st_mode | stat.S_IXUSR)
        analyze_diff.write_capture(rng, fake / "capture.pcap", analyze_diff.records_for(rng, sessions))
        (fake / "mode").write_text("finish")
        env = dict(os.environ, PATH=str(fake) + os.pathsep + os.environ.get("PATH", ""), PROTODETECT_GO_BINARY=binary,
                   PROTODETECT_FAKE_DIR=str(fake))
        env.pop("PROTODETECT_BACKEND", None)
        services = [Service("reference", [sys.executable, "-B", str(ROOT / "presentation/server.py"), "--port", "0"], env),
                    Service("go", [binary, "serve", "--port", "0", "--root", str(ROOT / "presentation")], env)]
        probe_failures = []
        try:
            for service in services:
                service.token = json.loads(split(service.request("GET", "/api/live/interfaces"))[1])["token"]
                service.json("GET", "/api/live/interfaces")
            run = Run(services)
            for service in services:
                run.normalizers[service.name].walk({"token": service.token})
            for stage in (lambda: static_and_reads(run, rng), lambda: framing(run), lambda: live_control_refusals(run, rng),
                          lambda: live_runs(run, fake), lambda: analyses(run, rng, sessions, folder, args.count),
                          lambda: admission(run), lambda: handler_pool(run)):
                try:
                    stage()
                except ProbeError as error:          # the stage's later answers would compare nothing; go on to the next
                    probe_failures.append(str(error))
        finally:
            for service in services:
                service.stop()
    for failure in probe_failures:
        print("server parity FAILED:", failure)
    for failure in run.failures[:int(os.environ.get("SERVER_DIFF_SHOW", "8"))]:
        print("server mismatch:", failure)
    print("server parity: {} exchanges compared, {} mismatched, {} probes failed (seed {})".format(
        run.compared, len(run.failures), len(probe_failures), args.seed))
    return 1 if run.failures or probe_failures else 0


if __name__ == "__main__":
    sys.exit(main())
