# Culvert load test: what observe mode adds per connection (PRO-269, 2026-11-24)

> **Second, independent run of PRO-269 (PR #120).** The first run, merged in PR #118, is
> `docs/integration/LOAD-TEST.md` with its tools at `lab/culvert/tools/loadtest.py`, `loadtest_summary.py` and
> `loadorigin/`. This run uses other rates (200, 500, 1,000/s) and adds a fake-engine build (C) for the CPU split,
> GC counts and a 1,000-tunnel hold test. Its tools live in `lab/culvert/tools/loadsplit/` and its origin binary is
> `loadorigin-split`, so neither run's tooling replaces the other's. The two runs agree in direction: no
> measurable p99 cost below the rig's knee, and a CPU cost of roughly 0.1 to 0.3 CPU-s per 1,000 HTTPS flows.

Lee approved this test on 2026-11-23. It answers one question: how much does the protocol detector add to each
connection through Culvert when it runs in observe mode (visibility only, decision 3), compared with the
detector off? Everything ran in the synthetic Culvert lab: loopback addresses, RFC 5737 origins and synthetic
requests. Nothing was sent to KidCarmi/Culvert or to any outside host, and vegeta (MIT) is a test tool only; it
is never shipped.

## 1. Results in one paragraph

On this 4-CPU container, observe mode added **no measurable latency to the median HTTPS connection at 200 and 500
new tunnels per second**: p50 +0.07 to +0.11 ms, p95 +0.26 to +0.59 ms, and p99 inside the round-to-round noise
(−0.53 to +0.03 ms). These are medians of 3 rounds, and every one sits inside the spread between rounds. Every
request succeeded on every build, at the offered rate. The detector's real cost shows up as **proxy CPU**: +105
to +277 ms per 1,000 HTTPS flows, which is 0.1 to 0.3 ms per tunnel and about 15 to 26% more proxy CPU per new
HTTPS tunnel. It also adds +2.5 to +3 GC cycles per 1,000 flows. The added CPU splits roughly in half:
- the lab's observation path (hook, window timer, record) on a fake engine;
- the real engine's parsing and evidence.

Memory barely moves at these rates, because a TLS tunnel leaves observation within milliseconds. The peak RSS
difference is +0.1 to +1.4 MiB. With 1,000 tunnels held open at once, observing costs nothing measurable over the
detector off. After the window ends, the kept record costs **+3.9 KiB per tunnel, about +3.8 MiB per 1,000** (the
plan's budget is ≤ 4 KiB). Plain HTTP is Culvert's forward path, which the lab does not observe, and it shows no
detector cost, as designed. At 1,000/s the test rig itself, not the detector, reaches its limit (section 5).

## 2. What was measured

| Build | What it is | Proxy |
|---|---|---|
| A | Unmodified Culvert `ef9431189490f7f85bb32d6fe7e7b6b8be5b0844` (`GOWORK=off`) | `bin/culvert-A` |
| B | Lab build, detector off (`CULVERT_LAB_PROTODETECT` unset: the relay path is the unmodified one) | `bin/culvert-lab` |
| C | Lab build, fake engine (`=fake`: the same hook, window timer and record, no parsing); cost split only | `bin/culvert-lab` |
| D | Lab build, **observe mode** (`=real`, window 3 s, families http, tls, ssh, smtp) | `bin/culvert-lab` |

"Added" always means **D − B**: the same binary with only the detector switched on. **B − A** is the lab hook
with the detector off, and it stays inside the noise (HTTPS p50 −0.04 to +0.01 ms at 200 and 500/s).

- **HTTPS:** `GET https://origin.lab.test/load` through the proxy. vegeta runs with `-keepalive=false`, so every
  request opens a new client connection. That makes every request one CONNECT bypass tunnel, which is one
  detector flow on D. D logged one `PROTODETECT` record per request (6,000 of 6,000, 15,000 of 15,000, and
  30,000 at 1,000/s, with a few warm-up stragglers logged late), with **0 refused admissions**.
- **HTTP:** `GET http://origin.lab.test/load`, Culvert's forward path. Phase 1 observes CONNECT bypass tunnels
  only, so this is the control: D logged 0 records, as expected.
- **Rates:** 200, 500 and 1,000 requests per second, which are also new connections per second, at a constant
  rate. Each cell lasts 30 s after a 3 s warm-up.
- **Rounds:** 3. Builds run one at a time, and the build order rotates each round (A, B, D, then B, D, A, then D,
  A, B), so drift does not favour one build (plan 8.3: interleaved). The proxy is restarted with a fresh data
  directory for every cell.
- **Latency:** vegeta's per-request latency, measured from connect to the end of the response body, through
  CONNECT and a full TLS handshake for HTTPS. These are p50, p95 and p99 of 6,000 to 30,000 requests per cell.
  The figures shown are the median of the 3 rounds, with the range [min–max].
- **CPU:** utime + stime of the proxy process from `/proc/<pid>/stat` over the attack, divided per 1,000
  requests (= flows).
- **Memory:**
  - the proxy's RSS sampled every 100 ms, as idle before the attack and peak during it;
  - GC cycles counted from `GODEBUG=gctrace=1` (the same setting on every build);
  - a separate hold test (`loadhold.py`): 1,000 silent CONNECT tunnels held open with a 10 s window. RSS (median
    of 10 samples) is taken before, while observing and after the window has ended.
- **Pinning:** proxy on CPUs 0–1, vegeta on CPU 2, origin on CPU 3 (`taskset`).

No pass or fail threshold was set for this run. The task asks for a report, not a gate, so no threshold was
loosened either (plan 8.3).

## 3. Results

### 3.1 HTTPS latency per request (ms): median of 3 rounds [min–max]

| Rate | Build | p50 | p95 | p99 | Throughput (req/s) | Success (worst round) |
|---:|---|---:|---:|---:|---:|---:|
| 200/s | A | 2.12 [2.01–2.56] | 2.99 [2.52–3.66] | 5.11 [3.45–5.24] | 200.0 | 100.00% |
| 200/s | B | 2.08 [1.96–2.24] | 3.04 [2.55–3.24] | 5.14 [3.80–5.39] | 200.0 | 100.00% |
| 200/s | D | 2.18 [1.89–2.53] | 3.30 [2.47–3.57] | 5.17 [4.85–5.21] | 200.0 | 100.00% |
| 500/s | A | 2.14 [1.93–2.50] | 3.67 [3.17–5.17] | 7.65 [5.79–10.35] | 500.0 | 100.00% |
| 500/s | B | 2.14 [1.93–2.29] | 3.65 [3.00–4.33] | 7.64 [4.71–8.88] | 500.0 | 100.00% |
| 500/s | D | 2.21 [1.87–2.52] | 4.24 [3.00–4.59] | 7.12 [5.19–10.82] | 500.0 | 100.00% |
| 1000/s | A | 2.76 [2.25–648.43] | 11.91 [9.36–3152.68] | 25.15 [20.01–4730.31] | 999.9 | 100.00% |
| 1000/s | B | 4.75 [2.34–1684.18] | 119.42 [10.05–6798.42] | 221.89 [21.20–9399.78] | 999.8 | 92.93% |
| 1000/s | D | 3.57 [2.35–11.18] | 18.09 [9.23–279.00] | 66.99 [18.44–418.17] | 999.9 | 100.00% |

**Added latency, D − B (ms):**

| Rate | Δp50 | Δp95 | Δp99 | Reading |
|---:|---:|---:|---:|---|
| 200/s | +0.11 | +0.26 | +0.03 | Inside the round-to-round spread of B and D |
| 500/s | +0.07 | +0.59 | −0.53 | Inside the spread; the second run (3.3) gives −0.05, −0.18, −0.10 |
| 1000/s | (−1.18) | (−101.33) | (−154.90) | Not a detector figure: the rig is at its limit and some rounds are disturbed on every build (section 5) |

The second run (3.3) repeated 500/s and 1,000/s with B, C and D. At 500/s it gave D − B of −0.05 ms (p50),
−0.18 ms (p95) and −0.10 ms (p99). The detector's effect on per-connection latency is below what this rig can
resolve, roughly ±0.5 ms at p95 and p99 and ±0.1 ms at p50.

### 3.2 HTTPS proxy CPU and memory

| Rate | Build | CPU per 1,000 flows (ms) | Proxy CPU (% of one core) | RSS idle (MiB) | RSS peak (MiB) | GC cycles per 1,000 flows |
|---:|---|---:|---:|---:|---:|---:|
| 200/s | A | 1073 [1050–1297] | 21 | 45.9 | 51.6 [51.5–52.1] | 2.17 |
| 200/s | B | 1072 [1020–1140] | 21 | 49.7 | 55.7 [55.6–56.3] | 2.00 |
| 200/s | D | 1348 [1173–1505] | 27 | 51.7 | 56.3 [56.1–56.7] | 4.83 |
| 500/s | A | 908 [866–1047] | 45 | 48.3 | 52.2 [52.0–52.5] | 1.93 |
| 500/s | B | 926 [864–997] | 46 | 51.6 | 55.8 [55.8–56.2] | 1.73 |
| 500/s | D | 1137 [1052–1261] | 57 | 54.8 | 57.2 [56.2–57.3] | 4.73 |
| 1000/s | A | 663 [632–774] | 66 | 51.7 | 58.6 [56.2–157.9] | 1.70 |
| 1000/s | B | 709 [648–778] | 71 | 57.0 | 68.2 [60.0–242.9] | 1.47 |
| 1000/s | D | 815 [773–836] | 81 | 57.3 | 68.7 [62.5–80.8] | 3.97 |

**Observe-mode cost per 1,000 HTTPS flows (D − B):**

| Rate | Proxy CPU | Share of the proxy's CPU per tunnel | RSS peak | GC cycles |
|---:|---:|---:|---:|---:|
| 200/s | +277 ms | +26% | +0.6 MiB | +2.83 |
| 500/s | +211 ms (second run +171) | +23% (+18%) | +1.4 MiB (+0.4) | +3.00 (+2.93) |
| 1000/s | +105 ms (second run +126) | +15% (+19%) | +0.5 MiB (+0.1) | +2.50 (+2.70) |

CPU per flow falls with the rate on every build: the process wakes less per request as work batches up. That is
why the 200/s cell is the most expensive per flow.

### 3.3 Where the CPU goes: fake engine against real engine (HTTPS, second run)

| Rate | B, detector off | C, fake engine | D, real engine | Observation path (C − B) | Engine (D − C) |
|---:|---:|---:|---:|---:|---:|
| 500/s | 926 ms | 997 ms | 1097 ms | +71 ms | +100 ms |
| 1000/s | 671 ms | 730 ms | 797 ms | +59 ms | +67 ms |

These are proxy CPU per 1,000 flows, median of 3 rounds. GC cycles per 1,000 flows were B 1.73, C 2.87 and D 4.67
at 500/s.

The in-process `BenchmarkFlow/tls` of `go/detector` gives 17 µs and 14.3 KB per flow on the same machine (about
17 ms of CPU and 14 MB allocated per 1,000 flows). The live engine share of 67 to 100 ms is 4 to 6 times that,
which is consistent with the extra GC work. The live path also does more than the benchmark:
- it builds the evidence and the record (hostnames through the keyed pseudonymizer);
- it writes a JSON log line per tunnel;
- it pays the allocation through GC on a busy process.

Reducing the observation path's share is lab-adapter work (`protodetect_lab.go`), not detector work.

### 3.4 Memory with 1,000 tunnels held open (`loadhold.py`, 3 rounds)

| Build | RSS idle | 1,000 tunnels open, observing | After the window, tunnels still open | Per tunnel, observing | Per tunnel, after |
|---|---:|---:|---:|---:|---:|
| A | 40.9 MiB | 69.4 MiB | 69.4 MiB | 29.2 KiB | 29.2 KiB |
| B | 44.2 MiB | 72.7 MiB | 72.7 MiB | 29.1 KiB | 29.1 KiB |
| D | 43.7 MiB | 72.5 MiB | 75.9 MiB | 29.1 KiB | 33.0 KiB |

These are medians of 3 rounds, and every range is within ±0.5 MiB. All 1,000 tunnels were admitted (0 refused,
under the cap of 4,096), and each one produced a record.

- **About 29 KiB per tunnel is Culvert's own cost** (two sockets, the upstream dial, goroutines), the same on A,
  B and D.
- **While observing, a silent tunnel costs nothing measurable on top.** The flow's 32 KiB reservation is a budget
  charge, "not heap or RSS" (`go/detector/detector.go:175`), and a flow that has seen no bytes holds little.
- **After the window, D keeps +3.9 KiB per tunnel** over B (about +3.8 MiB per 1,000). This is the window-end path
  (Expire, Finish) and the record that SEC-CULV-1 keeps until the tunnel closes, with the 4 KiB tap buffer of a
  read still blocked. It is within the plan's budget of "≤ 4 KiB retained per relay after observation" (section
  9). RSS includes memory the Go runtime has freed but not returned, so this is an upper bound for that state.
- **Not measured:** 1,000 flows held at once while each has sent its full 16 KiB of observed bytes (the worst
  case of the observing state), and the blocked-write case. The plan lists both (8.3).

### 3.5 HTTP control (forward path, not observed)

| Rate | p50 A / B / D (ms) | p99 A / B / D (ms) | CPU per 1,000 flows A / B / D (ms) | D records |
|---:|---|---|---|---:|
| 200/s | 1.01 / 1.01 / 1.02 | 2.93 / 3.09 / 2.86 | 885 / 910 / 905 | 0 |
| 500/s | 0.93 / 0.92 / 0.95 | 2.70 / 4.64 / 3.70 | 829 / 829 / 857 | 0 |
| 1000/s | 1.13 / 1.13 / 1.23 | 4.07 / 4.65 / 5.39 | 768 / 776 / 854 | 0 |

All are 100% success at the offered rate. No detector code runs on this path. The 1,000/s D cell has the highest
CPU (+78 ms per 1,000 over B) and p99 (+0.74 ms), with overlapping ranges (B 719–861, D 653–885 ms). That is the
size of this rig's noise at that rate, and it is also why the HTTPS differences in 3.1 are read as noise.

The complete tables, including RSS and GC for HTTP, are produced by
`python3 lab/culvert/tools/loadsplit/loadtest_report.py lab/culvert/results-load`.

## 4. Method and versions

| Item | Value |
|---|---|
| Culvert | `ef9431189490f7f85bb32d6fe7e7b6b8be5b0844` (build A); lab branch `lab/protocol-detector-ef94311` = that commit + `lab/culvert/culvert-lab-ef94311.patch` (4 patches, applied with `git am`, local head `cbc75793f`), push disabled |
| Detector | this repository's `go/` at `main` `593f6a467199d15fcdb9d441d4cadff8aa78d417`, through `go.work` (`lab/culvert/go.work.example`) |
| Go | go1.27.4 linux/amd64 (the toolchain both modules pin), for Culvert, the lab build, vegeta and the origin |
| vegeta | `github.com/tsenart/vegeta/v12` v12.12.0 (MIT), `go install`ed into the lab's `bin/`; test tool only |
| Origin | `lab/culvert/tools/loadsplit/loadorigin` (standard library Go): HTTP on 203.0.113.10:80, HTTPS on :443 with a per-run self-signed certificate for `origin.lab.test`, a 33-byte body. The lab's Python origins would be the bottleneck at these rates. Its header timeout, which also bounds the TLS handshake, was raised from 5 s to 60 s for the hold test after the rate runs; no rate-run request came near either |
| Host | one container, 4 vCPUs (Intel Xeon @ 2.10 GHz), 16 GiB, Linux 6.18.44; Python 3.13 runs the harness (the code is 3.9-compatible) |
| Socket settings | `net.ipv4.ip_local_port_range = 1024 65535`, `tcp_tw_reuse = 1` (defaults were 32768–60999 and 2); every cell waits until fewer than 5,000 sockets are in TIME_WAIT |
| Detector settings | lab defaults: families http, tls, ssh, smtp; 16 KiB and 16 feeds per direction; 4,096 observed tunnels; window 3 s for the rate runs and 10 s for the hold test |
| Raw data | `lab/culvert/results-load/` (main run: `cells.json`, `summary.json`, `settings.json`, `run.log`), `results-load-split/` (B, C, D), `results-load-hold/hold.json` |

Reproduce (as root in the lab container, with the builds of `lab/culvert/README.md` in `/home/user/culvert-lab/bin`):

```bash
echo "1024 65535" > /proc/sys/net/ipv4/ip_local_port_range; echo 1 > /proc/sys/net/ipv4/tcp_tw_reuse
python3 lab/culvert/tools/addaddr.py 203.0.113.10 203.0.113.20
grep -q origin.lab.test /etc/hosts || echo "203.0.113.10 origin.lab.test" >> /etc/hosts
GOBIN=/home/user/culvert-lab/bin go install github.com/tsenart/vegeta/v12@v12.12.0
GOWORK=off go build -o /home/user/culvert-lab/bin/loadorigin-split lab/culvert/tools/loadsplit/loadorigin/main.go
cd lab/culvert/tools/loadsplit
python3 loadtest.py --out ../../results-load --rates 200,500,1000 --duration 30 --rounds 3
python3 loadtest.py --out ../../results-load-split --schemes https --rates 500,1000 --builds B,C,D --rounds 3
python3 loadhold.py --out ../../results-load-hold --rounds 3
python3 loadtest_report.py ../../results-load
```

The main run takes about 80 minutes, the split run 27 and the hold test 3.

## 5. Limits of this measurement

- **One shared 4-CPU container, not two hosts.** vegeta, the origin and the proxy compete for the same memory
  and kernel, even though each has its own CPUs. Absolute latencies are loopback figures, not Culvert's
  production latency. Only the differences between builds mean something.
- **1,000/s is this rig's knee, not the proxy's.** At 1,000 new TLS connections per second:
  - vegeta used about 80% of its core and the origin about 65% of its core, doing a full handshake per request;
  - the proxy used 67 to 85% of its two cores.

  In some rounds the latency of every build jumped by seconds, with `Bad Gateway` and client timeouts. This
  happened in round 1 of the main run (A and B; D's p99 rose to 418 ms) and in round 2 of the second run (B at
  76.7% success, D at 95.2%). The detector-off build B was the worst-hit in both runs, so this is not a detector
  effect. The cause was not isolated; the accept backlog (`somaxconn` 4,096, `tcp_max_syn_backlog` 1,024) and
  vegeta's worker growth are candidates. To measure at 1,000/s and above, run the load generator and the origin
  on other hosts.
- **The first attempt was discarded** (`results-load/aborted-run-port-exhaustion.log`). At 1,000/s every build
  failed on `bind: address already in use`: one connection per request into one proxy endpoint exhausted the
  default ephemeral port range (28,214 sockets in TIME_WAIT). The harness now checks the socket settings and
  drains TIME_WAIT before each cell. Every number in this report comes from the rerun.
- **Only first-message observation of short HTTPS tunnels.** Each tunnel carries one request. A long-lived tunnel
  pays the detector cost once, so per-request cost on keep-alive traffic is lower than here. Inspected tunnels,
  SOCKS5, WebSocket and plain HTTP are not observed in Phase 1.
- **RSS, not heap.** Memory is the process RSS. The Go heap, retained bytes and goroutines were not read from
  inside the process (Culvert exposes no runtime metrics), so allocation per flow is taken from GC cycles here
  and from `BenchmarkFlow` (14.3 KB per TLS flow).
- **No tracing during the runs** (plan 8.2). The CPU split comes from the fake engine, not from a profile.

## 6. Answer for the plan's budget table (section 9)

| Budget | Hypothesis | Measured here (observe mode, HTTPS) | Decision |
|---|---|---|---|
| Added latency per connection | (not in the table) | p50 ≤ +0.11 ms, p95 ≤ +0.6 ms, p99 within noise at 200 and 500/s | No action |
| Proxy CPU per flow | (not in the table) | +0.1 to +0.3 ms per tunnel, about half observation path and half engine | Input for Culvert's budget; the adapter's share is the cheaper half to reduce |
| Retained after observation | ≤ 4 KiB per relay | +3.9 KiB per tunnel (about +3.8 MiB per 1,000), RSS upper bound | Within, with little margin |
| Concurrent observed flows | admission cap from capacity | 1,000 silent tunnels admitted, 0 refused (cap 4,096) | No change |
