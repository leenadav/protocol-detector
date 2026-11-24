# Culvert lab load test: what the detector adds to each connection (PRO-269, 2026-11-24)

Lee approved this test on 2026-11-23. It ran in the synthetic Culvert lab only: loopback addresses, a synthetic
origin on 203.0.113.10 (RFC 5737), and no traffic to or from anything outside the container. Nothing was sent to,
pushed to or proposed for KidCarmi/Culvert. vegeta (MIT) is a test tool here; it is not a dependency of the
detector or of Culvert and is never shipped.

## Result in short

On the path the detector observes (HTTPS through a CONNECT tunnel that Culvert relays without inspection), with
one new connection per request, at 100, 300 and 600 requests per second:

| | 100 req/s | 300 req/s | 600 req/s |
|---|---:|---:|---:|
| Added latency p50 (µs) | +113 | +73 | +5 |
| Added latency p95 (µs) | +424 | +185 | +84 |
| Added latency p99 (µs) | +19 | +9 | +220 |
| Latency with the detector off, p50 / p99 (µs) | 1,865 / 4,589 | 1,744 / 3,680 | 2,054 / 9,477 |
| Throughput, off → observe (req/s) | 100.0 → 100.0 | 300.0 → 300.0 | 600.0 → 600.0 |
| Proxy CPU per 1,000 flows, off → observe (CPU-s) | 1.015 → 1.225 (+0.210) | 0.930 → 1.153 (+0.223) | 1.103 → 1.255 (+0.152) |
| Proxy peak RSS, off → observe (MiB) | 51.8 → 54.3 (+2.5) | 55.2 → 55.6 (+0.4) | 55.1 → 56.0 (+0.9) |
| Flows observed and logged | 2,000 of 2,000 | 6,000 of 6,000 | 12,000 of 12,000 |

"Added" is observe mode minus detector off, on the same lab binary, taken per round and then the median of three
rounds. The ranges over the rounds are in the full tables below.

- **Latency.** The median request gets about 0.0 to 0.1 ms slower, against a base of about 1.7 to 2.1 ms for a new
  HTTPS connection through the proxy. The p95 gets up to 0.42 ms slower. At p99 the difference is smaller than
  the run-to-run noise: the per-round range includes negative values at every rate.
- **CPU.** The detector costs 0.15 to 0.22 CPU-seconds per 1,000 flows, about 150 to 220 µs per flow. That is
  14 to 24 % more proxy CPU on this path. It covers the engine, the record and the JSON log line that observe
  mode writes for each tunnel.
- **Memory.** Peak resident memory is 0.4 to 2.5 MiB higher and does not grow with the number of flows: a
  12,000-flow step ends 0.9 MiB above the off build. Each flow lives about 2 ms here, so only a few are observed
  at the same time. The lab's own limit bounds the worst case: 4,096 concurrently observed tunnels with at most a
  32 KiB reservation each, so at most 32 MiB per 1,000 concurrent observed flows.
- **Throughput** is unchanged: every configuration reached the target rate with 100 % success at 100, 300 and
  600 req/s.
- **The control behaves as expected.** Plain HTTP through the forward proxy is not observed: 0 records. Its
  observe-minus-off difference is within noise (p50 −34 to +41 µs), and its CPU difference is +0.002 to
  +0.025 CPU-s per 1,000 flows.
- **The lab hook costs nothing measurable with the detector off.** Lab build B against unmodified Culvert A: p50
  −59 to +4 µs, CPU −0.06 to +0.09 CPU-s per 1,000 flows.
- **At 1,000 req/s this harness saturates,** with or without the detector (see "Saturation at 1,000 req/s"). The
  figures at that rate measure queueing in the harness, not the detector's cost.

## Method

**Configurations.** Each one is started fresh for every round, with an empty data directory, no admin account and
no rules:

| Name | Binary | Detector |
|---|---|---|
| direct | none: vegeta to the origin, no proxy | none (the floor) |
| A | unmodified Culvert `ef94311` | none |
| B | lab build (Culvert `ef94311` + `lab/culvert/culvert-lab-ef94311.patch`) | off (`CULVERT_LAB_PROTODETECT` unset) |
| D | the same lab build | observe mode (`CULVERT_LAB_PROTODETECT=real`; families http, tls, ssh, smtp; window 10 s) |

Visibility only, as decided on 2026-11-17: the lab build has no blocking and no L7. Every Culvert protection stays
at its default.

**Traffic.**
- `vegeta attack -insecure -keepalive=false -rate=R -duration=20s -timeout=10s`, with one target, `GET /load`.
- `-keepalive=false` gives every request its own TCP connection, so one request is one flow and one detector
  observation.
- HTTPS: `https://origin.lab.test/load` with `HTTPS_PROXY`. Go's client opens a CONNECT tunnel, and Culvert relays
  it without inspection: the path the detector observes. The origin's certificate is a throw-away self-signed one
  made at start-up, hence `-insecure`.
- HTTP: `http://origin.lab.test/load` with `HTTP_PROXY`, through Culvert's forward proxy. The detector does not
  observe this path. It is the control.
- Rates: 100, 300 and 600 req/s, plus 1,000 req/s to find saturation. Each step lasted 20 s (2,000 to 20,000
  flows), with 3 s between steps.
- A 2 s warm-up at 50 req/s after each start was not recorded.
- Three rounds. Each round runs direct first, then rotates the order of A, B and D, so no configuration always
  comes first. The 600 req/s round set ran in a second invocation, right after the first.

**Origin.** `lab/culvert/tools/loadorigin` is a Go standard-library server on 203.0.113.10:80 and :443, a
loopback alias. It answers every request with a 22-byte `text/plain` body.

**CPU placement.** The host has 4 vCPUs. The proxy is pinned to CPUs 0 and 1, vegeta to CPU 2 and the origin to
CPU 3 (`taskset`).

**Measurements,** by `lab/culvert/tools/loadtest.py` for every step:
- latency and throughput from vegeta's JSON report;
- proxy CPU as the change in utime + stime (`/proc/<pid>/stat`, 10 ms resolution) over the step, divided by the
  requests;
- proxy resident memory sampled every 100 ms (`VmRSS`), as the peak and the mean;
- the PROTODETECT records the step logged, and any refused admissions.

`lab/culvert/tools/loadtest_summary.py` computes the tables. Latency is end-to-end, as vegeta's client sees it:
the TCP connect to the proxy, CONNECT, TLS handshake, request and response. "Added latency" is therefore what
observation adds to a whole new connection.

**Versions:**

| Component | Version |
|---|---|
| vegeta | `github.com/tsenart/vegeta/v12` v12.12.0 (`h1:FKMMNomd3auAElO/TtbXzRFXAKGee6N/GKCGweFVm2U=`), built with Go 1.24.7 |
| Culvert | `ef9431189490f7f85bb32d6fe7e7b6b8be5b0844` (A); with the 4-commit lab patch applied with `git am`: tree `b9037501`, local head `a4b63f3b` (B, D) |
| Lab patch | `lab/culvert/culvert-lab-ef94311.patch`, sha256 `e1a90fa3…`, the patch the lab README records for its head `8f828789` |
| Detector | this repository's `go/` module at `main` `593f6a4`, through `go.work` (`lab/culvert/go.work.example`) |
| Go (Culvert builds) | go1.27.4 linux/amd64, `toolchain go1.27.4` of Culvert's `go.mod` |
| Go (loadorigin) | go1.24.7 linux/amd64 |
| Host | Linux 6.18.44, 4 vCPU Intel Xeon at 2.10 GHz, 16 GiB, cloud container |

**Raw data:**
- `lab/culvert/results-loadtest/results.json`: 100, 300 and 1,000 req/s, 72 steps, 15:50 to 16:20 UTC;
- `lab/culvert/results-loadtest/results-600.json`: 600 req/s, 24 steps, 16:21 to 16:31 UTC;
- `lab/culvert/results-loadtest/summary.md`: the generated tables for both files.

## Full results

Latency in µs, the median over 3 rounds. CPU-s are per 1,000 flows. "PD records" counts the observation records
Culvert logged, against the requests sent.

### HTTPS, CONNECT tunnel (observed by the detector in D)

| Rate | Config | p50 | p95 | p99 | max | Throughput | Success | CPU-s / 1,000 flows | Peak RSS MiB | PD records |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 100 | direct | 1318 | 1875 | 3421 | 13782 | 100.0 | 100.00% | n/a | n/a | n/a |
| 100 | A | 1887 | 2517 | 4533 | 13785 | 100.0 | 100.00% | 1.010 | 49.1 | n/a |
| 100 | B | 1865 | 2510 | 4589 | 19954 | 100.0 | 100.00% | 1.015 | 51.8 | n/a |
| 100 | D | 1875 | 2693 | 4836 | 10266 | 100.0 | 100.00% | 1.225 | 54.3 | 2000 of 2000 |
| 300 | direct | 1362 | 1833 | 3003 | 26019 | 300.0 | 100.00% | n/a | n/a | n/a |
| 300 | A | 1832 | 2549 | 5279 | 48778 | 300.0 | 100.00% | 0.962 | 51.6 | n/a |
| 300 | B | 1744 | 2274 | 3680 | 16907 | 300.0 | 100.00% | 0.930 | 55.2 | n/a |
| 300 | D | 1817 | 2449 | 3567 | 17130 | 300.0 | 100.00% | 1.153 | 55.6 | 6000 of 6000 |
| 600 | direct | 1273 | 2111 | 3431 | 16784 | 600.0 | 100.00% | n/a | n/a | n/a |
| 600 | A | 1865 | 4066 | 9113 | 26087 | 600.0 | 100.00% | 1.011 | 52.4 | n/a |
| 600 | B | 2054 | 5244 | 9477 | 56172 | 600.0 | 100.00% | 1.103 | 55.1 | n/a |
| 600 | D | 1928 | 4899 | 10387 | 50464 | 600.0 | 100.00% | 1.255 | 56.0 | 12000 of 12000 |
| 1000 | direct | 1451 | 4916 | 9745 | 41559 | 1000.0 | 100.00% | n/a | n/a | n/a |
| 1000 | A | 9483 | 173845 | 317753 | 806049 | 999.0 | 100.00% | 1.232 | 65.2 | n/a |
| 1000 | B | 5571 | 37411 | 73628 | 187029 | 999.9 | 94.89% | 1.196 | 60.9 | n/a |
| 1000 | D | 8440 | 95017 | 233544 | 532156 | 999.1 | 100.00% | 1.310 | 72.5 | 20227 of 20000 |

Added latency in µs: the median of the per-round differences, with the range in brackets.

| Rate | Pair | p50 | p95 | p99 |
|---:|---|---:|---:|---:|
| 100 | D − B: observe vs off, same binary | +113 [−20..+201] | +424 [+69..+471] | +19 [−414..+1447] |
| 100 | B − A: lab build (off) vs unmodified | −59 [−145..+40] | −245 [−247..+208] | −331 [−506..+1137] |
| 300 | D − B | +73 [+54..+172] | +185 [+175..+244] | +9 [−165..+959] |
| 300 | B − A | −54 [−116..−1] | −195 [−378..−119] | −1575 [−2451..−669] |
| 600 | D − B | +5 [−185..+94] | +84 [−1807..+1650] | +220 [−3409..+4401] |
| 600 | B − A | −31 [−137..+383] | −433 [−816..+2622] | +364 [−6394..+6584] |
| 1000 | D − B (saturated, not meaningful) | +2575 [−386228..+5791] | +71009 [−2714784..+141817] | +159916 [−4349175..+249303] |
| 1000 | B − A (saturated, not meaningful) | −2187 [−8421..+388893] | −29076 [−206603..+2608110] | −29235 [−452828..+4128791] |

Every observed flow was identified in both directions. In the 600 req/s run's last D log (12,100 records,
warm-up included), all 24,200 direction results are `identified` / `engine` (TLS). No step logged a refused
admission.

### HTTP, forward proxy (the control: not observed)

| Rate | Config | p50 | p95 | p99 | max | Throughput | Success | CPU-s / 1,000 flows | Peak RSS MiB | PD records |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 100 | direct | 391 | 602 | 1186 | 5343 | 100.0 | 100.00% | n/a | n/a | n/a |
| 100 | A | 1017 | 1598 | 3682 | 24439 | 100.0 | 100.00% | 0.905 | 61.3 | n/a |
| 100 | B | 956 | 1333 | 2794 | 8183 | 100.0 | 100.00% | 0.845 | 61.0 | n/a |
| 100 | D | 982 | 1386 | 2872 | 9972 | 100.0 | 100.00% | 0.870 | 63.7 | 0 of 2000 |
| 300 | direct | 367 | 552 | 986 | 5608 | 300.0 | 100.00% | n/a | n/a | n/a |
| 300 | A | 913 | 1416 | 2998 | 8606 | 300.0 | 100.00% | 0.812 | 56.8 | n/a |
| 300 | B | 902 | 1692 | 2775 | 15203 | 300.0 | 100.00% | 0.805 | 58.8 | n/a |
| 300 | D | 952 | 1533 | 2733 | 11467 | 300.0 | 100.00% | 0.822 | 60.4 | 0 of 6000 |
| 600 | direct | 327 | 514 | 946 | 11178 | 600.0 | 100.00% | n/a | n/a | n/a |
| 600 | A | 835 | 1330 | 2456 | 20536 | 600.0 | 100.00% | 0.760 | 54.1 | n/a |
| 600 | B | 851 | 1360 | 2514 | 21126 | 600.0 | 100.00% | 0.761 | 58.0 | n/a |
| 600 | D | 860 | 1286 | 2219 | 14604 | 600.0 | 100.00% | 0.765 | 57.8 | 0 of 12000 |
| 1000 | direct | 315 | 576 | 1099 | 6771 | 1000.0 | 100.00% | n/a | n/a | n/a |
| 1000 | A | 794 | 1478 | 2860 | 20980 | 1000.0 | 100.00% | 0.629 | 55.1 | n/a |
| 1000 | B | 848 | 1562 | 3863 | 23177 | 1000.0 | 100.00% | 0.653 | 57.9 | n/a |
| 1000 | D | 827 | 1465 | 3002 | 12393 | 1000.0 | 100.00% | 0.655 | 58.2 | 0 of 20000 |

| Rate | D − B p50 | p95 | p99 | CPU-s / 1,000 flows D − B | Peak RSS D − B (MiB) |
|---:|---:|---:|---:|---:|---:|
| 100 | +41 [+26..+49] | +29 [−218..+115] | +12 [−634..+265] | +0.025 | +2.7 |
| 300 | +15 [+5..+93] | −159 [−489..+276] | −42 [−639..+61] | +0.017 | +1.6 |
| 600 | −34 [−36..+18] | −28 [−91..−4] | −226 [−314..−202] | +0.004 | −0.2 |
| 1000 | +15 [−75..+109] | +32 [−401..+165] | −796 [−1368..+364] | +0.002 | +0.3 |

The RSS differences of 0.3 to 2.7 MiB on this unobserved path are the noise floor of the memory figure. The HTTPS
memory differences (+0.4 to +2.5 MiB) are inside that floor.

## Saturation at 1,000 req/s

HTTPS at 1,000 new connections per second saturates this harness in every configuration, including unmodified
Culvert:
- A's p99 is 318 ms, against 5 ms at 300 req/s.
- vegeta runs on one CPU and performs 1,000 TLS handshakes a second. The proxy spends about 1.2 to 1.3 CPU-s per
  second on its two CPUs.
- In round 1, B lost 5.1 % of its requests to the client's own `bind: address already in use` (ephemeral ports:
  each request opens two connections, and closed ones linger in TIME_WAIT) and to `Bad Gateway`.
- In D, Culvert logged 20,227 tunnel records for 20,000 requests (median of rounds). So under saturation the
  client opened more tunnels than it completed requests. The likely cause is Go's HTTP client dialling again when
  a connection fails before the request is written; this run did not confirm it.

The per-round D − B differences at this rate run from −4.3 s to +0.25 s. They describe queueing, not the
detector. Measuring the capacity limit, and the detector's share of it, needs a client that does not share the
host's CPUs: a multi-host test, out of this lab's scope.

## Limits of this measurement

- Synthetic, loopback-only, one container with a 4-vCPU budget. These are local CPU and latency figures, not
  production end-to-end latency (AGENTS.md, "Benchmarks report local CPU work").
- One protocol in the observed path: TLS 1.3 ClientHello and ServerHello from Go's client and server. HTTP, SSH
  and SMTP inside a tunnel were not load-tested, because vegeta speaks HTTP(S) only, and the forward proxy is not
  observed.
- One small response per connection. Larger transfers leave observation after the window or the handoff, and
  Culvert's normal copy path carries the rest (lab README), so per-flow detector cost does not grow with the
  transfer size. This was not measured here.
- The proxy's CPU figure has 10 ms resolution per step: at least ±0.005 CPU-s per 1,000 flows at 100 req/s.
- Memory is the RSS of the whole Go process, which the garbage collector shapes. It is not a heap profile.
- Observe mode writes one JSON log line per tunnel to Culvert's log, here a file. That cost is included in D.

## How to reproduce

From an environment where the lab is set up (`docs/integration/LANE-BRIEF-culvert.md` §4):

1. Build A from an unmodified worktree at `ef94311`: `GOWORK=off go build -o /home/user/culvert-lab/bin/culvert-A .`
2. Build the lab binary on the lab branch: `GOWORK=/home/user/culvert-lab/go.work go build -o /home/user/culvert-lab/bin/culvert-lab .`
3. Build the origin from this repository:
   `(cd lab/culvert/tools/loadorigin && GO111MODULE=off go build -o /home/user/culvert-lab/bin/loadorigin .)`
4. Install vegeta: `go install github.com/tsenart/vegeta/v12@v12.12.0`
5. Add the loopback alias and the host name:
   `python3 lab/culvert/tools/addaddr.py 203.0.113.10`, then
   `echo "203.0.113.10 origin.lab.test" >> /etc/hosts`
6. From `lab/culvert`, run the two invocations and the summary:
   - `python3 -B tools/loadtest.py --out results-loadtest/results.json`
   - `python3 -B tools/loadtest.py --rates 600 --out results-loadtest/results-600.json`
   - `python3 -B tools/loadtest_summary.py results-loadtest/results.json results-loadtest/results-600.json > results-loadtest/summary.md`

Both tools have a `--self-test`.
