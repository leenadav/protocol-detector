# Child applications under load: what Classify adds to each decrypted request (PRO-516, 2026-11-27)

Follow-up of PRO-504 (`docs/integration/CHILDAPP-LAB.md`, PR #165), which measured the classifier with
micro-benchmarks only. This run drives the lab Culvert build end to end with vegeta and compares the child-app lab
**off** and **on** on the same binary. It is the baseline for Engine's allocation work on `AppClassifier.Classify`
(PRO-514).

Local only. Synthetic traffic, IPv4, loopback: a synthetic origin on 203.0.113.10 (RFC 5737) answers for the
hosts of the mix through `/etc/hosts`. Nothing left the container. The Culvert clone is read-only with its push URL
disabled; nothing was pushed or proposed to KidCarmi/Culvert. No detector code changed. vegeta (MIT) is a test
tool, never shipped.

## Result in short

Mix of five decrypted requests, sent round-robin; 3 repetitions of 60 s per cell; medians.

| | HTTP/1.1, 200 / 1,000 / 3,000 req/s | HTTP/2, 200 / 1,000 / 3,000 req/s |
|---|---|---|
| **Heap allocations per request**, off → on | 46.1 → 62.5 / 46.4 → 62.5 / 46.7 → 62.9 (**+16.1 to +16.3**) | 92.7 → 108.7 / 92.4 → 108.6 / 92.4 → 108.7 (**+16.1 to +16.3**) |
| **Heap bytes per request**, change | +807 / +764 / +779 B | +772 / +796 / +817 B |
| **Proxy CPU per request**, change of medians | +11.7 / +8.8 / +8.4 µs (paired ranges −32..+37, +5.5..+15.5, +4.1..+9.1) | +5.8 / +10.3 / −25.1 µs (within noise at every rate) |
| **Latency p50**, change | +9 / +10 / +19 µs, all within noise | +2 / +5 / −26 µs, all within noise |
| **Latency p95 / p99**, change | within noise at every rate (p99 +112 / −34 / −48 µs) | within noise at every rate (p99 +124 / +8 / −9 µs) |
| **Throughput** | target reached in every step, off and on | the same |
| **GC cycles per 1,000 requests**, change | +0.00 / +0.07 / +0.03 | +0.00 / +0.03 / +0.03 |
| **Peak RSS**, change | +4.9 / +3.2 / +3.5 MiB | +2.2 / +3.1 / +6.7 MiB |

"Within noise" means the off and on ranges over the three repetitions overlap (benchstat's "~"); the full table
with every range is in `lab/culvert/results-childapp-load/summary.md`.

- **Allocations are the one clear signal: +16.2 per request on this mix, on both protocols and at every rate.**
  That equals the PRO-504 micro-benchmarks averaged over the mix (lab hook: 23 child, 15 parent, 6 unowned), so the
  benchmark predicts the end-to-end figure; the classifier adds no hidden allocations under load.
- **CPU: about +8 to +12 µs per request on HTTP/1.1**, roughly 3 to 4 times the isolated 2.7 µs of
  `BenchmarkLabChildAppNote/child`. The profile agrees: `labAppTally.note` took 0.68 s of CPU for 90,000 requests
  (7.6 µs each) at 3,000 req/s, with lock profiling on. On HTTP/2 the run-to-run spread (± 3 to 12 %) is larger than the effect.
- **Latency and throughput do not move measurably** at 200, 1,000 or 3,000 req/s: a few µs on a 270 to 570 µs
  request is below this harness's resolution.
- **Correctness under load:** every request sent in an on-step was classified (1,511,997 requests; the `pd`
  counts exceed them by 0 to 5 per step, see "Checks"), with the right verdict for each of the five classes, and
  off-steps logged no `pd` block.

## Against the ADR-0011 budget (PR #160 draft, section 6)

| Budget | Value | This run | Verdict |
|---|---|---|---|
| ADR-0011 §4, allocations for the decryption block | ≤ 1 per **session** | +16.2 per **request** (mix average; up to 23 for a child match, PRO-504) | **Exceeded**, by about 15 per request on this mix (22 for a child match). As PRO-504 said, the per-session budget cannot hold a per-request classifier; the draft's section 6 needs a per-request row. |
| PRO-504's proposed row for section 6: application verdict per decrypted request | ≤ 24 allocations, ≤ 1.5 KB | +16.2 allocations and +0.76 to +0.82 KB on the mix; the worst class (child match) is 23 and 1.4 KB in the PRO-504 benchmark | **Within**, with 1 allocation of headroom on the worst class. |
| ADR-0011, off is unchanged | 0 added | not measurable end to end here (off is the baseline arm); 0 allocations per tunnel by `TestLabChildAppOffIsByteIdenticalAndAllocationFree` (PRO-504) | Holds. |
| Draft section 6, locks: no new process-wide lock | none | mutex profile: 0 samples under the classifier; block profile: 0.36 ms of 411 s on HTTP/2, 0 on HTTP/1.1 | Holds. |
| Draft section 6, CPU and latency | "report, no gate" (per-flow observation: +150 to +220 µs per flow; added p50 +5 to +113 µs) | +8 to +12 µs CPU per request (HTTP/1.1); latency within noise | Reported. Per request, the classifier costs about 1/20 of what protocol observation costs per flow. |
| Draft section 6, GC | "report" (+2.5 to +3 per 1,000 flows for observation) | +0.03 to +0.07 per 1,000 requests | Reported. |

**Proposed row for the ADR draft** (to replace the PRO-504 proposal when PRO-514 lands): "application verdict per
decrypted request: ≤ 24 allocations and ≤ 1.5 KB (end-to-end mix average 16.2 and 0.8 KB on 2026-11-27); CPU
report only (+8 to +12 µs per request on HTTP/1.1)". The gate stays the library's allocation test plus a Culvert
benchgate on `BenchmarkLabChildAppNote`; this run shows that the benchmark predicts the end-to-end figure.

## Where the cost is (profiles at 3,000 req/s)

CPU, allocation, mutex and block profiles of the proxy, 30 s each, off and on, both protocols. Raw profiles and
text reports: `lab/culvert/results-childapp-load/profiles/` (`pprof-top.txt`).

**CPU, top 5 under `labAppTally.note`** (HTTP/1.1: 0.68 s, 6.5 % of the proxy's samples; HTTP/2: 0.67 s, 3.8 %):

| # | HTTP/1.1 (cum) | HTTP/2 (cum) |
|---|---|---|
| 1 | `childapp.(*Set).Classify` 0.44 s (the library; `detector.(*AppClassifier).Classify` 0.47 s) | `childapp.(*Set).Classify` 0.51 s |
| 2 | `runtime.mallocgc` 0.16 s (allocation) | **`runtime.newstack` / `copystack` 0.31 s**, entered from `childapp.normalizeHost` |
| 3 | `childapp.(*rule).matches` 0.10 s | `runtime.mallocgc` 0.07 s |
| 4 | `labAppTally.add` 0.09 s (lab hook: the tally) | `childapp.(*rule).matches` 0.06 s |
| 5 | `strings.Split` 0.06 s, `fmt.Sprintf` 0.05 s | `labAppTally.add` 0.05 s |

**Allocations, top 5 under `labAppTally.note`** (alloc_objects, HTTP/1.1; HTTP/2 has the same order):

| # | Site | Share of the classifier's allocations |
|---|---|---|
| 1 | `labAppTally.note`, `names = append(names, k)` (`childapp_lab.go:108`, lab hook: the header-name slice grows by append) | 29 % |
| 2 | `strings.Split` in the library: `matchPattern` 43 %, `normalizeHost` 34 %, `canonicalPath` 23 % of it | 27 % |
| 3 | `strings.ToLower` in `childapp.(*Set).Classify` (its `strings.Builder` growth, `bytealg.MakeNoZero`) | 23 % |
| 4 | `childapp.parseQuery` | 8 % |
| 5 | `detector.(*AppClassifier).Classify` flat, `labAppTally.add`, `fmt.Sprintf` in `Set.Classify` | 4 % each or less |

Profiles are sampled, so the shares are approximate; the per-request counts come from `runtime/metrics`, not from
the profiles.

**Levers, in order of size** (none taken here; they belong to Engine, PRO-514, and to the lab hook):
1. **Library: split-free matching.** `strings.Split` in `matchPattern`, `normalizeHost` and `canonicalPath`, and
   `strings.ToLower` in `Set.Classify`, are about half of the classifier's allocations. Iterating segments with
   `strings.Cut`/`IndexByte`, comparing in place and lower-casing only when a byte is upper case (ASCII fast path)
   removes most of them.
2. **HTTP/2: stack growth.** Every H2 stream runs on a fresh goroutine, and the classifier's call depth makes it
   grow its stack once per stream (`newstack` from `normalizeHost`), which is nearly half of the classifier's CPU on
   HTTP/2. Smaller frames on that path (no large local arrays, less inlining depth) would avoid it. This is invisible
   in `BenchmarkRealAppsClassify`, which runs on a grown benchmark goroutine; an H2-shaped benchmark (a new goroutine
   per call) would show it.
3. **Lab hook: preallocate the header-name slice** (`make([]string, 0, min(len(req.Header), 32))`): 2 to 3 fewer
   allocations per request. A Culvert-side change for the product PR, not made here (no Culvert patch change in this
   task).
4. `fmt.Sprintf` in `Set.Classify` and `parseQuery`: small, per request.

## Method

**Build.** Culvert `ef9431189490f7f85bb32d6fe7e7b6b8be5b0844` + `lab/culvert/culvert-lab-ef94311.patch` (sha256
`e1a90fa3…`) + `lab/culvert/culvert-lab-ef94311-childapp.patch` (sha256 `6b8cbd77…`), applied with `git am` on a
fresh read-only clone (local branch `lab/childapp-ef94311`, head `4109615c`, tree `52897d4a`; the head depends on
the committer date). The detector is this branch's `go/` at `9a4226b` through `go.work`. Go 1.27.4 (Culvert's
`toolchain`). One extra file is copied into the clone before the build: `lab/culvert/tools/childappload/
zz_labmetrics_lab.go`, a loopback-only `runtime/metrics` and `net/http/pprof` endpoint enabled by
`CULVERT_LAB_METRICS_ADDR`. It is not part of the lab patch and runs in both arms. Measured binary sha256
`f8cc01b6…`; the profile pass used a rebuild with the opt-in lock profiling (`CULVERT_LAB_PROFILE_LOCKS`, set only
for that pass), sha256 `1112cfda…`. The committed hook differs from the one in both builds only in how the loopback metrics listener is
started (`http.Server` with a 5 s `ReadHeaderTimeout` instead of `http.ListenAndServe`, for the workflow policy's
no-`#nosec` rule); the request path and both arms are unaffected.

**Configuration.** Each step starts a fresh proxy with an empty data directory, creates a throw-away admin and two
rules through Culvert's own API (`tools/childappload/inspect_rule.py`): an auth rule that exempts 127.0.0.1 from
proxy credentials, and Allow + `sslAction: Inspect` for every destination with traffic logging on. HTTP/1.1 steps
use the rule default (ALPN stripped: `runH1InspectLoop`); HTTP/2 steps set `stripAlpn: false`, so the tunnel is
inspected natively (`handleInspectH2`). Culvert verifies the origin's certificate against a throw-away lab CA given
by `SSL_CERT_FILE`; vegeta does not verify Culvert's forged leaf (`-insecure`). Every other Culvert protection stays
at its default.

| Arm | Environment |
|---|---|
| off | `CULVERT_LAB_CHILDAPP` unset |
| on | `CULVERT_LAB_CHILDAPP=real` |

**Traffic.** vegeta v12.12.0 (`-http2=false|true -rate=R -duration=60s -timeout=10s -connections=32
-max-connections=32`) through `HTTPS_PROXY`. The 32-connection cap per host keeps a fixed pool of kept-alive
tunnels, so a step measures the per-request cost on established tunnels. (Without it, a queueing spike at
3,000 req/s on HTTP/1.1 made vegeta open new tunnels, each with a CONNECT and two TLS handshakes: 274 allocations
per request and a 0.9 s p99 in a trial, whichever arm went first.) The five targets, round-robin:

| Class | Request | Verdict in the `pd` block |
|---|---|---|
| gmail-like upload | `POST gmail.googleapis.com/upload/gmail/v1/users/me/messages?uploadType=media`, `message/rfc822`, 74-byte body | `gmail-uploading`, `child_rule_matched` |
| child-matched | `GET www.googleapis.com/drive/v3/files/1AbCdEf/export?mimeType=text/plain` | `google-drive-downloading`, `child_rule_matched` |
| parent only | `GET gmail.googleapis.com/gmail/v1/users/me/labels` | `google-base`, `no_child_rule_matched` |
| unowned host | `GET unowned.example/upload` | no app, `host_unowned` |
| non-canonical path | `POST gmail.googleapis.com/upload/gmail/v1/users/me/../me/messages?uploadType=media` | `google-base`, `path_not_canonical` |

The origin (`tools/childappload/origin`, Go standard library) serves HTTP/1.1 and HTTP/2, discards the body and
answers 200 with 22 bytes. It uses a plain handler, not `http.ServeMux`, which would answer the `..` path with a
301 and turn one request into two.

**Order.** 3 repetitions × 2 protocols × 200, 1,000, 3,000 req/s × 2 arms = 36 steps of 60 s, 03:45 to 04:26 UTC.
The arm order alternates by repetition and rate. Each step has an unrecorded 5 s warm-up at 100 req/s.

**CPU placement.** The host has 4 vCPUs: the proxy on CPUs 0–1, vegeta on 2, the origin on 3 (`taskset`).

**Measurements** (`tools/childappload/run.py`), per step over the 60 s attack:
- latency and throughput from vegeta's JSON report (end to end as the client sees it, on an established tunnel);
- proxy CPU: utime + stime from `/proc/<pid>/stat`, divided by the requests;
- heap allocations (objects and bytes) and GC cycles: `runtime/metrics` deltas from the lab endpoint, divided by
  the requests (this includes the proxy's own background work, the same in both arms);
- peak RSS: `VmRSS` every 100 ms;
- on-steps: every `pd` block from `/api/logs`, summed per verdict.

`tools/childappload/summary.py` builds the benchstat-style tables (median ± largest deviation, change of medians,
paired range, "~" when the ranges overlap). CPU per request is higher at 200 req/s than at 3,000 because the
proxy's fixed background work is spread over fewer requests; compare arms within a rate, not across rates.

**Machine.** Linux 6.18.44 cloud container, 4 vCPU Intel Xeon Processor @ 2.30 GHz (1 thread per core, L2 8 MiB,
L3 260 MiB), 15 GiB RAM, shared host. Local CPU work, not production latency.

## Checks

- **Every request was classified.** On-steps: the `pd` request count minus (requests sent + the 500 warm-up
  requests) is 0 to 5 per step, never negative. The extra ones are requests that Go's transport re-sent on a new
  tunnel after a reused one closed: the proxy saw them twice, vegeta counts them once.
- **Verdicts.** Each on-step shows exactly the five verdicts of the table above, in equal counts (largest
  difference between classes: 3, from the re-sent requests).
- **Off-steps** logged 0 `pd` blocks.
- **Errors.** 3,023,999 requests, all 200 except one: `POST …/upload/gmail/…: EOF` in the HTTP/1.1, 1,000 req/s,
  repetition 1 on-step (1 of 60,000). One request in three million is too few to attribute to the classifier; it
  is recorded, not explained.

## Files

| Path | What |
|---|---|
| `lab/culvert/tools/childappload/run.py` | the runner (`--self-test`) |
| `lab/culvert/tools/childappload/summary.py` | the tables (`--self-test`) |
| `lab/culvert/tools/childappload/inspect_rule.py` | admin, auth exemption and inspect rule through Culvert's API (`--self-test`) |
| `lab/culvert/tools/childappload/origin/main.go` | the synthetic HTTPS origin, h1 and h2 |
| `lab/culvert/tools/childappload/zz_labmetrics_lab.go` | the loopback metrics and pprof hook copied into the lab clone |
| `lab/culvert/results-childapp-load/results.json` | the 36 steps, raw |
| `lab/culvert/results-childapp-load/summary.md` | the full tables |
| `lab/culvert/results-childapp-load/run.log` | the runner's one line per step |
| `lab/culvert/results-childapp-load/profiles/` | CPU, allocs, mutex and block profiles, off and on, h1 and h2; `pprof-top.txt` |

**Reproduce** (after the lab clone and `/etc/hosts` entries for the three hosts → 203.0.113.10):

```bash
python3 lab/culvert/tools/childappload/run.py --out lab/culvert/results-childapp-load/results.json
```

```bash
python3 lab/culvert/tools/childappload/summary.py lab/culvert/results-childapp-load/results.json
```

```bash
python3 lab/culvert/tools/childappload/run.py --profile-out lab/culvert/results-childapp-load/profiles --rate 3000 --duration 40
```
