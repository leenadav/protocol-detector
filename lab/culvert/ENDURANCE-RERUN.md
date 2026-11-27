# Culvert lab endurance re-run with revision 1 (PRO-564, working plan phase L6)

The PRO-540 run (`ENDURANCE.md`) failed P1 because of when its baseline was taken, not because of a leak
(diagnostics D1 to D3). Hermes chose candidate 1 of that report. This document reports one run of the same
30-minute schedule with that revision. Local lab only: loopback, RFC 5737 origin addresses, synthetic traffic.
The Culvert clone is read-only (push URL disabled), and nothing was pushed to, or proposed for, KidCarmi/Culvert.

**Verdict: P1 to P5 all pass** (`results-endurance-rerun/verdict.json`, `run.py --verdict`, `"all_pass": true`).

| # | Condition | Result | Evidence |
|---|---|---|---|
| P1 | Goroutines and live heap within ±10% of the baseline ≤ 60 s after load | **pass** | first within at 5.0 s and still within at 60.1 s: goroutines 25 vs 25 (0%); live heap 10.30 MB vs 11.02 MB (−6.5%) |
| P2 | No unbounded growth slope in the steady phase | pass | largest \|slope\| 0.51%/min (p3 goroutines); heap ≤ 0.16%/min, RSS ≤ 0.23%/min, fds ≤ 0.23%/min |
| P3 | No panic | pass | engine panics 0 in p1, p2 and p3; no "panic" log line in any of the five processes; every exit code 0 |
| P4 | No leaked reservation | pass | after load: `Active` 0, `ReservedBytes` 0, `RetainedBytes` 0; 0 refused admissions in 214,777 |
| P5 | Flows after the restart and the content change use the intended version | pass | every pd block: p1 and p2 `content=2026.11.8`, p3 `content=2026.11.9` (child release 2026.11.1 throughout), none mixed |

## 1. The revision (recorded before the run)

`results-endurance-rerun/manifest.json`, block `revision`, committed and pushed in `4fe99b7` before the run
started (working plan 8.3). Only the time of the P1 baseline changes:

- **Warm-up.** Process p1 is driven with the same mix (`endurance-load drive`, unchanged) for 60 s, starting
  when it is ready. This fills Culvert's request-log ring (`reqlog.MaxRing` 5,000, D3) and builds the lazy
  child-app classifier (`sync.Once`, D2).
- **Idle, then the baseline.** The process is then left idle. The three baseline samples (forced GC, median, as
  before) start no earlier than 120 s after p1 was ready and 30 s after the warm-up driver exited. By then the
  two `net/http` keep-alive connections that close about 85 s after start (D1) have closed.
- **Unchanged:**
  - the thresholds: ±10%, 60 s, the 120 s steady skip and 1.0%/min;
  - the mix and rates, the 1,800 s of load, the restart at 600 s and the content change at 1,200 s;
  - the sampling, the verdict code, and the binaries' sources;
  - traffic logging, which stays on, as in production.

`run.py` without a `warmup` block runs exactly as in PRO-540. Between the warm-up and the baseline it records
`settle` samples (forced GC, every 15 s). They are not pass-condition inputs.

**Timing in this run:**
- the warm-up ran from 0 to 80.7 s after p1 was ready (60 s of new tunnels, then the 20 s holds finishing);
- the settle samples were taken at 81, 96 and 111 s: 38, then 25 and 25 goroutines;
- the baseline samples were taken at 120.0, 125.0 and 130.1 s.

## 2. Samples

| Time | Process | Goroutines | Live heap | Open fds | RSS | Detector active |
|---|---|---|---|---|---|---|
| reference idle, both binaries | ref-v8, ref-v9 | 29 | 6.45–6.52 MB | 15 | 45.4–46.9 MiB | 0 |
| warm-up end (+81 s) | p1 | 38 | 10.52 MB | 89 | 62.3 MiB | 0 |
| baseline (+120 to +130 s) | p1 | 25, 25, 25 | 10.26, 11.02, 11.03 MB | 13 | 55.4–60.1 MiB | 0 |
| load, from 120 s after ready | p1 | 154–157 | 11.35–11.79 MB | 187–195 | 66.2–67.1 MiB | 25–26 |
| restart at 616 s | p2 | 32–162 | 8.20–11.77 MB | 29–193 | 48.5–67.1 MiB | 1–26 |
| content change at 1,216 s | p3 | 32–168 | 8.67–11.76 MB | 25–201 | 48.5–66.7 MiB | 0–29 |
| load stop + 5 s | p3 | 25 | 10.31 MB | 54 | 57.1 MiB | 0 |
| load stop + 60 s | p3 | 25 | 10.30 MB | 13 | 56.6 MiB | 0 |
| load stop + 180 s | p3 | 25 | 10.32 MB | 13 | 57.1 MiB | 0 |

The p2 and p3 load ranges include their first samples after each start. The steady slopes (P2) skip those
samples.

**The heap of the idle process moves by 0.75 MB with the lab's own feed query.** The first baseline sample, at
10.26 MB, was taken before the orchestrator read the latest 1,000 feed entries (`/api/logs?limit=1000`, for the
P5 release tally). The next two samples, at 11.02 and 11.03 MB, came after it. The same step shows after the
recovery run: the post samples read 11.05, 11.02 and 11.01 MB after the 60 s recovery sample, which queries the
feed, and 10.32 MB once that is collected. So the median baseline holds about 0.75 MB of a transient that the
measuring tool causes, and the recovery samples at 5 to 55 s (no feed query) do not. PRO-540 sampled the same
way. P1 passes against either figure: the recovery heap is −6.5% from the median and +0.4% from the first sample.
Changing the sampling would be a revision of its own, so this run leaves it as it is.

## 3. Other results

- **Driver.** 225,389 flows passed their traffic check in the 1,800 s of load: tls 106,065, http1 44,198, ssh 35,359,
  inspect 17,674, adverse 17,680, quiet 3,535, blocked 878.
  - 4,103 flows failed. All of them fall in the two 30 s intervals that hold a restart (2,054 and 2,049): refused
    dials while Culvert drains for its 15 s shutdown timeout.
  - The new process was ready 1.37 s and 1.27 s after the old one exited.
  - 6 inspected flows failed on the old inspection CA during the switch. The 6 `blocked` tunnels reported closed
    early are among those force-closed at shutdown, as in PRO-540.
  - The warm-up driver passed all 7,650 of its flows, with no failure.
- **Detector records.** 214,777 records in the three processes (p1 77,573, including the 7,050 of the warm-up;
  p2 68,614; p3 68,590), none refused. Identified:
  - TLS 109,671 in both directions;
  - HTTP 46,113 on the client side;
  - SSH 37,389 on the client side.

  On the client side the adverse inputs gave `budget_exhausted` 1,746, `malformed` 832, `unknown` 1,248,
  `outside_profile` 9,133 (smb2 2,073 the most) and `incomplete` 8,645. 415 records carry `host_mismatch`.
- **Steady-state slopes** (% of the mean per minute, from 120 s after each process was ready):

  | Process | Samples | Span | Goroutines | Live heap | RSS | Open fds |
  |---|---|---|---|---|---|---|
  | p1 | 19 | 9.0 min | 0.09 | 0.14 | 0.09 | 0.11 |
  | p2 | 15 | 7.0 min | 0.00 | 0.16 | 0.12 | 0.05 |
  | p3 | 16 | 7.5 min | 0.51 | −0.02 | 0.23 | 0.23 |

  Detector `ReservedBytes` was at most 950,272 (29 × 32 KiB), and `RetainedBytes` at most 136.

## 4. Compared with PRO-540

- **The baseline.** With the warm-up, the baseline is 25 goroutines and 11.02 MB. PRO-540 had 29 goroutines and
  6.51 MB.
- **After load.** The values are the same as in PRO-540: 25 goroutines and 10.30 MB at 60 s. So the P1 failure
  was the baseline's timing, as D1 to D3 said, and the 30 minutes leave nothing that 60 s of warm-up does not.
- **A heap profile attribution is not needed,** because P1 passes. The profiles are committed:
  `heap-p1-baseline.pb.gz`, `heap-p1-before-restart.pb.gz`, `heap-p2-before-content_change.pb.gz` and
  `heap-p3-recovery.pb.gz`.

## 5. Builds

The sources are the same as in PRO-540. The lab was rebuilt in a fresh container:

| What | Value |
|---|---|
| Culvert | `ef9431189490f7f85bb32d6fe7e7b6b8be5b0844` with `culvert-lab-ef94311.patch` (this tree) and `culvert-lab-ef94311-childapp.patch` (branch `claude/culvert-PRO-516-childapp-load`), `git am`; local head `61ac3b3d6` (same patches as `0b94ef6a`, new commit times) |
| Hook | `tools/endurance/culverthook/` copied in, as in PRO-540 |
| Detector | `9944158d65e8ffe444437adfe6f70ef88f0c0419`; `culvert-lab-v8` with `go/internal/content/pack.json` from `253a91d` (2026.11.8), `culvert-lab-v9` as committed (2026.11.9) |
| Toolchain | go1.27.4, a `go.work` per binary naming the clone and the detector worktree |
| Binaries | `culvert-lab-v8` sha256 `faa38bb5…b1c08a19`, `culvert-lab-v9` sha256 `12ec04af…44713bf`, `endurance-load` sha256 `3f0bb4f3…9b6a326`. They differ from PRO-540's hashes because the paths and the VCS stamps differ. |
| Host | 4 vCPUs; proxy on CPUs 0–1, driver on 2, origin on 3; `ip_local_port_range 1024 65535`, `tcp_tw_reuse 1` |

**Reproduce:** as in `ENDURANCE.md`, then:

```
python3 lab/culvert/tools/endurance/run.py --manifest lab/culvert/results-endurance-rerun/manifest.json --out <dir>
python3 lab/culvert/tools/endurance/run.py --verdict <dir>
```

## 6. What this run does not show

The limits in `ENDURANCE.md`, section 5, all still apply. Also:

- **One run.** P1 passes with a margin of 3.5 points on the heap (−6.5% against ±10%), measured against the
  median baseline.
- **The warm-up is 60 s of load at the steady rate.** A deployment that ramps up more slowly fills the request-log
  ring later, so its live heap reaches the same plateau later.
