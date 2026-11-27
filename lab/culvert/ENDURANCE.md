# Culvert lab endurance run (PRO-540, working plan phase L6)

One endurance run of the Culvert lab: CONNECT bypass observed by the real detector, child-app classification on,
30 minutes of mixed load with quiet peers, a direction blocked in `Write`, adverse inputs, one restart and one
content-pack version change. Local lab only: loopback, RFC 5737 origin addresses, synthetic traffic. The Culvert
clone is read-only (push URL disabled); nothing was pushed to, or proposed for, KidCarmi/Culvert.

**Verdict: P1 (recovery) fails as defined; P2 to P5 pass.** The run is in `results-endurance/` and the
verdict in `results-endurance/verdict.json` (`run.py --verdict`).

| # | Condition | Result | Evidence |
|---|---|---|---|
| P1 | Goroutines and live heap within ±10% of the baseline ≤ 60 s after load | **FAIL** | goroutines 25 vs 29 (−13.8%) from 5 s on; live heap 10.30 MB vs 6.51 MB (+58.2%), flat from 5 s to 180 s |
| P2 | No unbounded growth slope in the steady phase | pass | largest \|slope\| 0.55%/min (p2 goroutines); heap ≤ 0.18%/min, RSS ≤ 0.19%/min, fds ≤ 0.26%/min |
| P3 | No panic | pass | engine panics 0 in all three processes; no "panic" log line; every exit code 0 |
| P4 | No leaked reservation | pass | after load: `Active` 0, `ReservedBytes` 0, `RetainedBytes` 0; 0 refused admissions in 207,579 |
| P5 | Flows after the restart and the content change use the intended version | pass | every pd block: p1 and p2 `content=2026.11.8`, p3 `content=2026.11.9` (child release 2026.11.1 throughout), none mixed |

**Finding (P1), with its cause.** Neither half of the P1 failure comes from the detector:

1. **The live heap that stays is Culvert's bounded state, not growth.** Its size does not depend on how long the
   load ran: 2 minutes of the same mix leave 10.27 MB (diagnostic D3), 30 minutes leave 10.30 MB. Split, by
   diagnostics on the same binary (section 4):
   - **2.94 MB is Culvert's traffic logging.** With `logTraffic` off on both rules (D2) the heap returns to
     +0.87 MB instead of +3.80 MB. The heap profile puts it in `internal/reqlog.Add` (the in-memory request-log
     ring, `reqlog.MaxRing` = 5,000 entries, full after about 40 s at this rate) and `DecryptionOutcome.toBlock`
     (the entries' decryption blocks).
   - **0.58 MB is the child-app classifier,** built on the first inspected request (`labAppsCls`, a `sync.Once`),
     so after the baseline. `detector.NewAppClassifier` alone retains 575,952 bytes (measured twice in a
     standalone program on the same tree).
   - **About 0.29 MB is not attributed.** That is below the 512 KiB sampling rate of the heap profile. Culvert's
     per-host caches are the likely holders: the minted leaf certificates, top hosts and the hash cache.
   - **The detector engine holds nothing after load:** 0 active flows, 0 reserved and 0 retained bytes.
2. **The goroutine shortfall comes from when the baseline was taken.** With no load at all (D1), Culvert drops
   from 29 to 25 goroutines about 85 s after it starts. The goroutine dumps show two `net/http` client keep-alive
   connections (`persistConn` read and write loops) closing when idle. The baseline was sampled 60 to 70 s after
   start, before they closed. After the load, Culvert sits at 25: its idle steady state.

The thresholds stay as written. A re-run would need a documented revision before it starts (working plan 8.3).
Two candidates: sample the baseline at least 120 s after start, and after a warm-up that fills the bounded rings
and builds the lazy classifier. Or run with `logTraffic` off and measure the ring separately. Neither revision is
applied here.

**Other results:**

- **Driver.** 225,228 flows passed their traffic check (tls 105,987, http1 44,167, ssh 35,333, inspect 17,661,
  adverse 17,667, quiet 3,535, blocked 878).
  - 4,241 failed. All of them fall in the two 30 s intervals that hold a restart: about 16.5 s of refused dials
    per restart.
  - Culvert's graceful shutdown drains for its 15 s timeout, then force-closes the held bypass tunnels (5 at the
    restart). The new process is ready 1.74 s and 1.98 s after the old one exits.
  - The 6 `blocked` tunnels reported closed early are among those force-closed at shutdown.
  - No quiet or blocked tunnel was closed because observation expired.
- **Detector records.** 207,579 records in the three processes. Identified:
  - TLS 105,993 in both directions;
  - HTTP 44,569 on the client side;
  - SSH 36,135 on the client side.

  The adverse inputs gave `budget_exhausted` 1,687, `malformed` 804, `unknown` 1,206, `incomplete` and
  `outside_profile` (13 families named from the fuzz seeds). 133 to 136 records per process carry `host_mismatch`:
  one adverse seed asserts another host.
- **Steady state, per process (8 to 9 minutes each):**
  - goroutines 154 to 168;
  - live heap 10.8 to 11.8 MB;
  - RSS 62 to 68 MiB;
  - open fds 139 to 199;
  - detector `Active` 25 to 29 and `ReservedBytes` at most 950,272 (29 × 32 KiB);
  - `RetainedBytes` at most 72.
- **Baselines.** The idle reference processes of both binaries are equal within noise: 29 goroutines and a live
  heap of 6.45 to 6.60 MB each. So the content-pack change itself moves neither figure.

## 1. Manifest (written before the run)

The manifest is `results-endurance/manifest.json`; it was committed unchanged from the version the run read.
Thresholds were fixed before the run and are not revised after it (working plan 8.3).

| Item | Value |
|---|---|
| Load duration | 1,800 s of driven load, after a 60 s idle baseline |
| Sampling | every 30 s during load; every 5 s for the 60 s after load stops, then every 30 s up to 180 s |
| Observation window | 10 s (`CULVERT_LAB_PD_WINDOW_MS=10000`), real detector, families http, tls, ssh, smtp |
| Child apps | `CULVERT_LAB_CHILDAPP=real`, rule `*.googleapis.com` Allow + Inspect; every other tunnel Allow + Bypass |
| Pinning | proxy on CPUs 0–1, driver on 2, origin on 3 (`taskset`); `ip_local_port_range 1024 65535`, `tcp_tw_reuse 1` |
| Restart | at 600 s: SIGTERM, then the same binary again (`culvert-lab-v8`), cold in-memory state |
| Content change | at 1,200 s: SIGTERM, then `culvert-lab-v9` (content pack 2026.11.9 instead of 2026.11.8) |

**Mix** (new CONNECT tunnels per second, one flow per tunnel; 127.5/s in total, below the rig's ~1,000/s knee):

| Kind | Rate | What the flow does | Driver's "ok" |
|---|---|---|---|
| tls | 60 | TLS 1.2+/1.3 to `origin.lab.test:443`, GET, close | handshake verified against the lab CA, 200, exact body |
| http1 | 25 | HTTP/1.1 GET to `:80` inside the tunnel | 200, exact body |
| ssh | 20 | server-first SSH banner on `:2222`, client banner back | exact banner |
| inspect | 10 | TLS to `www.`/`gmail.googleapis.com` (inspected by Culvert, child-app path), GET | proxy CA verified, 200, exact body |
| adverse | 10 | one adverse case per tunnel to a discard port `:9003` (below) | CONNECT 200 and every byte written |
| quiet | 2 | silent tunnel to `:9002`, held 15 s (past the window) | the tunnel stays open for the whole hold |
| blocked | 0.5 | writes into `:9001`, whose origin never reads, until a write blocks; held 20 s | the write blocked and the tunnel stayed open |

**Adverse cases**, round-robin (44 cases): random bytes (64 B, 4 KiB, 20 KiB, seed 540); a real Go ClientHello cut
after 5 bytes, at half and one byte short; an oversized ClientHello (record claims 16 KiB, handshake claims 16 MiB,
20 KiB sent, past the 16 KiB budget); the same real ClientHello in 1-byte writes; and the first input of every
seed file of the committed fuzz corpora `go/detector/testdata/fuzz` and `go/internal/engine/testdata/fuzz`.

**Pass conditions and thresholds:**

| # | Condition | Measure | Threshold |
|---|---|---|---|
| P1 | Recovery | goroutines and live heap after a forced GC, vs the median of 3 baseline samples of process 1 | both within ±10% at some sample ≤ 60 s after load stops, and still within at the 60 s sample |
| P2 | No unbounded growth | least-squares slope of goroutines, live heap, RSS and open fds over each process's load samples, from 120 s after it was ready | \|slope\| ≤ 1.0% of the mean per minute, each metric, each process |
| P3 | No panic | the engine's panic counter in the last record of each process, and log lines with "panic" | 0 |
| P4 | No leaked reservation | the engine's `Active`, `ReservedBytes`, `RetainedBytes` after load | 0, 0, 0 |
| P5 | Versions | the `content_release`/`child_release` of every pd block in the latest feed entries of each process | exactly the release of that process's binary |

## 2. Builds and SHAs

| What | Value |
|---|---|
| Culvert base | `ef9431189490f7f85bb32d6fe7e7b6b8be5b0844` (`main`), clone read-only |
| Lab patches | `lab/culvert/culvert-lab-ef94311.patch` (main) and `culvert-lab-ef94311-childapp.patch` (branch `claude/culvert-PRO-516-childapp-load`), applied with `git am`; local head `0b94ef6a` |
| Lab-only hook | `tools/endurance/culverthook/` copied into the clone (not in any patch): `/lab/endurance` counters, heap and goroutine profiles, on loopback only |
| Detector, `culvert-lab-v9` | `9944158d65e8ffe444437adfe6f70ef88f0c0419` (head of `claude/culvert-PRO-516-childapp-load`, which carries the child-app package PRO-492/504; not on `main` yet), content pack 2026.11.9 |
| Detector, `culvert-lab-v8` | the same tree with `go/internal/content/pack.json` from `253a91d` (the published release 2026.11.8), uncommitted, lab only |
| Toolchain | go1.27.4 (`GOTOOLCHAIN=go1.27.4`), `go.work` naming the clone and the detector's `go/` |
| Binaries | `culvert-lab-v8` sha256 `81a2e0e0…3401829`, `culvert-lab-v9` sha256 `d9c703a7…180807c26f` |

## 3. Samples

`results-endurance/samples.json` holds one row per sample:
- phase and process;
- goroutines;
- heap (`heap_live` after a forced GC in the baseline and recovery samples, `heap_inuse`, `heap_alloc`);
- RSS and open fds;
- the lab observer's counters (`pd_stats`) and the engine's (`pd_engine_stats`: admitted, refused, refused by
  memory or flow limit, panics, active, reserved and retained bytes);
- the handoff counter;
- the releases in the pd blocks of the latest 1,000 feed entries.

The run writes JSON lines (`*.jsonl`). The repository ignores that extension, so the same rows are committed
as JSON arrays (`*.json`); `run.py --verdict` and `show.py` read either form.

The other files:
- `driver.json`: per-interval outcome counts per kind;
- `phases.json`: the event times and the per-process log scan, with outcomes and signals;
- the `heap-*.pb.gz` profiles;
- `culvert-p*-tail.log`: the last 200 non-record lines of each process.

`python3 tools/endurance/show.py results-endurance` prints the table.

| Time after load start | Process | Goroutines | Live heap | Open fds | RSS | Detector active |
|---|---|---|---|---|---|---|
| baseline (−20 s) | p1 | 29 | 6.51 MB | 15 | 46.0 MiB | 0 |
| 36 s to 586 s | p1 | 154–160 | 11.37–11.72 MB | 187–197 | 64.6–67.7 MiB | 25–26 |
| restart at 600 s | p2 | 134–168 | 10.90–11.75 MB | 143–199 | 62.0–66.9 MiB | 25–29 |
| content change at 1,200 s | p3 | 134–165 | 10.79–11.73 MB | 139–197 | 61.9–66.9 MiB | 25–28 |
| load stop + 5 s | p3 | 25 | 10.31 MB | 73 | 58.9 MiB | 0 |
| load stop + 60 s | p3 | 25 | 10.30 MB | 13 | 56.8 MiB | 0 |
| load stop + 180 s | p3 | 25 | 10.30 MB | 13 | 57.4 MiB | 0 |

## 4. Diagnostics after the run (not pass conditions)

`run.py --diag` on the same binary (`culvert-lab-v9`). The files are `diag-samples.json`, `diag.log`, the
goroutine dumps `diag-D1-goroutines-60s.txt` and `-end.txt`, and the driver counts `diag-D2-*` and `diag-D3-*`.

| Case | What | Baseline (median) | 60 s after load |
|---|---|---|---|
| D1 | no load; 15 s samples for 5 minutes after setup | 29 goroutines, 6.42 MB at 60 s | 25 goroutines from 90 s on; 6.40 MB |
| D2 | 120 s of the mix, both rules `logTraffic` off | 29, 6.46 MB | 25, 7.33 MB (+13.4%) |
| D3 | 120 s of the mix, `logTraffic` on (as in the run) | 29, 6.47 MB | 25, 10.27 MB (+58.8%) |

The difference D3 − D2 is 2.94 MB: the traffic logging. The child-app classifier's 575,952 bytes are part of D2.

## 5. What this run does not show

- **One host, one run.** No repetitions and no A-versus-D comparison: this is a retention check, not a cost
  measurement (that is `docs/integration/LOAD-TEST*.md` and PRO-516).
- **The content change is a restart onto another binary.** The pack is built into the binary, and the lab has no
  live reload. "Flows after the change use the new version" is shown on the child-app path, whose pd block names
  the content release. The bypass record names no content release, because the stream inspector reads no content
  data (`go/detector/doc.go`).
- **Culvert's state is in memory in this configuration:** admin, rules and inspection CA. Each start sets them
  up again, and the driver reloads the new inspection CA (6 inspected flows failed on the old CA during the
  switch).
- **A detector on `main` would differ.** The detector tree is the PRO-516 branch, because child apps are not on
  `main` yet. Its stream inspector is the same code as `main` `5cb35d2`. Under `go/`, the branch adds
  `go/internal/childapp`, `go/detector/apps.go` and its schema, and a `containers` match key in
  `go/internal/policy`, which the lab does not use.

## Reproduce

1. Clone Culvert, `git remote set-url --push origin DISABLED`, check out `ef94311`, `git am` both lab patches.
2. Copy `tools/endurance/culverthook/zz_endurance_lab.go` to the clone's root and
   `zz_endurance_lab_protodetect.go` to `internal/protodetect/zz_endurance_lab.go`.
3. Build `culvert-lab-v9` with a `go.work` naming the clone and a detector worktree at `9944158`; build
   `culvert-lab-v8` the same way from a second worktree with `git checkout 253a91d -- go/internal/content/pack.json`.
4. `GOWORK=off go build -o /home/user/culvert-lab/bin/endurance-load lab/culvert/tools/endurance/load/main.go`.
5. Loopback aliases `203.0.113.10` and `.20` (`tools/addaddr.py`), `/etc/hosts` mapping `origin.lab.test`,
   `gmail.googleapis.com` and `www.googleapis.com` to `203.0.113.10`, the two sysctls above.
6. `python3 lab/culvert/tools/endurance/run.py --manifest manifest.json --out <dir>`, then `--verdict <dir>`;
   `show.py <dir>` prints the samples as a table.

Self-tests: `endurance-load self-test`, `run.py --self-test`.
