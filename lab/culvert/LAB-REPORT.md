# Culvert lab report, first draft (PRO-589, 2026-11-27)

This is the first draft of the lab report that section 12 of `docs/integration/PROTODETECT-CULVERT-WORKING-PLAN.md`
requires before anything is proposed to KidCarmi/Culvert. It consolidates evidence that already exists. No lab run
was made for it. Local evidence only: loopback, RFC 5737 origin addresses, synthetic traffic. Nothing was pushed
to, or proposed for, KidCarmi/Culvert. Publishing or merging is a separate decision.

**Scope: visibility only (decision 3, 2026-11-17).** The detector observes and logs. Nothing in this report is a
claim about enforcement, blocking or a security control. The restriction demonstration on the first lab
(`52eb9d1`, section 5.3) is history kept for the record, outside the current scope (L7).

**How sources are cited.**
- Merged work: the file and the commit on `main` that last changed it (`main` is `cc1566d` when this was written).
- Unmerged work: the pull request and its full head SHA, read with `git show <sha>:<path>`:

| PR | Task | Head SHA | What it holds |
|---|---|---|---|
| #173 | PRO-516 | `cab35afb6849758dd768ee6dcdd96bd90fec9c5a` | child-app load test, `docs/integration/CHILDAPP-LOAD.md`, `lab/culvert/results-childapp-load/` |
| #179 | PRO-540 | `e5519f0f168c0d3bd4662e8536008ee4dc2dd598` | L6 endurance run, `lab/culvert/ENDURANCE.md`, `lab/culvert/results-endurance/` |
| #184 | PRO-564 | `62b407fbabf0d6c8ca6f46a2c2db76e10632f7be` | L6 re-run with revision 1, `lab/culvert/ENDURANCE-RERUN.md`, `lab/culvert/results-endurance-rerun/` |
| #186 | PRO-578 | `b54c137e4b3b297e852332fbd9f086a171bd7a02` | drift check on Culvert `a0aecf8`, `lab/culvert/DRIFT-a0aecf8.md`, `lab/culvert/results-a0aecf8/` |

Evidence in an unmerged pull request can still change in review. Each row below that depends on one says so.

## 1. Phase status, L0 to L6

The exit evidence is that of section 7 of the working plan. **Done 2, partial 4, missing 1.**

| Phase | Status | Evidence | Gap, stated plainly |
|---|---|---|---|
| L0: unmodified Culvert, topology, synthetic origins | **partial** | Build A is unmodified Culvert at `52eb9d1`, `ef94311` and `a0aecf8` (sections 2 and 4). The 15 smoke scenarios repeat: 74 of 74 on 2026-11-21, again on 2026-11-22, and on `a0aecf8` (#186). SSRF proof through the real resolver and dial: 403 for `127.0.0.1`, `10.0.0.1`, `198.18.0.1` and `169.254.169.254` on every build, while the RFC 5737 origins are reached with every protection on. CONNECT to ports 22, 25, 5432 and 9000 is relayed by build A, so this configuration restricts no CONNECT destination port. Baseline latency, CPU and RSS of A: `docs/integration/LOAD-TEST.md` (`def6d2b`). | No L0 manifest as section 6.3 defines it (binary hash, config hash and runner version are not recorded). Proxy authentication success and failure, and TLS verification of the origin, are not scenarios of the visibility matrix: the visibility run creates no admin account. The port observation comes from the scenario set, not a dedicated check. |
| L1: adapter and fake engine, off by default | **done** | A/B equivalence: every one of the 15 scenarios gives the same traffic verdict on A and B, and the 7 hashed scenarios deliver the same bytes (`results-ef94311/results.json`, `d10a2b4`). Off: "observation off: no detector records" on A and B. Lifecycle, panic and error: build E (a fake engine that panics on every call) delivers every byte; the lab tests (`TestLab…`, 11 on `a0aecf8`) pass under `-race`. | The equivalence covers 15 scenarios, not the whole 8.1 matrix (auth and TLS-verification rows, short writes). |
| L2: facts only on inspect paths | **partial** | The child-app lab (PRO-504, `docs/integration/CHILDAPP-LAB.md`, `35f1e25`) reads only what Culvert has already parsed (decrypted H1 requests and H2 streams), adds no socket read, changes no policy, and logs a redacted `pd` block with closed vocabularies (no host, path or header value). Off adds 0 allocations and no entry. Load figures: #173 (`cab35af`). | The results carry no `culvert_facts` provenance, and they are the `AppClassifier`'s, not typed TLS/HTTP connection facts with the client and origin legs kept apart. The alpnpeek-versus-detector TLS comparison (5.3) has not been run. Redaction tests cover the `pd.apps` block only. |
| L3: raw tap on CONNECT bypass, fake engine | **partial** | Byte transparency (1 MiB and 32 MiB echoes, pipelined CONNECT, half-close, same hash on all builds), server-first (SSH, SMTP), fragmentation (1-byte writes), quiet-read expiry (silent tunnel past the 3 s window), release (300 short tunnels, then 0 flows held; SEC-CULV-1 releases at window end or handoff). Blocked-write expiry: 878 tunnels with a direction blocked in `Write` for 20 s in the endurance re-run (#184, `62b407f`). Splice restoration: 256 splice calls on A and 217 on D during a 32 MiB echo (`results/splice-trace-A.txt`, `-D.txt`, `7dc52c8`). | The splice count was taken on the first lab (`52eb9d1`) only, not on `ef94311` or `a0aecf8`. Short writes have no scripted-Conn test (Codex advisory point 3). Idle-timeout parity with the unmodified relay is known to differ (point 4), untested. No L3 manifest sets the bound on fix attempts. |
| L4: real detector behind the 4.4 gate | **done** | Expected classifications and typed outcomes on D: TLS with SNI and SSH both ways, SMTP and HTTP identified, PostgreSQL `outside_profile`, unrecognised bytes `unknown`, 1-byte writes `budget_exhausted`, silent tunnel `incomplete`/`expired`. Detector `0aa53ac` (on `main`), content pinned (2026.11.8 / 2026.11.9 in L6). Resource gates: `LOAD-TEST.md` and `LOAD-TEST-SPLIT.md` (`def6d2b`), the 1,000-tunnel hold (`results-load-hold/`), P4 of the endurance re-run (#184): 0 active, reserved and retained bytes after load. The post-quantum ServerHello (#4) is in Go on `main` (`b1379a4`, `TestPostQuantumServerHello`). | Section 8.4 counts (false positives and negatives per profile) are not computed: the expectations come from the scenario contracts, over a small synthetic corpus. That is not a false-positive rate. |
| L5: inspect fallbacks, SOCKS5, H1/H2 facts, WebSocket | **missing** | Only the decrypted-request path of inspected tunnels was exercised (L2 row). | No observation on inspect fallbacks, SOCKS5 or WebSocket; no per-path matrix; TLS-ordering asymmetry not checked; SOCKS observation consent not defined. Plan section 3: SOCKS5 is CONNECT only (`socks5.go`). |
| L6: endurance, churn, silent peers, adverse input, recovery, packaging | **partial** | PRO-540 (#179, `e5519f0`): one 30-minute run, P2 to P5 pass, P1 fails as defined, with its cause (baseline timing, Culvert's request-log ring and the lazy classifier, not the detector). PRO-564 (#184, `62b407f`): the same schedule with revision 1 recorded before the run (`4fe99b7`); **P1 to P5 pass**, 225,389 flows passed, the 4,103 failures all fall in the two restart intervals. Adverse inputs from the fuzz corpora, one restart and one content-pack change. Packaging: `run-local.sh` builds end to end (48 s). This report is the L6 lab report. | One passing run after a revision, not "repeatable results": a second run with revision 1 has not been made. Both runs are unmerged. The `run-local.sh` run step was not tested on macOS. |

## 2. Environment and topology

| Item | Value | Source |
|---|---|---|
| Host | one cloud container, Linux 6.18.44, 4 vCPU Intel Xeon at 2.10 GHz, 16 GiB | `LOAD-TEST.md`, `LOAD-TEST-SPLIT.md` (`def6d2b`) |
| CPU placement (load runs) | proxy on CPUs 0 and 1, vegeta on 2, origin on 3 | `results-load-split/settings.json` (`def6d2b`) |
| Go | go1.27.4 linux/amd64, Culvert's `go.mod` `toolchain go1.27.4` | `LOAD-TEST.md`; `DRIFT-a0aecf8.md` (#186) |
| Frontend (first lab only) | Node 24.19.0, npm 11.17.0 | `README.md` |
| Detector | this repository's `go/`, joined through `go.work` (`go.work.example`); Culvert's `go.mod` and `go.sum` untouched | `README.md` |
| Network | loopback only; origins on `203.0.113.10` (`origin.lab.test`) and `203.0.113.20` (`secure.lab.test`, `monitor.lab.test`) through `/etc/hosts`; every Culvert protection on | `tools/start-lab-visibility.sh`, `tools/addaddr.py` |
| Origins | `tools/origins.py`: HTTP 80, TLS 443 (ALPN `http/1.1`), SSH 22, SMTP 25, echo 9000, silent 9001, PostgreSQL 5432; a recording origin on `203.0.113.20` | `tools/origins.py` |
| Proxies | one Culvert process per build, fresh data directory each run, ports below | `tools/start-lab-visibility.sh` |
| Culvert clone | read-only, push URL disabled (`git remote set-url --push origin DISABLED`) | `README.md`, `DRIFT-a0aecf8.md` (#186) |

The plan's two-VM topology was not built: everything ran in one container (`README.md`, "What this does not
show"). A standalone host cannot certify cluster propagation.

## 3. Manifests for A, B, C and D

Section 6.3 asks, per campaign, for commits and patch hashes, dirty-tree status, content digest, Go compiler,
binary hash, config hash, OS and kernel, CPU and RAM, and runner version. What exists:

| Build | What it is | Port | Engine (environment) | Culvert source |
|---|---|---|---|---|
| A | unmodified Culvert | 18080 | none | the base commit, `GOWORK=off go build` |
| B | lab build, detector off | 18081 | off (default) | base + lab patch |
| C | lab build, fake engine | 18082 | `CULVERT_LAB_PROTODETECT=fake`, `CULVERT_LAB_PD_WINDOW_MS=3000` | base + lab patch |
| D | lab build, real detector, observe | 18083 | `CULVERT_LAB_PROTODETECT=real`, `CULVERT_LAB_PD_WINDOW_MS=3000` | base + lab patch + `go.work` |
| E (extra) | fake engine that panics on every call | 18084 | `…=fake`, `CULVERT_LAB_PD_FAKE_PANIC=observe` | base + lab patch |

| Campaign | Culvert base | Lab branch head (local) | Patch, SHA-256 | Detector | Content |
|---|---|---|---|---|---|
| First lab, 2026-11-17 (with restriction, history) | `52eb9d1e4482adc9773afc4db77109acad617625` | `lab/protocol-detector` | `culvert-lab-52eb9d1.patch` `63db24b6…0add` | `2faa7cb` | the #16 pinned pack |
| Visibility, 2026-11-21/22 | `ef9431189490f7f85bb32d6fe7e7b6b8be5b0844` | `lab/protocol-detector-ef94311` `8f828789` | `culvert-lab-ef94311.patch` `e1a90fa3…c58f` | `0aa53ac` | embedded pack of that commit |
| Child apps, PRO-504/516 | `ef94311` | `lab/childapp-ef94311` `88d2c0a4` | + `culvert-lab-ef94311-childapp.patch` | engine PR #163 (merged as `d1de60f`) | child release 2026.11.1 |
| Endurance, PRO-540/564 | `ef94311` | both patches | both patches | `9944158` (PR #173 branch) | 2026.11.8 (`804f727352bc61e0`), then 2026.11.9 (`cdaa5993077d101a`) |
| Drift, PRO-578 | `a0aecf8e1dbe6fbc2b385896c045759a6f4ce30b` | `lab/protocol-detector-a0aecf8` `3d3769b442c6448582b6837a7411a83f45ab071f` | `culvert-lab-a0aecf8.patch` (#186) | `main` `cc1566d` | embedded pack of `cc1566d` |

Full patch hashes (`sha256sum lab/culvert/*.patch` at this commit):

```
63db24b6668c051bf8f45711f2fa5e2e8a7ad85d4feaab30e496f0f95d260add  culvert-lab-52eb9d1.patch
e1a90fa3e6ee1eefe5c0ef70166d2d7cae96a2f84ac358e4e77f92248bbbc58f  culvert-lab-ef94311.patch
6b8cbd776d30cad3f42cb38212d89b0621c2724feeb4e54b06dd962720f013fa  culvert-lab-ef94311-childapp.patch
eb5f45a2bf74b40edd0fa467eac4f3890b2a0b8db349bca6092666f28db1c9a8  culvert-lab-a0aecf8.patch (#186, b54c137)
```

Content digests are those of `go/internal/content/lock.json` on `main`. The endurance manifest written before the
run is `results-endurance/manifest.json` (#179) with the revision block in `results-endurance-rerun/manifest.json`
(#184, `4fe99b7`).

**Gaps:** no binary hash, config hash, dirty-tree status or runner version was recorded for any campaign, and the
lab branch heads are local commits of a clone that no longer exists in this environment. Closing them needs a new
campaign that writes the full 6.3 manifest before it runs.

## 4. Git bundles and restore steps

**Status: missing.** No Git bundle of any lab branch exists. Section 6.3 asks for bundles stored off the VM and an
early restore test; neither was done. The patches in this directory are the backup in their place: they are
produced by `git format-patch`, they carry every lab commit, and they restore the lab branches exactly as far as
the changed files go (the first lab's patch leaves out `frontend/dist`, which `npm run build` regenerates).

Restore from the patches (from `README.md` and `DRIFT-a0aecf8.md`; the `a0aecf8` restore was exercised by
PRO-578):

```sh
git clone https://github.com/KidCarmi/Culvert.git culvert
git -C culvert remote set-url --push origin DISABLED
git -C culvert checkout -b lab/protocol-detector-ef94311 ef9431189490f7f85bb32d6fe7e7b6b8be5b0844
git -C culvert am lab/culvert/culvert-lab-ef94311.patch lab/culvert/culvert-lab-ef94311-childapp.patch
cp lab/culvert/go.work.example go.work   # then name the Culvert checkout and this repository's go/
```

To close the gap, a release owner would make `git bundle create lab-<base>.bundle <base>..lab/<branch>` for each
lab branch, store it off the machine, and record a restore with `git bundle verify` and a clean `git am` check.

## 5. Scenarios, seeds, expected results and commands

The 15 observation scenarios of the visibility run (`tools/runner.py`, results `results-ef94311/results.json`,
`d10a2b4`). The expected outcome comes from the scenario's contract, never from the detector's output.

| Group | Scenario | Seed / input | Expected (D) |
|---|---|---|---|
| Baseline access | Plain HTTP through the proxy | fixed request | traffic passes; no tunnel, no record |
| Protocols | CONNECT + TLS to the lab origin | Python `ssl` client, SNI `origin.lab.test` | TLS identified both ways, SNI recorded (pseudonymized in the log) |
| Protocols | CONNECT + SSH (server speaks first) | fixed banner | SSH identified both ways |
| Protocols | CONNECT + SMTP (server speaks first) | fixed dialogue | SMTP identified on the client side |
| Protocols | CONNECT + HTTP/1.1 inside the tunnel | fixed request | HTTP identified |
| Protocols | PostgreSQL | startup message | `outside_profile` `postgresql` |
| Protocols | Unrecognised bytes | fixed bytes | `unknown` |
| Byte transparency | 1 MiB echo | `random.Random(20261114)` | same hash on A to E |
| Byte transparency | Bytes pipelined with the CONNECT header | fixed request in the CONNECT write | same bytes; HTTP identified |
| Byte transparency | Half-close after sending | `random.Random(7)`, 200,000 bytes | same hash |
| Byte transparency | 32 MiB echo after the window | `random.Random(99)` | same hash (not run on E) |
| Fragmentation | HTTP request in 1-byte writes | 4 ms between writes | `budget_exhausted`, never left at `detecting` |
| Expiry | Silent tunnel past the 3 s window | no bytes | `incomplete` / `expired` |
| Security parity | SSRF guard | `127.0.0.1`, `10.0.0.1`, `198.18.0.1`, `169.254.169.254` | 403 on every build |
| Resource pressure | 300 short tunnels, 50 at a time | `random.Random(i)`, 2,000 bytes each | 300 records, 0 flows held afterwards |

Commands:

```sh
LAB_CULVERT_BASE=ef94311 lab/culvert/tools/start-lab-visibility.sh     # builds A to E, then runner.py and page.py
cd culvert && GOWORK=/path/to/go.work go test -race -run 'Tunnel|Idle|Relay|Bypass|CONNECT|Connect|Drain|TestLab' .
cd culvert && GOWORK=/path/to/go.work go test -race -run 'TestLab' . ./internal/pdobs ./internal/protodetect
```

Load and endurance scenarios are defined by their own manifests: `LOAD-TEST.md` (100/300/600/1,000 req/s, three
rounds), `LOAD-TEST-SPLIT.md` (200/500/1,000/s and a 1,000-tunnel hold), `CHILDAPP-LOAD.md` (#173: 200, 1,000 and
3,000 req/s, 60 s, three repetitions, a five-request mix) and `results-endurance/manifest.json` (#179: 127.5 new
tunnels/s for 1,800 s, restart at 600 s, content change at 1,200 s, thresholds ±10% within 60 s and 1.0%/min).
Each is run by the `run.py` or `loadtest.py` in its tools directory. The scripts assume `/home/user/culvert-lab`.

## 6. Pass/fail results with reproductions

| Campaign | Result | Reproduce | Source |
|---|---|---|---|
| Visibility on `ef94311` | 74 of 74 (15 scenarios × A to E, 32 MiB not on E); every cell matches the `52eb9d1` run | section 5, first command | `README.md`, `results-ef94311/` (`d10a2b4`) |
| Rerun after SEC-CULV-1/2 | 74 of 74, no cell different | same | `README.md` |
| Culvert tests on the lab branch | 193 passed under `-race`; 198 with `TestLab` | section 5, second command | `README.md` |
| Drift on `a0aecf8` | 33 of 33 hunks clean; root package 209 passed under `-race` (198 + 11 `TestLab`); `TestLab` ×10 clean; 74 of 74, 0 cells different | `DRIFT-a0aecf8.md` section 2 | #186, `b54c137` |
| Child apps (PRO-504) | lab tests pass, 20 runs under `-race` clean; on: 23 allocations, about 2.7 µs per child-matched request | `README.md`, child-app block | `CHILDAPP-LAB.md` (`35f1e25`) |
| Child-app load (PRO-516) | +16.2 allocations and about +0.8 KB per request; latency, throughput and GC within noise; every request classified; 1 of 1,511,997 not 200 (origin EOF) | `tools/childappload/run.py` | #173, `cab35af` |
| Load test (PRO-269) | observe minus off: p50 +5 to +113 µs, p95 +84 to +424 µs; +0.15 to +0.22 CPU-s per 1,000 flows; throughput unchanged to 600 req/s; 1,000 req/s saturates the harness | `tools/loadtest.py` | `LOAD-TEST.md` (`def6d2b`) |
| Load split and hold | no measurable latency at 200 and 500/s; +105 to +277 ms CPU per 1,000 HTTPS flows; +3.9 KiB per held tunnel after the window | `tools/loadsplit/` | `LOAD-TEST-SPLIT.md` (`def6d2b`) |
| Endurance (PRO-540) | P1 **fail** as defined (cause found, not the detector); P2 to P5 pass | `tools/endurance/run.py` | #179, `e5519f0` |
| Endurance re-run (PRO-564) | **P1 to P5 pass** | same, with the revision block | #184, `62b407f` |
| First lab (history) | 84 of 84 on 2026-11-17, including the restriction cells | `tools/start-lab.sh`, `run-live.sh` | `results/` (`ced7e1e`) |

## 7. Raw measurements

| Data | Where |
|---|---|
| Visibility matrix | `lab/culvert/results-ef94311/results.json`, `index.html` |
| First lab matrix, Observatory page, splice traces | `lab/culvert/results/` |
| Load test | `lab/culvert/results-loadtest/` (`results.json`, `results-600.json`, `summary.md`) |
| Load split and hold | `lab/culvert/results-load/`, `results-load-split/`, `results-load-hold/hold.json` |
| Child-app benchmark | `lab/culvert/results-childapp/bench.txt` |
| Child-app load | `lab/culvert/results-childapp-load/` (#173) |
| Endurance | `lab/culvert/results-endurance/` (#179, #184): samples, phases, verdict, heap profiles `heap-*.pb.gz`, goroutine dumps |
| Endurance re-run | `lab/culvert/results-endurance-rerun/` (#184) |
| Drift | `lab/culvert/results-a0aecf8/` (`results.json`, `tests.txt`) (#186) |
| Screenshots (first lab) | `lab/culvert/shots/` |

## 8. Classifications by profile, path and provenance

All classifications below are raw-parser results of the detector (provenance: engine), on the CONNECT-bypass
path, except the child-app row. No facts-only (`culvert_facts`) results exist yet.

| Profile (decision 4) | Visibility matrix, D | Endurance re-run, records (#184) |
|---|---|---|
| TLS | identified both ways, SNI recorded | 109,671 identified, both directions |
| HTTP/1 | identified (whole and pipelined); 1-byte writes `budget_exhausted` | 46,113 identified, client side |
| SSH | identified both ways | 37,389 identified, client side |
| SMTP | identified on the client side; the server side `unknown` | not in the mix |
| Other families (named only) | PostgreSQL `outside_profile` | 9,133 `outside_profile` (smb2 2,073 the most) |
| Adverse and unrecognised | `unknown`; silent `incomplete`/`expired` | `budget_exhausted` 1,746, `malformed` 832, `unknown` 1,248, `incomplete` 8,645; 415 `host_mismatch` signals |

| Path | Covered | Provenance |
|---|---|---|
| CONNECT bypass (raw tap) | yes, L3/L4 | engine |
| Inspected tunnel, decrypted H1/H2 requests | child-app verdicts only (PRO-504/516) | `AppClassifier` over Culvert's parsed requests |
| Inspect fallbacks, SOCKS5, WebSocket, plain HTTP | no (L5 missing) | — |

The SMTP server side is `unknown` in the visibility matrix, the same on every run; its cause has not been traced
for this report. It is a recorded result, not a pass condition.

## 9. Known limits

- **Visibility only.** No enforcement, no blocking, no policy effect. Nothing here qualifies a control.
- **First message only.** After the observation window the rest of the tunnel is not inspected. SNI and ALPN
  are client assertions; TLS ClientHello metadata is an offer, not authenticated identity.
- **One container, synthetic traffic.** Not two VMs, not production traffic, no cluster propagation. The
  latency figures are loopback CPU work, not Culvert's end-to-end SWG latency.
- **A small corpus.** No false-positive rate can be read from it (8.4).
- **Untested paths:** short writes with a scripted Conn, idle-timeout parity with the unmodified relay (known to
  differ), holding under a slow client beyond the window, splice on `ef94311` and `a0aecf8`.
- **Child apps cost more than ADR-0011's one allocation per session** (23 per child-matched request); the ADR
  draft needs a per-request row.
- **Not reviewed.** The Culvert lab change has had no Codex round, by decision (plan 6.4).
- **Four sources are unmerged** (#173, #179, #184, #186).

## 10. Recommendation

1. **Keep the lab where it is; propose nothing upstream yet.** The CONNECT-bypass observation is transparent
   (byte-identical on every build), bounded (0 held flows, 0 retained bytes after load, P1 to P5 on the re-run)
   and cheap at the measured rates. The evidence supports a visibility-only proposal *later*, once the checklist
   below is closed.
2. **Close the lab gaps in this order**, as separate tasks: a full 6.3 manifest and Git bundles with a restore
   test (L0, sections 3 and 4); a second endurance run with revision 1 (L6 repeatability); splice on the current
   base and a scripted short-write test (L3); the facts-only provenance and the alpnpeek comparison (L2). L5 is a
   scope decision for Lee: either a declared scope with SOCKS5 consent defined, or written out of the first
   proposal.
3. **Merge the evidence first.** #173, #179, #184 and #186 are Lee's merge decisions; once merged, this report's
   citations should be moved to `main` SHAs.

## 11. Upstream proposal: blocked on section 12

The upstream proposal stays blocked until each item below is closed. This lane cannot close any item marked
"Lee". Status as of `main` `cc1566d`.

| Item (section 12) | Status | Owner |
|---|---|---|
| [ ] Licence and contribution terms | The detector is Apache-2.0 (`74638c4`); Culvert is MIT. Whether Culvert accepts an Apache-2.0 module is open (ADR draft, decision 1) | Lee, with the Culvert maintainers |
| [ ] Culvert ADR | draft exists (`docs/integration/adr/ADR-DRAFT-protodetect-in-process.md`, `cb39f2b`); not proposed; needs the per-request row for child apps | Culvert Integration (draft); Lee (proposal) |
| [ ] Signed `go/v0.x.y` tags | procedure in force (`docs/governance/RELEASE-TAGS.md`); `allowed_signers` empty; no tag | Lee (release owner) |
| [x] govulncheck | in CI (`.github/workflows/ci.yml`) | Platform & CI |
| [ ] SBOM and provenance | SBOM steps in `ci.yml` and `publish-release.yml`; no release has been published, so no provenance exists yet | Platform & CI; Lee (release) |
| [x] Standard-library-only test | `TestDetectorImportsStandardLibraryOnly` (`2c89a66`) | Engine |
| [ ] Signed content with anti-rollback before any dynamic update | digests and the C11 rollback check exist; no content signature | Engine; Lee (keys) |
| [x] CODEOWNERS | `.github/CODEOWNERS` | — |
| [x] Semver and deprecation policy | `docs/governance/VERSIONING.md` | — |
| [ ] Compatibility matrix (Culvert × detector × content) | defined in `VERSIONING.md`; no row, because no release exists | Lee (release owner) |
| [ ] Coordinated security disclosure | `SECURITY.md` exists; not agreed with the Culvert maintainers | Lee |
| [ ] Release owner | Lee until another is named; no signing key added | Lee |
| [ ] Culvert `AGENTS.md` route for `internal/protodetect` | not written | Culvert Integration (draft); Lee (proposal) |
| [ ] Runtime kill switch (`ClusterSynced`, `AdminDurable`, no restart), node-group canary, written abort criteria | designed in the ADR draft, section 8; not implemented in the lab (the lab uses environment variables) | Culvert Integration (lab); Lee (proposal) |
| [ ] Lab report deliverables | this draft; gaps in sections 1, 3 and 4 | Culvert Integration |
| [ ] Repository settings (rulesets, tag protection) | noted in `docs/governance/README.md`; none set | Lee |
