# Culvert integration lane brief: read this first

The onboarding note for a fresh chat taking any task in the Culvert integration-preparation lane. **Update this
brief at the end of every task**, in the same push as the task: §2 (state), §5 (open items), §6 (frozen and
queued SHAs), and a §7 line for every new pitfall.

## 1. Purpose and scope

The lane prepares the Go detector for in-process use by the Culvert proxy (KidCarmi/Culvert), following
`docs/integration/PROTODETECT-CULVERT-WORKING-PLAN.md`.

- **Branch:** since the Go merge, one `claude/culvert-<PRO-n>-<slug>` per task, cut from `main`, one PR each.
  `claude/culvert-integration-prep` (head `d10a2b4`) is frozen history; PRO-233 lands it as
  `claude/culvert-land-main`. Fast-forward pushes only. Commits are authored as Lee, with the
  session trailers.
- **Scope, decided:**
  - visibility only (decision 3, 2026-11-17);
  - first profile TLS, HTTP/1, SSH and SMTP with evidence, every other family named only (decision 4,
    2026-11-18);
  - enforcement and restriction (L7) out of scope.
- **Owns:** the public package `go/detector` and the Go code it needs, `go/consumertest`, `lab/culvert/`,
  `docs/integration/` and `docs/governance/`.
- **Read-only here:**
  - Python reference, `.py` tests, generators and shared fixtures, unless Lee approves a case;
  - `.github/` and the CI tools: copies only, with Lee's word, of what the Platform & CI lane already landed.
- **Never:**
  - merge, rebase, force-push, tag, release or change settings;
  - post GitHub comments, which includes no review requests until Lee lifts that;
  - push anything to KidCarmi/Culvert, open PRs there or contact upstream.

  The Culvert clone's push URL is disabled.
- **Data:** synthetic and loopback only. The lab's origins are on RFC 5737 addresses.

## 2. Current state (2026-11-24, after PRO-269)

- **Landing on main (PRO-233):** `claude/culvert-land-main` = `d10a2b4` + a merge of `main` `f027a4d` + focused
  fixes. Kept: `go/detector`, `go/consumertest`, `docs/integration/`, `docs/governance/`, the lab, the licence
  files, and the engine plumbing the adapter needs (`parsing.Credit`, the read-only registries). Taken from main:
  CI, `migration/`, the content package (the #16 pin, `embedded.go`, left: main has its own `Embedded`),
  CODEOWNERS, PROTOCOLS.md and the Python reference. **Not landed:** work items #4 (post-quantum key shares), #5
  (unknown TLS registry values), #6 (Content-Length overflow) and the #7 fixtures, because they edit the frozen
  Python reference and the parity fixtures. `TestPostQuantumServerHelloGap` pins the consequence: a default Go
  TLS server's reply is `unknown` again.

- **Load test (PRO-269, 2026-11-24):** `docs/integration/LOAD-TEST.md`. vegeta v12.12.0 runs through builds A,
  B, C and D of the `ef94311` lab at 200, 500 and 1,000/s, one tunnel per request. Observe mode adds:
  - HTTPS latency below the rig's resolution at 200 and 500/s (p50 ≤ +0.11 ms, p99 within noise);
  - +105 to +277 ms of proxy CPU per 1,000 flows (15 to 26%), about half the lab observation path (fake engine
    C) and half the engine;
  - +2.5 to +3 GC cycles per 1,000 flows;
  - +3.9 KiB per tunnel retained after the window (1,000 held tunnels).

  1,000/s is the rig's knee on 4 vCPUs (disturbed rounds on every build). Tools are in `lab/culvert/tools/`
  (`loadtest.py`, `loadhold.py`, `loadtest_report.py`, `loadorigin/`), data in `lab/culvert/results-load*/`.
- **Plan:** every approved detector-side item is done (4.1 to 4.3, and #10 completed). The governance policies
  are in force; no tag and no setting exists.
- **Lab:**
  - **Current:** visibility only, on Culvert `main` `ef94311`. Local branch `lab/protocol-detector-ef94311`, head
    `8f828789` (SEC-CULV-1/2 fixed, PRO-180). 74 of 74 observation checks pass; Culvert's tunnel, relay and drain
    tests and the lab tests pass, 198 under `-race`.
  - **First lab:** on `52eb9d1`, branch `lab/protocol-detector`, with the restriction demonstration. Kept
    unchanged: 84 of 84 checks on 2026-11-17.
- **Culvert team request** (`docs/integration/CULVERT-TEAM-REQUEST.md`): anchors refreshed at `ef94311`. It
  covers the SNI finding, UDP/HTTP3 and the allocation gap. It is not sent; Lee decides.
- **Allocations per flow, two figures** (`docs/integration/ENGINE-DRIFT-2026-11-21.md`):
  - engine core on the benchgate workloads at `0081f6f`: tls_whole 33, tls_fragmented 37, http_small 26,
    http_fragmented 38, ssh_banner_kexinit 34, unknown 10 (Research Lab, PRO-82). Inside the plan's 64.
  - a whole flow through `go/detector`: TLS 89, HTTP 76, SSH 53, unknown 11 (PRO-148). It was 191, 128, 89 and 15 at
    `3efda92`, before the package stopped copying closed-vocabulary and engine-composed strings. The gate
    ceilings are now 110, 95, 65 and 15.

  Culvert's whole HTTP forward is 82. Waiting on Culvert's budget before tuning.
- **Engine drift** (PRO-91): a trial merge with `claude/go-migration` `0081f6f` has 23 conflicting files, and 5 Go
  packages fail. `go/consumertest` does not build, because the engine's `go.mod` now says `go 1.27.4` and requires
  `golang.org/x/crypto`. The lab still passes 74 of 74 against the merged tree. See the report.

## 3. Where things live

1. `AGENTS.md`, then the working plan (sections 4.3a, 13 and the review queue under 4.3a).
2. `migration/STATUS.md`, section "Culvert integration preparation": every item with SHAs and evidence.
3. `go/detector/doc.go`: the package contract (containment, memory, results). `go/CHANGES.md`: unreleased changes.
4. `docs/governance/`: versioning, signed tags, the settings note (single-owner trap).
5. `lab/culvert/README.md`, plus the patches `culvert-lab-52eb9d1.patch` and `culvert-lab-ef94311.patch`.
6. `lab/culvert/tools/`: `start-lab-visibility.sh` and `runner.py`. Results are in `results/` (52eb9d1) and
   `results-ef94311/`.

## 4. How to verify

From the repository root, before every push: `make check`, then `make go-check`, then `make go-check-minimum`.
At `0aa53ac` they gave 833 tests OK, parity 6725 of 6725 and Go parity 6651 of 6651 with 74 listed gaps.

The lab, on this container:
1. In `/home/user/kidcarmi/culvert` on branch `lab/protocol-detector-ef94311`, build
   `GOWORK=/home/user/culvert-lab/go.work go build -o /home/user/culvert-lab/bin/culvert-lab .`.
2. Build A from an unmodified worktree at the base: `GOWORK=off go build -o .../bin/culvert-A .`.
3. Run `LAB_CULVERT_BASE=ef94311 sh tools/start-lab-visibility.sh` from `/home/user/culvert-lab`.

Culvert's allocation gates need `-tags benchgate`.

## 5. Open items

- **Decided (Hermes, PRO-235, 2026-11-22): #4 to #6 are re-landed in Go only, by Engine.** The work goes on a new
  branch from main, with no Python edit and no regenerated fixtures. Each intended difference from the Python
  reference gets a justified entry in `migration/parity/deltas.json`, reviewed by Codex. This follows Lee's rule of
  2026-11-22: after #40 the Python reference is frozen, and new behaviour goes to Go. A difference that changes
  existing Python behaviour, or any Python edit, needs Lee's explicit approval first. Not this lane's work. When
  #4 lands, `TestPostQuantumServerHelloGap` is replaced by the positive test (commit `a51f459`). The old commits
  are ancestors of main once PRO-233 merges, so this is new work, not a cherry-pick.
- **Memory accounting of main's new parser state:** `RetainedBytes` of `tlsx` counts the hello accumulators only.
  The facade never enables certificates or continuation, so their buffers are not reached today; enabling either
  needs that accounting first.

- **Answered for Engine (PRO-107, 2026-11-22), from Culvert `ef94311`, read-only:**
  - **#19 means (a), compiled code, not (b), the module list.** Culvert already requires `golang.org/x/crypto
    v0.59.0` and `golang.org/x/sys v0.50.0` (`go.mod:59`, `:61`), the engine's exact versions, so they add nothing
    to Culvert's graph. Culvert's dependency gate is a licence gate (`pr-deep-gate.yml:426-447`,
    `go-licenses --disallowed_types=forbidden,restricted`), not a "no modules" rule. On the trial merge,
    `go list -deps ./detector` shows no non-standard package; only `internal/decrypt` imports `x/crypto`.
  - **"Standard library only" is our own rule** (ADR 0002 line 39). Since PRO-151 it is checked as rule (a):
    `TestDetectorImportsStandardLibraryOnly` (it replaced `TestModuleIsStandardLibraryOnly`, which read the
    `require` lines of `go.mod`). The test runs `go list -deps` on `go/detector` for linux/amd64, linux/arm64,
    darwin/arm64 and windows/amd64, and fails on any package outside the standard library and this module. A planted
    import of `internal/decrypt` failed it on every platform, naming the `golang.org/x/crypto` packages. If the
    engine's requirement ever exceeds Culvert's versions, MVS raises Culvert's pin, which is a reviewed dependency
    bump on their side.
  - **The Go floor:** decided by Hermes on 2026-11-22: the engine's `go.mod` moves to `go 1.27.0` with
    `toolchain go1.27.4` (Engine, on `claude/go-migration`). Before that decision, the Culvert sources said: `go.mod:9-11` says the `go` line is the
    language minimum and "is not raised to match" the toolchain. `godebug_pins_test.go:67-71` says a patch bump of
    the `go` line does not invalidate the GODEBUG review, and `toolchain_consistency_test.go:100-103` only needs
    `toolchain >= go`. So `go 1.27.4` passes Culvert's tests, but importing the module would force their `go` line
    from 1.27.0 to 1.27.4: the dependency-driven raise `go.mod:14-36` warns about.
  - **The minimum API is the nine calls the lab adapter uses** (listed in the PRO-107 answer).
- **Before any merge of the engine branch:** reconcile `tlsx`, `textroute` and `engine` with the engine lane:
  - credit coverage of the engine's new buffers;
  - SSH list ownership;
  - 7 replay mismatches.

  Then this lane's follow-ups from the report, section 5. One of them is a defect in this lane's own test:
  `TestNoCodeOutsideThePackageWritesAValidatedPack` ignores build tags.
- **The public package's allocations:** done for the copies that bought nothing (PRO-148). The lower floor described
  in the drift report §4 waits for Culvert's budget and, for two of its three steps, the engine lane.
- Codex's review of the frozen milestone and the queued commits (Sunday).
- **Hosted `ci` red on `2fdc5e9`** from another lane's commits (secret scan, see §7). Asked App Research and
  Platform & CI on PRO-148; this lane's own jobs are green.
- The Culvert team's answers (request items 1 to 6), and Lee's decision to send the request.
- Repository settings and the first `go/v0.x.y` tag (Lee).
- **From the load test (PRO-269), not started:**
  - the lab observation path's CPU share (about +60 to +70 ms per 1,000 flows on the fake engine: timer, record,
    log line) is the cheaper half to reduce;
  - measuring at 1,000/s and above needs vegeta and the origin on other hosts;
  - the observing state with full 16 KiB prefixes, and the blocked-write case, are not measured yet.

## 6. Frozen and queued SHAs

- **Frozen milestone:** `8d28748..725cd95` (base `d725890`): #15, #14, #16. Never change it.
- **Frozen for Codex (PRO-233):** merge `378dfb3` (parents `d10a2b4`, `f027a4d`), then `1fa45d2`, `e94e2d9`,
  `40311a3`, the brief commit `10627c6` and `80d6d34` (errcheck in the adapter tests) on
  `claude/culvert-land-main`; PR leenadav/protocol-detector#97. Then `60b2305` (merge of main `e5ac90f`) and the
  brief commit that records the PRO-235 decision, then the commit that fixes the 12 CodeQL alerts in
  `lab/culvert/tools/` (TLS 1.2 minimum on the lab clients, files closed, one unused assignment).
- **Queued for a later round:** listed in the working plan, under 4.3a "Review queue". The PRO-269 load-test
  commits (lab tooling, results and docs only, no Go code under `go/`) are added there too. The PRO-81 commit
  (`3efda92`) and the PRO-91 commit are added there in the same push as each task.

## 7. Pitfalls

- **`pkill -f` matches its own invoker.** The lab scripts' `pkill -f "bin/culvert-"` also kills a wrapper shell
  whose command line contains that text, and an orphaned script's final cleanup then stops the next run's
  servers. Invoke the scripts with nothing matchable in the command, and check `ps` for leftovers before a rerun.
- **The Culvert clone is shallow.** Commit counts over its history are unreliable; quote first-parent counts, or
  none.
- **A `.github/CODEOWNERS` already existed.** Look for an existing file before drafting a replacement.
- **The permission system refuses some combined commands,** for example a CI-file copy or a push chained with a
  build. Run the safe parts on their own, and stop and report if a write is refused.
- **Pronouns:** Lee's are not stated. Use neutral wording.
- **Two allocation figures.** "Allocations per flow" means different things in the two lanes: the engine's
  benchgate measures the inspector on benchgate workloads; this lane's `BenchmarkFlow` measures a whole flow through
  `go/detector`. Always quote which, with the commit.
- **The pitfall above struck again:** a restore step such as `cp .../bin/culvert-lab` placed in the same command as
  the lab script also matches the script's `pkill -f`. Restore in a separate command.
- **Detachment rests on immutability.** Go strings are immutable and the engine uses no `unsafe`, so a copy never
  protects a snapshot from input overwrites; it only avoids holding a larger engine allocation alive. If the
  engine ever builds strings with `unsafe`, `TestHeldSnapshotsStayDetached` is the test that must catch it.
- **Lab flows are held only for the observation window** (SEC-CULV-1). A tunnel's engine flow is finished at
  window end or handoff, never at tunnel close, and a refused admission still logs a record. The window timer's
  callback must not read `o.timer`: with a short window it can run before the assignment (a race `-race` caught).
- **The CI secret scan covers every branch.** The `ci` checkout fetches all history, and gitleaks scans all of it, so
  another lane's commit can fail this branch's gate. Seen on `2fdc5e9` (run 44971293208): `generic-api-key` matched
  in `research/live-results-2026-11-21-r5.tsv` (App Research, commits `655d440`, `75695d3`). Reproduce with
  gitleaks 8.30.1 (`git --ignore-gitleaks-allow --redact --exit-code 1 .`) and check `git merge-base --is-ancestor`
  before changing anything. Never edit `.gitleaks.toml` (CI/CD lane) or another lane's files; ask them instead.
- **Merge trials go in a worktree.** Use `git worktree add --detach /home/user/pd-drift <lane head>` and merge
  there; never on the lane branch.
- **A conflict-free merge can still change the reference.** Lane edits to `protocol_engine/` and `test_*.py`
  auto-merged with no conflict; only the parity replay (7 mismatches) showed them. Diff the merge against `main`
  for the Python reference and fixtures before anything else.
- **One connection per request exhausts ephemeral ports.** At 1,000 new connections per second into one proxy
  endpoint, the default range (32768–60999) fills with TIME_WAIT within a 30 s cell, and every build fails with
  `bind: address already in use`. Set `ip_local_port_range` to `1024 65535` and `tcp_tw_reuse` to 1; `loadtest.py`
  refuses to run otherwise and drains TIME_WAIT before each cell.
- **Culvert writes `categories.json` and `cluster.json` into its working directory.** Start it from the lab's
  `run/` directory, never from inside this checkout (the files appeared as untracked files in `lab/culvert/tools/`).
- **Go's `ReadHeaderTimeout` also bounds the TLS handshake.** A silent CONNECT tunnel to a Go HTTPS origin is
  closed by the origin after that timeout, so a hold test needs it longer than the window.
