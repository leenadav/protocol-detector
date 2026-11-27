# Engine lane brief: read this first

The onboarding note for a fresh chat taking any task in the engine lane. It has to stay short. **Rule (PRO-347,
2026-11-24): every task adds its own `migration/notes/PRO-<n>.md`** (front matter: task, lane, date, title, PRs,
SHAs; then one paragraph; `migration/notes/README.md`) in the same push as the task. That note is the task's record
and its frozen SHAs. **Never edit a section between `BEGIN GENERATED` and `END GENERATED` markers** ("Recent work"
below, the README/REVIEW-SCOPE test counts): `tools/build_ledgers.py` writes them after merge. Edit the hand-written
§2, §5, §6 and §7 only when the lane's standing state changes (a new open item, a new pitfall), not to log a task.

## 1. Purpose and scope

This lane finishes and maintains the Python → Go migration of the IPv4-only passive protocol classifier. The work
happens on `claude/go-migration`, and issue #2 is its Codex mailbox. PR #19 is closed: it merged an early snapshot
(`7debf09`) into `main` on 2026-11-15 (`c121ada`). The lane has no open pull request now, and opening one waits on Lee.

- **Go** (`go/`) is the only engine (PRO-403, 2026-11-27). The Python reference was removed; its last state is the
  tag `python-final` (`5cb35d2`). New detection work goes to Go only.
- **Go is judged against the reference's frozen answers** (`migration/fixtures/cases.json`,
  `migration/fixtures/golden/`) by the parity gates. Those answers are never edited to match Go; a Go change that
  moves them is a pinned, Lee-approved divergence, and re-recording needs a checkout of `python-final`.
- **The lane owns** `go/`, `migration/`, the product code (`go/`, `presentation/`), the content data and the
  `Makefile`.
- **Security requirements** (SECURITY-REQUIREMENTS.md) name Go tests; a change that removes or renames one updates
  the row in the same commit (`make requirements`, `make requirements-run`).
- **Never touch the CI/CD lane's files:** `.github/**`, `tools/workflows.lock.json` and its CI tools in `tools/`
  (`go_ci.py`, `check_go_drift.py`, `content_gate.py`, `merge_readiness.py`, `go_fuzz_long.py`, `perf_history.py`,
  `build_go_release.py`, `release_provenance.py`, `check_workflow_policy.py`). Changes there go to that lane as a
  patch or a PR into `claude/cicd-next`.
- **Out of scope:** IPv6 transport, proxy integration, and any merge, deployment, release or public tag without Lee's
  decision.
- **Data:** IPv4 and synthetic only. No captured traffic or key logs, ever (`tools/check_no_keylogs.py`).

## 2. Current state (2026-11-24)

- **Branch head:** check `git log -1 origin/claude/go-migration`. On 2026-11-21 (PRO-69) `main` `0ef7349` (41 commits, through PR #39,
  including #39's numeric content-version order) was merged in with a normal merge commit. On 2026-11-22 `main` `2a33183` (PR #66, #36) came
  in as `f5353c5`; PR #55 (per-target module sets in the release build, `07cda53`) was merged in (`b1d69d5`, Lee's
  approval), then `main` `2c92b17` (PR #66, #71 gitleaks rules, #63, #68) with a normal merge (`b2e36d4`), and `main` `b2643ed` (through PR #85) as `f255c9d`, so the branch is 0 behind
  `main` and merges into it without conflicts. PR #40 is ready for review (Lee, 2026-11-22); the merge is Lee's.
  On `b2e36d4` every check on PR #40 passes (44 pass, 1 skipped: `release publish`, which only runs on tags).
- **Done, Milestones A and B:**
  - The Go engine, the CLI `protodetect` and the dashboard service `protodetect serve`.
  - The launcher starts Go when the binary is installed and Python otherwise (`24e410e`, Lee's decision of
    2026-11-17).
- **Parity:** 7,474 of 7,474 cases agree (18 of them through PRO-260's pinned Go-only deltas; 12 SEC-FP-1 ALPN fingerprint cases added by PRO-394). 79 of 88 families are parity-verified since PRO-201 (`098b201`): the verifier no longer credits a replay of the positive message as foreign bytes, so ftp, http, imap, nats, pop3, rtsp, sip, smtp and ssh are `experimental` until real foreign cases are added. Server parity: 424 exchanges, 0
  differences. The adversarial suite (4,041 cases) passes.
- **Content release:** 2026.11.9 (digest `cdaa5993077d101a`), with 544 applications and 442 host entries. Every earlier
  release reproduces the digest it was published with (C11). **Since PRO-411 the content source is Go's**
  (`go/internal/content/pack.json`, `history.json`, ledger `lock.json`), edited only with `tools/content_pack.py add
  BATCH.json` (docs/CONTENT-BATCHES.md); the Python export tools are gone. Open before a real batch merges: the
  frozen answers (cases.json, golden files) and the serve catalog pin release 2026.11.9 and need Go pinned to it.
- **Vendored dependencies:** `x/crypto` and `x/sys/cpu` live under `go/vendor`, and every Go command runs with
  `-mod=vendor`.
- **Codex review packet:** complete in `migration/review-packet/` (frozen head `50ce5c0`, 43 chunks).
- **PRO-31**: both engines order content versions numerically. Go has it in `6194fb9` (plus the numbering-rule test in
  `4d8aa29`); the Python reference got it in `376a204`, under Lee's exception of 2026-11-20.
- **PRO-127 (tshark oracle):** `go/oracle`, merged with PR #79 (`d7240ee`); 26 of 26 comparisons agree;
  the nightly job is with the CI/CD lane.
- **PRO-126 (mutation testing):** gremlins tooling, the baseline and reference-checked boundary tests for TLS,
  QUIC and HTTP/1 merged with PR #72 (`bb2af2e`); the nightly job is with the CI/CD lane, and PR #80 (`9b499f8`) moved the
  pin's x/sys and x/text past the OSV advisories.
- **SEC-CONTENT-1 (PRO-154):** the content-pack loader decodes exact keys only; merged with PR #84
  (`bc80f45`).
- **Dependency rule (PRO-107, PRO-156):** no non-standard package in the detection path's import graph;
  `TestDetectionPathImportsOnlyTheStandardLibrary` enforces it (ADR 0002). `golang.org/x/crypto` is used only
  by key-log decryption.
- **SEC-INSP-1 (PRO-129, P0):** parser-driven shift nesting capped at 2, merged with PR #87 (`f209bd5`); a Go-only
  parity divergence (Python nests without bound), approved by Lee on 2026-11-22 (PRO-129).
- **SEC-HTTP-1 (PRO-179, P1):** an absolute-form or CONNECT target's authority is the HTTP hostname (Go only, recorded
  divergence; `random_diff.py` accepts it as an approved class), merged into `main` with PR #92 (`c08fe67`).
- **PRO-189 (Codex PRO-12, P2):** an unknown stream finalizes when the byte budget is spent before the unknown buffer
  fills (Go only, recorded divergence), on `claude/fix-unknown-budget` (PR into `main`).
- **PRO-261 (#99 vs #98):** every #99 finding checked on `main` `cb3ac80` (table in `STATUS.md`); three partial gaps ported on `claude/engine-PRO-261-reconcile-99` (pcapng 32-bit original length, analyze/decrypt empty-run checks, server null measurements). #99 is superseded; the buffer growth item stays a decision.
- **PRO-201 (Codex P2s, windows 2-10):** 23 fix commits `7da811e`..`6b614c0` on `claude/funny-cori-6znbkn`; per-finding table in `STATUS.md`. Six fixes that move parity are held as patches in `migration/held-patches/PRO-201/`.
- **PRO-101 (property, fuzz and chaos tests):** rapid (`pgregory.net/rapid` v1.3.0, test-only, vendored, ADR 0002)
  and native fuzz targets over all 59 registry parsers, the inspector, the datagram inspector and the facade
  (no panic, budgets, split invariance, determinism), plus `go/detector/chaos_test.go` (max flows, memory, huge
  headers, slowloris, panic storm and breaker). Finding F1 (SMB watch, `bytes_inspected` split-dependent, Python
  alike) is held for a parity decision ([#103](https://github.com/leenadav/protocol-detector/issues/103)). Details in
  `STATUS.md`. Merged into `main` with PR #102 (`cb3ac80`, `merged_by: leenadav`, not by the session). Hermes's
  review follow-up (who merged, the branch reason, gitleaks on `fd46be0` and `3a25bd0`, issue #103) is in `STATUS.md`
  ("PRO-101 review follow-up"), on `claude/dazzling-franklin-1179wl`.
  alike) is held for a parity decision. Details in `STATUS.md`. Branch `claude/busy-ramanujan-7oczj2`.
- **PRO-260 (TLS post-quantum hybrid key shares, Go only by Lee's decision, 2026-11-23):** 0x11EB, 0x11EC and
  0x11ED are named groups in `tlsx` (`selected_key_exchange` = `hybrid`); branch `claude/engine-PRO-260-tls-pq-keyshare`,
  PR #105 into `main`. Recorded as a Frozen-Python exception; 18 parity cases pinned in `deltas.json` (`go`), and
  `migration/parity/pro260.py` models the divergence on the reference for the decrypt and live-decrypt differentials.
- **SEC-QUIC-3 (PRO-47, PRO-123):** a client Initial datagram under 1200 bytes is malformed and feeds no CRYPTO
  data, and a second complete ClientHello of a flow naming another server invalidates it (Go only, recorded
  divergence approved by Lee on PRO-124; `random_diff.py` accepts it as an approved class). `fe87386` on
  `claude/youthful-lamport-hzlekc` (PR into `main`).
- **PRO-291 (Codex PRO-290 P2 on SEC-QUIC-3):** the flow's first QUIC server name now outlives the scope's CRYPTO
  entries (eviction, expiry, exhaustion); only `Reset`/`Clear` forget it, bounded by `MaxNames`. On
  `claude/engine-PRO-291-quic-sni-retraction`, cut from PR #107's head `d10c007` (PR into that branch).
- **PRO-315 (Codex PRO-312 P2s on SEC-QUIC-3):** P2 1 (first SNI dies with the last entry) was already fixed by
  `5b48d91` (PRO-291). P2 2: an undersized client Initial on a conflicted connection no longer refreshes the marker
  or retracts; the 1200-byte rule runs right after opening, before frames (also the related P3). `653b1ca` on
  `claude/engine-PRO-315-quic-conflict-size`, cut from PR #107's head `d950eb8` (PR into that branch).
- **SEC-QUIC-1 budget (PRO-47, PRO-122):** an over-budget CRYPTO merge no longer forgets the QUIC connection; it
  stays a sticky exhausted marker with its pre-overflow bytes, so a later contradicting ClientHello conflicts and
  retracts instead of assembling as a first message (Go only, recorded divergence approved by Lee on PRO-124).
  Branch `claude/engine-PRO-122-quic-exhausted-sticky`, PR #145 into `main`; details in `STATUS.md`.
- **Merged:** PR #40 brought `claude/go-migration` into `main` on 2026-11-22. Engine work now branches from `main`.
- **PRO-141 (livectl stop flake):** the stand-in worker sets its INT trap first and writes a ready file last; the
  three stop tests wait for it (`aff4d13`, branch `claude/vigilant-meitner-t7kw7h`). 200 of 200 under `-race`, also
  with 8 spinning loops on 4 CPUs. Root cause from PRO-140: the test, not `Manager.Stop`.

### Recent work (generated)

Written by `tools/build_ledgers.py` from `migration/notes/PRO-<n>.md`, newest first. Never edit it: a task adds
its own notes file, and the section is refreshed after merge.

<!-- BEGIN GENERATED: recent-work lane=engine limit=15 -->
<!-- tools/build_ledgers.py writes this section from migration/notes/PRO-<n>.md. Do not edit it: add a notes file instead (migration/notes/README.md). -->

- 2026-11-27 · **PRO-590** · engine · PR #174 (Python removal) and PR #181 merged with the PR #166..#169 chain, conflicts resolved: The chain head 97edba3 (#169, holding #166, #175, #173, #179, #176, #180, #177, #178, #170) is merged into #174's branch with a merge commit (57f68b4). Six conflicts: the ci gate's `needs` is #174's Go-only list plus go-bench (lock regenerated); AGENTS.md keeps the series' pointer to REVIEW.md, and REVIEW.md now carries #174's post-deletion rules (Go parsers, the Go content pack, the frozen answers); the Makefile keeps #174's targets plus child-apps and the requirements self-test, without the capabilities target (it imports the removed engine); SECURITY-REQUIREMENTS.md keeps #174's Go-test rows with #178's SR-70..75 renumbering, and check_security_requirements.py combines #178's strict parse, duplicate check, id lock and `--retire` with #174's Go references and `--run`. The renumbered rows' Go tests keep their names (`TestSR58RDPSecurityPosture`..`TestSR63ServerNameCatalog`), which key the recorded requirement cases. The manifest is regenerated. #174's new head is then merged into #181 (PRO-546), whose strict Python-test runner is carried into the combined tool. PRs: #174, #181. SHAs: `57f68b4410e93b2333f734de446bdf477f6b6f0d`, `81180398ef14c04031639ddf9261e31cbce0c068`. (merged in #181)
- 2026-11-27 · **PRO-574** · engine · PR #174 made mergeable again: main cc1566d merged into the PRO-403 branch, both sides' CI and Makefile kept: Merge commit 48cd35d (normal merge, no rebase) brings main cc1566d (PRs #157-#165: go-bench PRO-268, child apps PRO-492/495/504, framed on 386 PRO-503, dependabot, A12/A14) into claude/vigilant-maxwell-gub33g. Conflicts in .github/workflows/ci.yml, Makefile and tools/workflows.lock.json: PRO-403's removals stay (no behaviour-diff, mutation-smoke or package jobs; no capabilities or parity targets) and main's additions are kept (go-bench in the required needs list; child-apps in make check, standard library only). tools/workflows.lock.json regenerated by check_workflow_policy.py --write-workflow-lock and presentation/SOURCE.json by build_manifest.py --write (150 files, digest 06a0633152810b69), since main changed Go sources. The ci.yml and lock lines still need the CI/CD lane's review, as for the rest of #174. PRs: #174. SHAs: `48cd35d844fdeb585fa5fe7d0fb58651094c7142`. (merged in #181)
- 2026-11-27 · **PRO-547** · engine · SR-59 Go tests for the key-log FIFO, device and owner refusals (SEC-PYRM-3): SEC-PYRM-3 (from PRO-541): after the Python tests were removed, no Go test covered SR-59's FIFO, device or owner refusals, and mutations M1b (dropping O_NONBLOCK) and M1c (dropping the uid check) in go/internal/livedecrypt/keylog_unix.go survived. New tests in keylog_unix_test.go: a Mkfifo key log is refused within a 5 s timeout (a stuck open is released by a writer, then the test fails); /dev/null is refused as a device; a regular file is refused once the user id seen through the new package seam `getuid` (default syscall.Getuid, so product behaviour is unchanged) is another user's. No skip. Each mutation now fails: M1b times out the FIFO test, M1c fails the owner test, and dropping the S_IFREG check fails the FIFO, device and existing link/directory tests. SECURITY-REQUIREMENTS.md (SR-59 row) is Platform & CI's and is left to it. PRs: #190. SHAs: `348a8866ab844e43b8e785974af53f631bd81a14`, `540b016a7bb178418b8545e65843691181fb07c2`. (merged in #190)
- 2026-11-27 · **PRO-510** · engine · SEC-CHILD-3, child-app rules cover real Gmail, Graph, Drive v2, Google batch, Telegram, Discord and Dropbox forms: Wave-0 child rules missed request forms the vendors document, so a deny on a function child could be bypassed. `tools/child_apps_wave.py --evidence` now reads App Research's verified `sec_child_3` items (`research/child-apps/wave-1.json`, PRO-524; fixture copy) and applies one widening per item, citing it: Google media uploads drop the `message/*` (Discovery accept) and `uploadType` conditions, Gmail drafts.update (PUT) and Drive v2 rules are added, Graph paths also under `/beta/` and case-insensitive, Telegram methods case-insensitive, Discord `/api/` unversioned and v6 to v10, Dropbox content rules no longer assume `Dropbox-API-Arg` (the `arg` URL parameter is unverified, blocked-urls row 48). New batch children `gmail-batch`, `google-drive-batch`, `ms-base-graph-batch`; body parsing is CHILD-BATCH-1 in the backlog. Go: rule field `path_case_insensitive`, and percent-encoded unreserved characters are decoded before matching (`%24batch`). Release 2026.11.2, 50 children; `secchild3_test.go` pins 32 forms and 8 bounds. SHAs: `bce8743a7a4a7669fe7d2222531536a3f008b043`. (merged in #193)
- 2026-11-27 · **PRO-492** · engine · Child applications per function (enterprise App-ID): rules as data, Culvert API, policy containers, work ceiling: Enterprise App-ID: a service splits into child apps per function; the verdict names both (app=gmail-uploading, container=gmail) and the host's catalog owner (host_owner). Go only. go/internal/childapp matches one proxied HTTP request on host, method, path prefix or pattern, query, headers, content type, direction and WebSocket; the most specific rule wins. Rule hosts must be claimed by the container or its depends_on, also at match time. Ceiling: 64 rule evaluations, 4,096 path bytes, reported in `limit`. API: go/detector AppClassifier; policy.FromJSONWithChildren adds a Go-only `containers` key. SEC-CHILD-2 (PRO-505/509): `containers` and Matches also match host_owner, so deny containers:[ms-base] still denies Graph sendMail; a child's risk is never below its container's or depends_on's. SEC-CHILD-7: a child is also evaluated as its host owner, so deny apps:[ms-base] still holds. Rules come from App Research's cited wave 0 (PRO-495) via tools/child_apps_wave.py: 47 children over 20 services, 3 skipped (docs/child-apps/wave-0-rules.md). The pack stays at 2026.11.9. Tests: examples, refusals, owner_test.go, properties, two fuzz targets. Parity 7,474 of 7,474. PRs: #163. SHAs: `e75e4a8474db80a7ad9d4a01534938e0d0531efa`, `4e530900bffa7c6e6094ad23eafef1019a58d696`, `745eeee173a76151809a1219d9720b334d994e1e`. (merged in #163)
- 2026-11-27 · **PRO-403** · engine · Python reference engine removed; every security requirement verified by Go tests: The Python engine, adapters, root engine scripts and tests and stale benchmark/live-smoke/interop artifacts are deleted (history under the tag python-final, 5cb35d2); BENCHMARK-V*.md moved to docs/history; tools/*.py kept. All 75 SECURITY-REQUIREMENTS.md rows now name Go tests (188 in 29 packages, 0 missing): go/internal/replay TestSR* replay 47,493 inspector inputs recorded from the removed tests at python-final (migration/fixtures/requirements.json.gz, requirement_cases.py) plus the rows' cases.json families; new Go tests cover control retraction, hostnames, capture argv, risks, schemas, loopback server rules, privileges and named bounds. Widening each of 25 named bounds fails a listed test. The recorded cases found a Go byte-class bug (regexp ranges match runes), fixed in textroute. tools/evaluate_corpus.py now runs the Go binary. Open: other tools/ scripts that still import the removed engine and run in no gate. SHAs: `94b8a37`, `60125d4`, `8b7db4d`, `68dcfbe`, `63639b9`, `3ac8a59`, `9d5870f`, `f5f1c32`, `7838cdc`. (merged in #181)
- 2026-11-26 · **PRO-461** · engine · PR #135 conflict with main: already resolved by the PRO-458 merge (93347bd); gates re-run, task note only: The reported conflict of PR #135 (PRO-411) with main in migration/parity/analyze_diff.py, live_decrypt_diff.py and live_diff.py was already resolved before this task ran: PRO-458 merged main 3647d2f (#124, SEC-SESS-1) into #127 (dfa4001) and that branch into #135 (93347bd), so origin/main is an ancestor of the head, git merge-tree against main is clean, the three files carry no conflict markers, and git merge origin/main reports "Already up to date". No code or lock change was needed; this commit adds only this note. Re-run on 93347bd with go1.27.4: make check exit 0 (902 + 86 tests OK, parity 7474/7474, workflow policy ok on 10 files, content batch e2e ok); make go-check exit 0 (golden analyze 300, decrypt 300, live 300, live-decrypt 300, control 120, server 424, adversarial 4041: 0 mismatched; random 1882/2000 with 118 approved, 0 failures, planted difference caught). CI on 93347bd: 34 of 34 checks green. #135's base is still #127's branch and returns to main once #127 merges. PRs: #135. SHAs: `93347bd37aae1b51cc4b674fb5ddedd3aae3cec4`. (merged in #135)
- 2026-11-26 · **PRO-458** · engine · main (#124, SEC-SESS-1) merged into PR #127 (golden replay); three golden files re-recorded with the pinned Go answers: PR #127 (PRO-401: golden replay, no reference run) conflicted with main after #124 (PRO-398/PRO-432: SEC-SESS-1 pins) in migration/parity/analyze_diff.py, live_diff.py and live_decrypt_diff.py. Resolved by a merge commit keeping both: --golden replays stay reference-free with the unchanged strict comparison; in reference and --record runs sec_sess1.Pins approves exactly the pinned divergences, and a recording stores Go's pinned answer (entry flag "sec_sess1"); present_problem/present_limits keep #127's split and return the pins' sides as on main. The analyze, live and live-decrypt golden files were re-recorded (go1.27.4; live decrypt under OpenSSL 3.5, the previous file's line, keeping 40 PRO-260 cases); the other six are unchanged. Only the 20 / 6 / 15 pinned answers changed in substance (migration/STATUS.md, SEC-SESS-1, "In golden mode"). The same merge then went into #135's branch (PRO-411). No Python product code changed. PRs: #127, #135. (not committed yet)
- 2026-11-26 · **PRO-448** · engine · analyze reports udp_flow_limit and tcp_connection_limit, and marks UDP sessions with mixed datagram outcomes: External PoC (kidcarmi, via Lee): 800 UDP flows gave 32 session records (the UDP table follows MaxConnections 32) and udp_flow_limit never reached the output. Go only: the analyze summary and input_quality always carry udp_flow_limit and tcp_connection_limit (text names them only when not 0); analyze's UDP session records carry mixed_outcomes and datagram_outcomes (at most 8 labels, plus beyond_limit); detector gains Stats.RefusedFlowLimit. Schemas, OUTPUT.md, STATUS.md updated; migration/parity/pro448.py models the reference. After main's SEC-SESS-1 (PRO-460, dcd932b): undecided flows are evicted, not kept, so the 800-flow test gives 33 records and 767 refusals (query 9 stays half-open and is evicted); tcp_connection_limit counts SYNs refused by established connections (32 handshakes + 8 SYNs: 8; 40 bare SYNs: 0, 16 evicted). Nine analyze pins got new digests for the added counters; without them both sides hash to the old pins. Default of 32 unchanged; STATUS.md proposes MaxUDPFlows 1024 for Lee. PRO-460 (790b81f, main 6c6d4dd): main's analyze golden predates these fields, so it is re-recorded with the pro448 model (0 mismatched); pro448 loads only when recording. PRs: #148. SHAs: `81b331db7116b1c3cb315e88923275148fd15fc3`, `0c51e26d7712408c81c8c7e4fac908df90745ec0`, `b45979c8b0a8d4e64bceebb6d5e6cd60491b1ef2`, `dcd932bd3cfe6c334e6d4f1a2438f0627a48c7cd`, `790b81f33e5b1f829313d8d7437b6fb96b702ec8`. (merged in #148)
- 2026-11-26 · **PRO-437** · engine · SEC-KEY-1 residual, release and zero the secrets of closed key-log connections (Go only): Spec: Engine's PRO-164 answer (items 1-4). A key-log connection that failed at the capture level (gap, one direction, conflicting overlap) never reached a decoder verdict, so its decrypt.Connection kept the client random and derived traffic secrets for as long as the 4096-connection report window held it. keylogcap now Discards and drops c.tls after the close-time build and rows() never rebuilds a released connection (Fail is not called, so the row is unchanged); decrypt release() zeroes the TLS 1.3 secrets and IVs, the TLS 1.2 key block and the client random (copies and derivations only, never the KeyProvider's shared bytes; KeyUpdate zeroes the superseded secret); the finished window clears the dropped slot; the coordinator clears analyzer records once their generations are published. Six regression tests (decrypt/release_test.go, keylogcap/release_test.go) fail on main. No output change: make go-check exit 0, parity 7474/7474, every differential 0 mismatched. The PRO-164 thread itself was not readable from this session; tests follow the four items. SHAs: `68202be`. (merged in #144)
- 2026-11-26 · **PRO-432** · engine · SEC-SESS-1 random-suite divergences pinned case by case as approved Go-only deltas; main merged into PR #124: Lee's option B (2026-11-25: no more Python fixes): the 41 cases where Go's half-open budget, eviction and 5 s half-open lifetime (PRO-398) make the seeded random suites differ from the frozen reference are pinned in migration/parity/sec_sess1.json, each with its exact case id, the reason (SEC-SESS-1, PRO-398), Go's and the reference's first differing line and the SHA-256 of each side's whole result: parity-analyze 20 (13 captures, analyze and present), parity-live 6, parity-live-decrypt 18 under OpenSSL 3.0 (CI) and 15 under 3.5 (its scripts hold real OpenSSL exchanges, so the case id names the OpenSSL line). migration/parity/sec_sess1.py approves a mismatch only on an exact match of both digests and fails stale pins; live-decrypt scripts with a real OpenSSL exchange are masked (numbers and hex only) because their keys change each run. With Go from main 23bbc0c all three suites give 0 mismatches (both OpenSSL lines) and every pin is reported stale. Now: 0 unapproved in each suite, all other counts as on main. No Python product code changed. PRs: #124. (merged in #124)
- 2026-11-26 · **PRO-195** · engine · protodetect version is a variable a release build can stamp with -ldflags -X: go/cmd/protodetect/main.go declared const version = "0.0.0-m4", and the linker silently ignores -ldflags "-X main.version=..." on a constant, so a release binary named protodetect-<release>-... still reported 0.0.0-m4 (PRO-26 review, P2). It is now var version = "0.0.0-m4": same default, no output or parity change, no Python change. Test first: TestVersionIsSettableAtBuildTime (go/cmd/protodetect/version_test.go) did not compile against the const and passes now; it checks the default and that the version command prints a stamped value. CI errcheck then flagged unchecked pipe Close calls in that test; d89f332 checks them (tools/go_lint.py: no finding beyond the baseline, 194 accepted). A manual go build -ldflags "-X main.version=2026.11.26-test" prints the stamped version; a plain build prints 0.0.0-m4. Open: PRO-194 (Platform & CI) adds the -X flag to the release build and checks the binary's version output. SHAs: `f34e8c9c0bde863e6b1cc2c1243c60b04c78af8c`, `d89f332d2be921f80845270337063e1a3454f04e`. (merged in #143)
- 2026-11-26 · **PRO-166** · engine · SEC-PAR-2, parity leaf comparison strict on type and a bool-to-int plant: SEC-PAR-2 (from PRO-51): `migration/parity/compare.py` `diff()` used Python `==`, so True, 1 and 1.0 were equal. `144daf5` already split booleans from numbers; an int still matched a float. A leaf now differs when its Python types differ, and `--plant bool-to-int` (seventh plant) turns a result's first JSON boolean into the equal integer. Tests: `test_leaf_comparison_is_strict_on_type`, the plant loop. The stricter check found one Go harness gap: `protodetect replay` wrote session records with `encoding/json`, which writes float64 40.0 as 40 (`session/lifecycle/half-message-idle`); `replay.Records` now marshals through `pyjson.Dumps`, as the product output already did (`TestSessionRecordsKeepPythonNumberTypes`, failing first). No product or Python reference code changed. PRO-459 (duplicate #139 dropped): 813de6e ports its type-mismatch and plant tests; its 1 == 1.0 match is not ported. (merged in #141)
- 2026-11-26 · **PRO-122** · engine · SEC-QUIC-1 budget: an exhausted QUIC connection stays a sticky marker, so a later contradiction conflicts: Go only, a divergence Lee approved on PRO-124 (the Python reference is unchanged). quicx.Assembler.Add used to forget a connection whose CRYPTO merge went over MaxFragments or MaxCrypto, so a ClientHello contradicting the complete one the connection had assembled was taken as a first message, with no conflict and no retraction. The entry now stays as a sticky exhausted marker holding its pre-overflow bytes: later datagrams answer exhausted and assemble nothing, and a contradiction of the retained bytes turns it into the conflict marker. Regression test TestCompleteThenExhaustedThenContradictionConflicts fails on main 23bbc0c and passes after; details and numbers in migration/STATUS.md and the PR. PRs: #145. SHAs: `79cf9dd`. (merged in #145)
- 2026-11-26 · **PRO-119** · engine · P3 hardening from audits A2 and A3, decrypt memory, key zeroing, datagram assertion, dispatch invariant (Go only): SEC-DEC-1: an awaiting_keys decrypt.Connection held about 2x what the tier admitted (framer tail kept consumed prefixes, queued[1:] kept processed bodies, hello records duplicated). Framer compacts, popped slots are cleared, hello records dropped; 64 connections fed 2,104,000 bytes held 4,541,856 bytes of heap before and 2,283,680 after. Nothing counted against Tier.allocated (that would move parity). SEC-KEY-1: Analyze defers keys.Release(); Expire and KeyUpdate overwrite secrets (KeyUpdate hunk identical to PR 144, which keeps terminal zeroing, PRO-437). A3: checked datagram error assertion; dispatch-prefix invariant pinned by a comment and tests. Every new test fails without its fix. Open, waiting on an approved parity delta (Python behaves the same): SEC-QUIC-2 conflict marker LRU place; decrypting records after close_notify or a fatal alert. PRO-459 (duplicate #147 dropped): 852af38 ports its uncovered cases, handshake secret zeroed at Finished, hello buffers dropped once negotiated, two heap tests (fail on main); terminal zeroing stays in #144. SHAs: `afbe5e1`, `91960e0`, `852af38`. (merged in #150)
<!-- END GENERATED: recent-work -->

## 3. Where things live (reading order)

1. `AGENTS.md`: the repository rules, the two lanes and the mailbox loop.
2. `migration/STATUS.md`: the ledger by milestone, with every SHA and command, and the frozen SHA list.
3. `migration/MERGE-READINESS.md`: the merge plan, covering the 7 conflicting files, how to resolve each, and the
   checklist.
4. `migration/POST-MERGE-BACKLOG.md`: the PM-1 to PM-8 detection items, the decisions behind them and the prepared tests.
5. `migration/CONTRACTS.md`: contracts C1 to C17, with the reference behaviour and the cases that check each one.
6. `PROTOCOLS.md` and `ARCHITECTURE.md`: the profiles, including what each profile deliberately excludes.
7. `migration/review-packet/INDEX.md` and `REVIEW-SCOPE.md`: what Codex reviews, and how fix rounds are reviewed.
8. `migration/CONTENT-DIGEST.md`, `go/internal/content/` and `docs/CONTENT-BATCHES.md`: the content releases and the C11 rule.
9. `migration/adr/`: ownership, toolchain and dependency decisions.

## 4. How to verify

Run everything from the repository root. Times are for the cloud container (4 vCPU):

| Command | What it checks | Runtime |
|---|---|---|
| `make go-check` | gofmt, vet, `go test -race`, 28 fuzz targets, parity-go with verify_families, every differential, bench-gate | about 8 min (488 s) |
| `make check` | ruff, the tooling and launcher tests, workflow policy, security requirements, docs counts, ledgers, manifest, presentation (Go service in Chromium), content, content pack (PRO-403: no Python engine left) | about 2 min |
| `make requirements-run` | every Go test SECURITY-REQUIREMENTS.md names, run on the pinned Go; each must PASS | about 2 min |
| `make parity-random` (in `go-check`) | the randomized differential's frozen seed-1 run (2,000 cases, `migration/fixtures/golden/random.json.gz`): `--self-test --rules-only`, `--plant` on the golden file, then the replay. Every differential of `go-check-parity` replays its golden file since PRO-401; re-recording needs a checkout of the tag `python-final` (PRO-403). Fresh random inputs: `make property-long` (Go only, nightly) | about 3 s |
| `make pcap-oracle` (nightly, not in `go-check`) | the tshark oracle (`go/oracle`, its own test-only module): real OpenSSL, curl and quic-go traffic on 127.0.0.1, read by gopacket, fed to the engine and compared with tshark 4.2.2 on SNI, ALPN, TLS version, HTTP Host and QUIC version. It needs the pinned tshark, OpenSSL and curl (`go/oracle/README.md`). Allow-list: `go/oracle/allow.json` | about 3 s |
| `make mutation` (nightly, not in `go-check`) | gremlins v0.6.0 on the nine parser packages against `migration/mutation/baseline.json` (fails on a drop of more than 5 points). `go-check` runs only `boundaries.py --check` and `mutation.py --self-test`. Regenerate the boundary tests with `python3 -B migration/mutation/boundaries.py` | about 20 min |
| `make go-vendor-check` | re-vendors into `build/go-vendor-check` and diffs it against `go/vendor` | seconds (module cache warm) |
| `python3 -B -m unittest discover -q` | the remaining Python tests (launchers, Makefile gates, verify_families) | part of `make check` |

Run `make go-check` and `make check` before every push. Also run `make go-vendor-check` after any change to
`go.mod`, `go.sum` or `go/vendor`. Push fast-forward only.

## 5. Open items and what each waits on

| Item | Waits on |
|---|---|
| PRO-31 (`6194fb9`, `4d8aa29`, `376a204`) | Engine work done; Hermes approved it, and PRO-31 is parked. Codex's code review is PRO-58 (under PRO-11), waiting for Codex's quota to come back. If it finds problems, Hermes reopens PRO-31 or opens a new Engine task; if not, PRO-31 closes. |
| PR #39 `claude/fix-content-version-order` → `main` (`37b3c84`) | merged by Lee on 2026-11-21 (`0ef7349`). It is in this branch since the PRO-69 merge. |
| Draft PR #40 `claude/go-migration` → `main` | Codex's review, then Lee's decision. Keep it draft. PRO-69 merged `main` in (9 conflicts, resolved per `MERGE-READINESS.md`). The CI fix it brought (`91113bc`, the Go build before the tests and presentation suites) lets `GoServiceTests` run instead of skip. | The secret scan's `296227b` findings (PRO-126's first push, hex case data) are allow-listed by PR #71, merged into this branch with `b2e36d4`.
| Codex review of the packet (`dbe20f3..50ce5c0`) | Codex, from Sunday. Fix rounds are reviewed as the fix diff only. |
| `release build` on PR #40 (`publish-release.yml`, not a required check) | nothing: fixed by PR #55 (`07cda53`, per-target module sets; the SBOM lists the union), merged into this branch on 2026-11-22 (`b1d69d5`). Green on `b2e36d4`. |
| Nightly randomized differential (PRO-100, PRO-136) | the CI/CD lane's PR #78 (`claude/cicd-nightly-parity-direct` → this branch, head `cd153f8`; #65 closed as superseded), then Lee's merge. Its `randomized Python-vs-Go parity (long)` job runs `make parity-random-long` with the run id as seed. Manual run 44995320464: seeds 44995320464 and 44995320465 matched 25,000 of 25,000 each (0 failures), the extended mutation fuzz passed, and the extended Go fuzz over every fuzz target passed (06:49 to 08:09 UTC, no failing inputs). |
| Nightly tshark oracle (PRO-127) | the CI/CD lane: a nightly job installing `tshark=4.2.2-1.1build3` on ubuntu-24.04 (OpenSSL 3.0.13 and curl 8.5.0 ship with it), building `go/oracle` in a step with module-proxy access, then running `make pcap-oracle` with `ORACLE_REPORT` uploaded. The target and module are on this branch; the workflow is theirs. |
| Nightly mutation run (PRO-126) | the CI/CD lane (accepted; stacked after #65): a nightly job that builds gremlins in its own step from a copy of `migration/mutation/gremlins/go.mod` and `go.sum`, then runs `make mutation MUTATION_BIN=<that binary> MUTATION_ARGS="--summary $GITHUB_STEP_SUMMARY"` with `GOPROXY=off`, about 30 minutes, uploading `build/mutation/*` always. The targets, the tool pin and the baseline are on this branch; the workflow is theirs. |
| Merging `claude/go-migration` into `main` | the Codex result, then Lee's decision. Don't ask again before then. The branch already contains `main` as of `2c92b17`, so the merge itself has no conflicts. |
| Merge conflicts (7 files, see `MERGE-READINESS.md`) | the merge itself. The `ci.yml` hunks resolve to `main`'s, which already has the govulncheck port (`85e99e9`, PR #32, merged). |
| PRO-201 held patches (`migration/held-patches/PRO-201/`: SMB empty buffer, SMB signing-enabled, SPNEGO mechTypes, live reject counter, stale cached row, failed-decryption inner protocol) and the live duplicate-SYN pre-check | an approved parity delta each (Hermes/Lee). Apply with `git apply`, then record the delta |
| PRO-141 livectl stop flake (`aff4d13` and its documentation commit) | Hermes's review, then Lee's merge of the PR into `main`. |
| PRO-101 F1 ([#103](https://github.com/leenadav/protocol-detector/issues/103)): the SMB1/SMB2 watch reports header bytes of a non-SMB next frame as consumed only when they arrive in separate calls (`bytes_inspected` ±7, observation unchanged; Python identical) | Lee: an approved parity delta to fix it in Go, or accept it. Until then `continuationConsumedVaries` relaxes only that field for `smb1`/`smb2` |
| PRO-101 nightly evidence | the first scheduled `nightly-fuzz.yml` run on `main` after `cb3ac80` (its `extended Go fuzz (every fuzz target)` job picks up the four new targets); record the run id in `STATUS.md` |
| PRO-201 decisions: buffer transient capacity (ADR 0001), unkeyed session id, signature names that collide with built-ins, 79 of 88 verified families | Hermes/Lee |
| PM-1 to PM-8 detection fixes | the merge. They are Go only, and each needs an approved parity delta. The prepared tests use `pending()`; remove that marker when the fix lands. |
| SEC-SIG-2 / SEC-SIG-1 (PRO-332, branch `claude/engine-PRO-51-sig-compile-cost`; replaces PRO-160 and PRO-159) | Hermes's review, QA Reviewer (Codex), then Lee's merge. Open for Hermes: (1) approve the Go-only divergence (a direction past its signature work allowance ends `budget_exhausted`; the reference has none); (2) the absolute ceiling PRO-370 added (`MaxSignatureWorkCeiling` 2^28, about 0.7 s per direction at worst; past it even a single full segment ends `budget_exhausted`; value approved by Hermes on PRO-375, ported to `main` by PRO-446 because PR #122 merged into the PRO-51 branch, not `main`), with PRO-370's charging of length-only conditions and candidate preparation (`signatures.FixedWork`); (3) the 11,110-cheapest-pattern document loads in ~99 ms, above the 50 ms target, from per-pattern fixed cost the instruction caps do not bound. Numbers: `migration/STATUS.md`, "SEC-SIG-2 and SEC-SIG-1". |
| SEC-QUIC-3 (`fe87386`, PR into `main`) | Hermes's review, QA Reviewer (Codex), then Lee's merge |
| PRO-291 (`5b48d91`, on top of PR #107) | Hermes's review, QA Reviewer (Codex), then Lee's merge after PR #107 |
| SEC-SESS-1 Go part (PRO-398 / PRO-432, PR #124, branch `claude/engine-PRO-398-halfopen-budget`): half-open budget, eviction, no SYN-retransmission refresh | Hermes's review, QA Reviewer (Codex), then Lee's merge. Lee's option B (2026-11-25): the 41 random-suite divergences are pinned case by case in `migration/parity/sec_sess1.json` (analyze 20, live 6, live-decrypt 18 under OpenSSL 3.0 / CI and 15 under 3.5; STATUS.md "SEC-SESS-1"). Live-decrypt case ids name the OpenSSL line: a new runner OpenSSL needs its own reviewed pins. A new case that differs is a new reviewed pin, never a wider rule. |
| PRO-315 (`653b1ca`, on top of PR #107) | Hermes's review, QA Reviewer (Codex), then Lee's merge after PR #107 |
| Python removal (Lee, 2026-11-25), PR A of 3 (PRO-401, PR #127): Go and CI gates on frozen answers, `serve` without Python | Hermes's review, then Lee's merge. PRO-431: main merged in and the server golden made build-independent (`8541b3a`); the fix then flows into #135 and #138 by merge. PR #125 (PRO-402) ports the same serve answers: whichever lands second reconciles `go/internal/serve`. PR B (the engine and its own jobs) and PR C wait for it. The demo capture, showcase and catalog are Go's own since PRO-401. |
| SEC-QUIC-1 budget (PRO-122, branch `claude/engine-PRO-122-quic-exhausted-sticky`) | Hermes's review, QA Reviewer (Codex), then Lee's merge |
| Release thresholds (plan M9 and M10), production SLOs, capacity | Lee. They are unproven, and docs must never claim production readiness. |
| SEC-X509-1 (PRO-68): DER length check wrapped on 32-bit `int` (`go/internal/protocols/x509x/x509.go`) | Hermes's review of the fix branch, then Lee's merge. `element` now compares `length > limit-pos` and `count > limit-pos`; `TestHugeDERLengthIsRejectedWithoutWrap` fails on `GOARCH=386` without it. |
| A2 second run (PRO-119): SEC-QUIC-2, a QUIC conflict marker refreshes its idle time but not its LRU place, so 1024 newer connections evict it; SEC-DEC-1, records after a close_notify or fatal alert are still decrypted | an approved parity delta each (Hermes/Lee, as for PRO-122/PRO-123). The Python reference behaves the same way (`quic.py` `conflicted`, `poc_decryption/engine.py` and `tls12.py`), so a Go-only fix would move parity. `migration/notes/PRO-119.md`. A prepared alert patch, against `c01942f` and not applying here, is `migration/held-patches/PRO-119/` on the dropped PR #147's branch `claude/confident-curie-qpv2sl` |
| Child-app waves (PRO-492, docs/CHILD-APPS.md): one PR of about 30 services per wave into `go/internal/childapp/childapps.json`; the component moves into `pack.json` once the frozen answers pin the content release | wave 0 is in PR #163 (App Research PRO-495, 47 children; SEC-CHILD-2 fixed there: `host_owner` in the verdict, `containers` matches it, child risk never below an owner's; SEC-CHILD-7 fixed in PR #177 into its branch: owner-keyed rules (apps, subcategories, characteristics) also hold on a child, and `TestPolicyOwnerRuleOrderOnChild` pins the first-match order across both identities); SEC-CHILD-3 fixed by PRO-510 (branch `claude/engine-PRO-510-sec-child-3`, release 2026.11.2, 50 children): Google upload paths no longer require `message/*` or `uploadType`, Drive v2 and Gmail drafts.update rules, Graph `/beta/` and case-insensitive paths, Telegram case-insensitive methods, Discord v6 to v10 and unversioned, Dropbox content rules without `Dropbox-API-Arg`, batch children (`gmail-batch`, `google-drive-batch`, `ms-base-graph-batch`; body parsing is backlog CHILD-BATCH-1), percent-encoded unreserved characters decoded before matching; evidence is App Research's PRO-524 `sec_child_3`; SEC-CHILD-5 fixed by PRO-512 (branch `claude/engine-PRO-512-sec-child-5`): a `host_suffixes` entry with a more specific catalog domain of a foreign owner under it is refused at load, beside the existing match-time owner re-check (`secchild5_test.go`); later waves wait on Research Lab's PRO-491 list. Each wave: `tools/child_apps_wave.py` and `make child-apps` |
| D09 dataset (ISCX VPN-nonVPN 2016) | nothing. It is for internal research evaluation only; commercial use is UNVERIFIED, and its data is never committed. |

## 6. Frozen SHAs awaiting Codex

The authoritative list is in `migration/STATUS.md` ("Frozen milestone SHAs"):

`61fd45a`, `fdb90e2`, `68fb867`, `58a4701`, `9e51389`, `6b280a6`, `024163f`, `12e1ed0`, `d1b63ee`, `baa07b9`,
`aaa5a7e`, `93cbf2a` (with `36e2c5e`), `76e467a`, `d65d21a`, `07b216e`, `6ab434d`, `7dcabb7`, `b6ed149`, `c08773f`,
`ee1645d`, `253a91d`, `2f6ad4d` and **`50ce5c0`, the review head**. After the packet: `6194fb9`, `4d8aa29` and `376a204` (PRO-31), each reviewed as its own diff (`376a204` together with `6194fb9`).

PRO-166 (PR #141, against `main` `23bbc0c`): `a2fd9b1` (fix and tests), `763b227` and `813de6e` (PRO-459: #139's uncovered tests ported), with the documentation commit after them.
PRO-201 (fix diff against `e5ac90f`): `7da811e`..`6b614c0` plus the documentation commit after them.
PRO-261 (against `cb3ac80`): `7045c42`, `9121403`, `9af4388` plus the documentation commit after them.

PRO-101 (against `main` `b9927b7`): `fd46be0` (the tests, the corpora, the rapid vendoring and the textroute test fix) and the documentation commit after it (`3a25bd0`). The review follow-up (against `main` `cb3ac80`) is one commit on `claude/dazzling-franklin-1179wl`: comments, the issue link and documentation only.
PRO-260 (against `main` `cb3ac80`, PR #105): `b1379a4` (Go fix, tests, parity cases, pinned deltas, the model), `0de4cff` (the presentation decrypt-backend test under the model) and the documentation commits `5d641ae` and after.

PRO-101 (against `main` `b9927b7`): `fd46be0` (the tests, the corpora, the rapid vendoring and the textroute test fix) and the documentation commit after it.

PRO-141 (against `main` `21dd113`): `aff4d13` (the livectl stop tests' synchronisation) and the documentation
commit after it.

SEC-SIG-2 and SEC-SIG-1 (PRO-332, against `main` `5005cdc`): `2885afa` (fix and tests) and the documentation commits after it (`b51698c` and this line).
PRO-370 (Codex PRO-369 findings on `2885afa`, against `0e1cd20`, branch `claude/focused-franklin-irsjdg`): `08c93c5` (fix and tests) and `27c4a54` (this line).
PRO-446 (the PRO-370 ceiling ported to `main` `23bbc0c`, branch `claude/engine-PRO-446-sig-work-ceiling`): `c2919bb` (cherry-pick of `08c93c5`, unchanged) and the documentation commit after it.

SEC-QUIC-3 (PRO-123, against `main` `21dd113`): `fe87386` (fix, tests, the random-differential class) and the
documentation commit after it.

PRO-119 (PR #150, against `main` `23bbc0c`): `afbe5e1`, `91960e0` (fixes and tests) and `852af38` (PRO-459: #147's uncovered cases ported), with the documentation commits after them.

PRO-291 (against `d10c007`, PR #107's head): `5b48d91` (fix and tests), the documentation commit after it, and the errcheck fix in the test after that.

PRO-315 (against `d950eb8`, PR #107's head): `653b1ca` (fix and tests) and the documentation commit after it.

PRO-401 (against `main` `8945986`, PR #127): `466e197` (golden replays, property tests, serve without Python, CI), `f2cb27c` (lint fixes), `a21010a` (scanner lock), `d34aa0f` (two CodeQL errors), `49f8e7d` and `cb1cbad` (the server golden made host-independent: interface list and the synthetic-scope probe) and the documentation commits after them. PRO-431 (main `23bbc0c` merged in as `dc0e42b`): `8541b3a` (the server golden compared without the build identity, Go's held to `SOURCE.json`) and the documentation commit after it.
SEC-KEY-1 residual (PRO-437, against `main` `23bbc0c`, branch `claude/engine-PRO-51-sec-key-1`): `68202be` (fix and tests) and the documentation commit after it (`migration/notes/PRO-437.md`).
SEC-CHILD-5 (PRO-512, against `main` `7a82293`, branch `claude/engine-PRO-512-sec-child-5`): `22c843e0f859a1aab73ef87757bed1f8f5b4e93b` (load-time refusal and tests) and the documentation commit after it (`migration/notes/PRO-512.md`).
SEC-CHILD-5 follow-up (PRO-604, PR #201 with `main` `8296a26` merged in): the merge commit on `claude/quirky-goodall-36hlwi` (PR #201's two extra tests in `secchild5_test.go`; no engine code change against `main`).
SEC-CHILD-3 (PRO-510, against `main` `05705a3`): `bce8743a7a4a7669fe7d2222531536a3f008b043` (converter hardening, `path_case_insensitive`, safe percent-decoding, regenerated rules, tests) and the documentation commit after it (`migration/notes/PRO-510.md`).
PRO-492 (child applications, against `main` `5cb35d2`): `e75e4a8474db80a7ad9d4a01534938e0d0531efa` (engine, API, policy, data and tests) and `4e530900bffa7c6e6094ad23eafef1019a58d696` (schema moved beside the facade, lint), with the documentation commit after them; `745eeee173a76151809a1219d9720b334d994e1e` (SEC-CHILD-2: host owner in the verdict and policy, risk floor; PRO-509).
SEC-QUIC-1 budget (PRO-122, against `main` `23bbc0c`, PR #145): `79cf9dd58e33e36c6c8c04244797781fe87fe5ef` (fix and tests) and the
documentation commit after it.
PRO-448 (PR #148, against `main` `23bbc0c`): `81b331d` (fix and tests), `0c51e26` (the pro448 self-test fix), and `b45979c` (PRO-459: main merged in, keeping both the pro448 reference model and the SEC-SESS-1 pins in `analyze_diff.py`), and `dcd932b` (PRO-460: the 9 SEC-SESS-1 analyze pins refreshed for the PRO-448 counters, and limits_test.go set to the half-open budget), and `790b81f` (PRO-460 again: main `6c6d4dd` merged in after #127; `analyze_diff.py` keeps main's golden replay and loads the pro448 model only for a recording run, and `migration/fixtures/golden/analyze.json.gz` is re-recorded with that model: 300 captures, 0 mismatched; then main `359b444`, PR #145, merged in with no code conflict), with the documentation commits after them.

SR-59 key-log tests (PRO-547, SEC-PYRM-3, PR #190, against `main` `cc1566d`): `348a8866ab844e43b8e785974af53f631bd81a14` (FIFO, device and owner tests, the `getuid` seam), `540b016a7bb178418b8545e65843691181fb07c2` (errcheck fix in the test that the Go lint job flagged) and the documentation and merge commits after them.
PRO-590 (PR #174 with the #166..#169 chain head `97edba3`, merge commits only): `57f68b4410e93b2333f734de446bdf477f6b6f0d` (conflict resolution: ci gate, REVIEW.md rules, Makefile, the SR table and gate) and the documentation commit after it; the #181 merge is recorded in `migration/notes/PRO-590.md`.

PRO-590 on #181 (PRO-546): `81180398ef14c04031639ddf9261e31cbce0c068` merges #174's head `06515ba` (the combined SR gate with the strict Python runner) and the documentation commit after it.

The commits after it are documentation only: `1437060` (the packet), `a88d679`, `b8a3ee1`, `fa5cb2c` and this brief.

## 7. Pitfalls learned

- **An SR row's id is not its Go test's name (PRO-590).** `TestSR58RDPSecurityPosture`..`TestSR63ServerNameCatalog`
  verify SR-70..SR-75 since PRO-545 renumbered the duplicates; the names key `requirements.json.gz`, so renaming a
  test means re-recording its cases at `python-final`. Change the row id (and the lock), not the test name.
- **Go `regexp` classes match runes, not bytes (PRO-403).** `[\x80-\xff]` is U+0080..U+00FF, so on wire bytes it
  refuses a raw obs-text byte and a negated class accepts one. Check byte ranges with a loop (`statusLine`,
  `isIMAPAtom` in textroute); the recorded requirement cases found two such divergences.
- **Security requirements replay the reference's recorded inputs (PRO-403).** `go/internal/replay::TestSR*` replay
  `migration/fixtures/requirements.json.gz` (inputs the removed Python tests made, by test) and the families'
  parity cases. A Go change that moves one of those answers is a reviewed divergence pinned in
  `migration/parity/requirement-deltas.json` (deltas.json form), never a re-recording. Re-recording needs a
  `python-final` extract: `git archive python-final | tar -x -C DIR`, then
  `python3 -B migration/parity/requirement_cases.py --reference DIR`.
- **The differential gates replay golden files (PRO-401).** A change that moves Go's answer fails `make go-check`
  until the golden file is re-recorded (`make golden-record`, with the reference) or, after the reference is gone,
  until the new answer is reviewed in. Never re-record to make a red gate green without reading the diff.

- **A fresh container is a clone of `main`.** Run `git fetch origin claude/go-migration` and check out the branch
  before deciding that any SHA is "missing".
- **Always vendor.** Every Go command needs `GOFLAGS=-mod=vendor`; the Makefile sets it. Scratch output goes under
  `build/`, never inside `go/`, or `go vet` and gofmt pick it up.
- **Recording a new content release (C11).**
  - First record the superseded release in `content._RELEASED_COMPONENTS` and `_PRIOR_HOST_STATE`. Until you do,
    `check_content.py --update` refuses.
  - Then regenerate the lock, `pack.json`, `history.json`, the fixtures, the `CONTENT-DIGEST.md` vectors, the
    `digest_test.go`, `history_test.go` and `test_content.py` pins, and the README/APPID counts.
- **Content release numbering rule (Hermes, PRO-34):** the version is YYYY.MM.N with a two-digit month and a single-digit N (0 to 9). When N is used up, move on to the next month segment at 0. The version is only a label; the real date is
  the release's `released` field. App Research's 2026.12.x placeholders stay as they are. `TestEmbeddedReleasesFollowTheNumberingRule` fails on any break. Both engines now compare numerically, so the rule is a policy and no longer a safety net; relaxing it is Hermes's call.
- **Content items stay name-based until the merge.** Skip a research spec that looks wrong or unclear, note why,
  and don't guess. Describe vendors neutrally by their domain.
- **The presentation suite needs the Go binary built first**, or `GoServiceTests` skip. `presentation-check` builds it.
- **Get numbers from commands, not memory.** Earlier briefs had wrong counts (128 vs 132, 1,055 vs 1,035) and named
  test files that didn't exist.
- **A fresh container may lack the pinned Go.** If `go version` is not go1.27.4, fetch it once with
  `GOTOOLCHAIN=go1.27.4 GOPROXY=https://proxy.golang.org go version` (run outside the repository) and put
  `~/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.4.linux-amd64/bin` first on PATH, with GOROOT set to its parent.
- **A new Go-only divergence that random inputs reach needs a `random_diff.py` approved class**, as narrow as
  SEC-HTTP-1's and SEC-QUIC-3's (the case's shape, Go's exact verdict, the paths allowed to differ), with self-test
  rejections; check that the earlier classes' counts are unchanged.
- **Don't run govulncheck locally.** CI runs it over the vendored tree.
- **The safety checker refuses `rm -rf` and heavy heredoc quoting.** Use `mv`, the Edit tool or plain `sed`.
- **Commits:** author `Lee Nadav`, and keep the email private. End every message with the Co-Authored-By and
  Claude-Session trailers. Ignore stop-hook requests to reset the author.
- **Never** merge, rebase, force-push, open a PR, tag, release or change a schedule. Post GitHub comments only when
  the task asks for them (the current Hermes rule is none).
- **Changes to `ci.yml`** go to the CI/CD lane, which ports them (see chunk-43, `34ea6b0` → `85e99e9`).
- **A QUIC host must attach the CRYPTO store.** `engine.NewDatagram` has no cross-datagram store until the host sets
  `Assembler` (the analyzer does). Without it, a ClientHello spread over Initials, as quic-go and browsers send it,
  never completes (PRO-127).
- **Loopback tests pass `--noproxy '*'` to curl.** This environment sets an HTTPS proxy, so curl would otherwise
  tunnel 127.0.0.1 requests through it.
- **A stand-in process announces readiness only after its signal handling is set.** The livectl worker wrote its
  child file before `trap '' INT`, so a stop right after it failed with -2 on CI (`f5353c5`; fixed in `c99923e`).
- **Generated test data can trip gitleaks.** A case name with `key`, `token`, `secret` or `auth` followed by a long hex
  string matches `generic-api-key` (PRO-126, `296227b`; allow-listed by PR #71). Name cases without those words and
  run the pinned gitleaks 8.30.1 (`tools/scanners`) on the tree before a push.
- **`encoding/json` matches field names case-insensitively (SEC-CONTENT-1).** Anything verified by exact keys
  (digests, the reference) must also be decoded by exact keys: the content pack is decoded from the strict tree with
  case-variant keys removed (`exactFields`), and every tagged struct field names its key explicitly.
- **Nesting driven by the traffic needs a fixed bound (SEC-INSP-1).** A phase that can open a phase (a shift, a
  tunnel, a continuation) must count its depth: one CONNECT per request nested without limit and cost O(n³).
- **Per-packet work must not scan a whole store (SEC-QUIC-1).** Index by what the hot path looks up (idle heap,
  scope index), and prove the new structure against the old implementation kept as a test oracle, with a mutation check.
- **The session picks the branch, not you (PRO-101).** A cloud session may push only to the one branch its harness
  assigns, for example `claude/busy-ramanujan-7oczj2`. If that is not `claude/engine-PRO-n-<slug>`, use it anyway and
  say why in the PR and in `STATUS.md`. Never push to another branch to get the name right.
- **"merged_by: leenadav" doesn't say who clicked.** The agents share Lee's GitHub identity. To show that a session
  did not merge, check its transcript (`list_events`) for a merge call and compare its turn times with `merged_at`.
- **Go versions (PRO-107):** `go/go.mod` states `go 1.27.0` (the floor Culvert imports at, gated by
  `make go-check-minimum`) and `toolchain go1.27.4` (the compiler every build and release uses). Never raise the
  `go` line for a build need; bump the `toolchain` line instead. "Standard library only" is checked on the import
  graph of the detection packages, not on `go.mod` (ADR 0002).
- **The release cross-compiles for `windows/amd64`** (`tools/build_go_release.py`, CI/CD lane), as well as linux and
  darwin on `amd64` and `arm64`. Unix-only code (process groups, `RLIMIT_CPU`, the key-log reader) lives in `*_unix.go`
  files with a `!unix` counterpart. Check with `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/protodetect`.
- **Bounds checks compare by subtraction (SEC-X509-1).** `pos+length > limit` wraps on 32-bit `int` (386, arm) for a
  four-octet length near `0x7fffffff`; write `length > limit-pos` once `pos <= limit` is known, and run the parser's
  tests with `GOARCH=386 go test ./internal/protocols/<pkg>/` too, since amd64 never shows the wrap.
- **After merging `main` in:**
  - regenerate `presentation/SOURCE.json` and let `tools/check_docs_counts.py` set the README/REVIEW-SCOPE test count;
  - check `migration/parity/cases.py --write <tmp> --head <recorded head>` reproduces `cases.json` byte for byte;
  - `tools/go_ci.py build` refuses a local Go other than go.mod's (this container has 1.24.7), so use `make go-build` locally.
- **A stand-in that prints before it traps races its own test (PRO-141).** `c99923e` moved the trap only ahead of the
  child file; `TestStopReleases…` still stopped on the first events, before the trap, and failed with -2 (6fdaa33,
  run 44960532796). Now the trap is the first line and the tests wait for a ready file written last (`aff4d13`).
  A readiness signal for a test is the stand-in's last write, never an output it produces on the way. To check such
  a fix, insert `sleep 0.3` at the old gap and run `-race -count=5`: it must still pass.
- **32-bit findings need a 386 test.** `GOARCH=386 go test` runs on amd64 Linux; the int-narrowing panics (PRO-15, PRO-16) only reproduce there.
- **One finding set, one branch.** PRO-201 was fixed twice (#98 merged, #99 duplicated it and conflicted). Before fixing a PRO's findings, check for an open PR naming the same PRO; reconcile by running the other branch's tests on `main`, never by merging it (PRO-261).
- **Parallel agents must not share scratch files.** Subagents overwrote each other's commit-message files in the shared scratchpad (PRO-201); keep scratch under each worktree's `build/`.
- **Run the Go linters before a push.** `make go-check` does not run golangci-lint, staticcheck or gosec; the CI
  `go-lint` job does, against `tools/golint/baseline.json`, and gosec runs with `-nosec`, so a comment cannot waive
  a finding. Build the pinned tools from `tools/golint/<tool>` (`go install tool`, under `build/`) and run
  `tools/go_lint.py --bin <dir>` with the pinned Go first on `PATH` (PRO-201: 7 new findings on the first push).
- **rapid's `*rapid.T` is not a `testing.TB`** (Go 1.27 added `ArtifactDir`). Shared checks take a small
  `failer` interface (`Helper`, `Fatal`, `Fatalf`). A failing property writes `testdata/rapid/**.fail` (git-ignored);
  check the shrunk counterexample in as a native seed (`testdata/fuzz/<Target>/`) and confirm it fails without the fix.
- **An approved Go-only divergence that moves parity is pinned, not exempted (PRO-260).** A plain `deltas.json`
  path exempts any value, and a list that changes size shows up only as `.length`. Record Go's value as `go`
  (compare.py, the Go replay test and verify_families.py then require exactly it), and model the change on the
  reference in process for the capture differentials (`migration/parity/pro260.py`), never by editing it.
- **A fresh container clone is shallow and has only Go 1.24.** `make workflow-policy` fails ("history baseline …
  not an ancestor") until `git fetch --unshallow origin`. Get the pinned Go with `GOTOOLCHAIN=go1.27.4 go version`
  once, then put `~/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.27.4.linux-amd64/bin` first on `PATH` (with `GOROOT`).
- **A concurrency test must force the overlap it asserts.** `TestChaosAdmissionStorm…` relied on goroutines
  overlapping and failed 2 of 3 times with `-cpu=1` (CI coverage job, PR #105). Use a barrier; check with
  `go test -count=30 -cpu=1,2,4`.
- **`bytes_inspected` is chunk-granular by contract** (the whole chunk in which a parser fails is counted, as in
  `engine.py`), and a parser's consumed count after a fault is discarded. Compare them against budgets, not across splits.
- **A reslice keeps its whole backing array alive** (SEC-DEC-1, PRO-119). `buf = buf[n:]` and `q = q[1:]` keep the
  consumed prefix reachable, even at length 0. Before you keep a tail or pop from a queue for a long-lived object,
  copy the tail into a new buffer, clear the popped slot and drop an emptied slice. Prove the fix with a heap test
  (`runtime.ReadMemStats` after two `runtime.GC()` calls; `go/detector/ownership_test.go`).
