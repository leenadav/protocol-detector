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

- **Python** (`protocol_engine/`, `protocol_adapters/`) stays as the reference and the fallback.
- **Go** (`go/`) is judged against Python by the parity gates.
- **The lane owns** `go/`, `migration/`, the product code (`protocol_engine/`, `protocol_adapters/`, `presentation/`),
  the content data and the `Makefile`.
- **Python detection code is read-only.** The only exceptions are ones Lee approves case by case; they are listed in `migration/STATUS.md` ("Frozen-Python exceptions").
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
- **Parity:** 7,462 of 7,462 cases agree (18 of them through PRO-260's pinned Go-only deltas). 79 of 88 families are parity-verified since PRO-201 (`098b201`): the verifier no longer credits a replay of the positive message as foreign bytes, so ftp, http, imap, nats, pop3, rtsp, sip, smtp and ssh are `experimental` until real foreign cases are added. Server parity: 424 exchanges, 0
  differences. The adversarial suite (4,041 cases) passes.
- **Content release:** 2026.11.9 (digest `cdaa5993077d101a`), with 544 applications and 442 host entries. Every earlier
  release reproduces the digest it was published with (C11).
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
- **Merged:** PR #40 brought `claude/go-migration` into `main` on 2026-11-22. Engine work now branches from `main`.
- **PRO-141 (livectl stop flake):** the stand-in worker sets its INT trap first and writes a ready file last; the
  three stop tests wait for it (`aff4d13`, branch `claude/vigilant-meitner-t7kw7h`). 200 of 200 under `-race`, also
  with 8 spinning loops on 4 CPUs. Root cause from PRO-140: the test, not `Manager.Stop`.

### Recent work (generated)

Written by `tools/build_ledgers.py` from `migration/notes/PRO-<n>.md`, newest first. Never edit it: a task adds
its own notes file, and the section is refreshed after merge.

<!-- BEGIN GENERATED: recent-work lane=engine limit=15 -->
<!-- tools/build_ledgers.py writes this section from migration/notes/PRO-<n>.md. Do not edit it: add a notes file instead (migration/notes/README.md). -->

_No notes for this lane yet._
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
8. `migration/CONTENT-DIGEST.md` and `protocol_engine/content.py`: the content releases and the C11 rule.
9. `migration/adr/`: ownership, toolchain and dependency decisions.

## 4. How to verify

Run everything from the repository root. Times are for the cloud container (4 vCPU):

| Command | What it checks | Runtime |
|---|---|---|
| `make go-check` | gofmt, vet, `go test -race`, 28 fuzz targets, parity-go with verify_families, every differential, bench-gate | about 8 min (488 s) |
| `make check` | the Python suite (866 tests), content, docs counts, manifest, presentation, parity | about 1 min (60 s) |
| `make parity-random` (in `go-check`) | the randomized differential: `--self-test`, `--plant`, then seed 1 at 2,000 cases, with the Python reference as oracle (`migration/parity/random_diff.py`, allow-list `random_allow.json`). `make parity-random-long SEED= COUNT=` for longer runs | about 3 s |
| `make pcap-oracle` (nightly, not in `go-check`) | the tshark oracle (`go/oracle`, its own test-only module): real OpenSSL, curl and quic-go traffic on 127.0.0.1, read by gopacket, fed to the engine and compared with tshark 4.2.2 on SNI, ALPN, TLS version, HTTP Host and QUIC version. It needs the pinned tshark, OpenSSL and curl (`go/oracle/README.md`). Allow-list: `go/oracle/allow.json` | about 3 s |
| `make mutation` (nightly, not in `go-check`) | gremlins v0.6.0 on the nine parser packages against `migration/mutation/baseline.json` (fails on a drop of more than 5 points). `go-check` runs only `boundaries.py --check` and `mutation.py --self-test`. Regenerate the boundary tests with `python3 -B migration/mutation/boundaries.py` | about 20 min |
| `make go-vendor-check` | re-vendors into `build/go-vendor-check` and diffs it against `go/vendor` | seconds (module cache warm) |
| `python3 -B -m unittest discover -q` | the Python suite on its own | part of `make check` |

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
| SEC-QUIC-3 (`fe87386`, PR into `main`) | Hermes's review, QA Reviewer (Codex), then Lee's merge |
| PRO-291 (`5b48d91`, on top of PR #107) | Hermes's review, QA Reviewer (Codex), then Lee's merge after PR #107 |
| PRO-315 (`653b1ca`, on top of PR #107) | Hermes's review, QA Reviewer (Codex), then Lee's merge after PR #107 |
| Not yet ported: demo capture, decryption showcase, catalog export | they still run as Python workers (`--python`). Nothing is scheduled. |
| Release thresholds (plan M9 and M10), production SLOs, capacity | Lee. They are unproven, and docs must never claim production readiness. |
| SEC-X509-1 (PRO-68): DER length check wrapped on 32-bit `int` (`go/internal/protocols/x509x/x509.go`) | Hermes's review of the fix branch, then Lee's merge. `element` now compares `length > limit-pos` and `count > limit-pos`; `TestHugeDERLengthIsRejectedWithoutWrap` fails on `GOARCH=386` without it. |
| D09 dataset (ISCX VPN-nonVPN 2016) | nothing. It is for internal research evaluation only; commercial use is UNVERIFIED, and its data is never committed. |

## 6. Frozen SHAs awaiting Codex

The authoritative list is in `migration/STATUS.md` ("Frozen milestone SHAs"):

`61fd45a`, `fdb90e2`, `68fb867`, `58a4701`, `9e51389`, `6b280a6`, `024163f`, `12e1ed0`, `d1b63ee`, `baa07b9`,
`aaa5a7e`, `93cbf2a` (with `36e2c5e`), `76e467a`, `d65d21a`, `07b216e`, `6ab434d`, `7dcabb7`, `b6ed149`, `c08773f`,
`ee1645d`, `253a91d`, `2f6ad4d` and **`50ce5c0`, the review head**. After the packet: `6194fb9`, `4d8aa29` and `376a204` (PRO-31), each reviewed as its own diff (`376a204` together with `6194fb9`).

PRO-201 (fix diff against `e5ac90f`): `7da811e`..`6b614c0` plus the documentation commit after them.
PRO-261 (against `cb3ac80`): `7045c42`, `9121403`, `9af4388` plus the documentation commit after them.

PRO-101 (against `main` `b9927b7`): `fd46be0` (the tests, the corpora, the rapid vendoring and the textroute test fix) and the documentation commit after it (`3a25bd0`). The review follow-up (against `main` `cb3ac80`) is one commit on `claude/dazzling-franklin-1179wl`: comments, the issue link and documentation only.
PRO-260 (against `main` `cb3ac80`, PR #105): `b1379a4` (Go fix, tests, parity cases, pinned deltas, the model), `0de4cff` (the presentation decrypt-backend test under the model) and the documentation commits `5d641ae` and after.

PRO-101 (against `main` `b9927b7`): `fd46be0` (the tests, the corpora, the rapid vendoring and the textroute test fix) and the documentation commit after it.

PRO-141 (against `main` `21dd113`): `aff4d13` (the livectl stop tests' synchronisation) and the documentation
commit after it.

SEC-QUIC-3 (PRO-123, against `main` `21dd113`): `fe87386` (fix, tests, the random-differential class) and the
documentation commit after it.

PRO-291 (against `d10c007`, PR #107's head): `5b48d91` (fix and tests), the documentation commit after it, and the errcheck fix in the test after that.

PRO-315 (against `d950eb8`, PR #107's head): `653b1ca` (fix and tests) and the documentation commit after it.

The commits after it are documentation only: `1437060` (the packet), `a88d679`, `b8a3ee1`, `fa5cb2c` and this brief.

## 7. Pitfalls learned

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
