# Merge readiness: `claude/go-migration` into `main` (documentation only)

Written 2026-11-18; refreshed at branch head `7dcabb7` against `origin/main` `b79e447`, and again on 2026-11-19 at
`1437060` against `origin/main` `ddc557d` (PR #30 and PR #31 merged; this branch 87 commits ahead, 21 behind). The trial
merge (`git merge-tree --write-tree`) still conflicts on the same 7 files with the same hunk counts (the Makefile 2), so the
plan below stands. `main`'s Makefile still has no `-mod=vendor`; its CI tool sets `GOFLAGS=-mod=vendor` in the job
environment when `go/vendor` exists, so the merge keeps this branch's explicit flags. Nothing here merges, rebases,
opens a pull request or changes history: whether and when to merge is Lee's decision (AGENTS.md), and the
review of the frozen snapshots is Codex's. The draft pull-request text is `migration/PR-DRAFT.md`.

## Where the two branches stand

| | |
|---|---|
| Merge base | `c121ada` (main's merge of PR #19, the earlier state of this branch) |
| This branch since the base | 77 commits (at `7dcabb7`), now including `go/vendor`, 194+ files, about +413,000 / −3,300 lines (most of it the regenerated fixtures `migration/fixtures/cases.json`, `content.json`, `go/internal/content/history.json`) |
| `main` since the base | 11 commits, 21 files, +605 / −135 lines: PR #25 (Codex's reference fix R1–R3, `e8830db`), PR #27 (README rewrite, `b7b98ac`), PR #28 (CI/CD lane: the Go minimum-version job, `c58fe65`), two Dependabot bumps (actions group, Playwright) |
| Trial merge | `git merge-tree --write-tree HEAD origin/main` (no ref changed): **7 files conflict**, everything else merges cleanly |

### Conflicts today (trial merge at `7dcabb7`) and the resolution plan

The same 7 files as at `baa07b9`; the Makefile now has 2 hunks (the vendoring added the second). Resolve on one
merge commit of `main` into this branch (no rebase, no force-push); the CI/CD lane resolves its own files.

| # | File | Hunks | What each side changed | Owner | Resolution plan |
|---|---|---|---|---|---|
| 1 | `.github/workflows/ci.yml` | 1 | the Go job's comment block: here the list of extra gates (parity-analyze, parity-decrypt, ...); main the toolchain-line rule and `GOPROXY=off` | CI/CD lane | keep main's text, including `GOPROXY=off`, and add this branch's gate list. Add one step that runs `make go-vendor-check` where the modules can be reached (module cache or proxy); every other Go step stays offline |
| 2 | `Makefile` | 2 | hunk 1, `.PHONY`: this branch's targets (go-build, parity-*, schema-go, bench-gate, adversarial, bench-load, go-vendor-check) vs main's `go-check go-check-minimum parity-go`. Hunk 2, the Go block: here the vendoring note and `go-vendor-check`; main the `toolchain`-line `GO_TOOLCHAIN`, `GO_MINIMUM` and `go-check-minimum` | engine, with the CI/CD lane | hunk 1: the union of both lists. Hunk 2: take main's `GO_TOOLCHAIN`/`GO_MINIMUM` definitions and `go-check-minimum`, add `GOFLAGS=-mod=vendor` to both of its commands (without it, it fails under `GOPROXY=off` just like the build), and keep `go-vendor-check` and its note. Then `make go-check`, `make go-check-minimum` and `make go-vendor-check` |
| 3 | `README.md` | 3 | main's rewrite (PR #27) and PR #25's counts vs this branch's counts and table rows | engine | take main's structure, re-apply this branch's rows (Go default backend, content 2026.11.5), and let `tools/check_docs_counts.py` set the numbers on the merged tree |
| 4 | `REVIEW-SCOPE.md` | 1 | test count: 856 here, 833 on main | engine | the merged tree's count: 856 plus main's new tests in `test_continuation.py` and `test_quic_isolation.py`, as `check_docs_counts.py` reports it |
| 5 | `SSDLC.md` | 1 | the CI job table: main adds the "declared minimum Go" row | CI/CD lane | keep both rows; mention the vendor check in the Go engine row |
| 6 | `presentation/SOURCE.json` | 2 | generated build manifest, both sides regenerated it | engine | do not hand-merge: `python3 -B tools/build_manifest.py --write presentation/SOURCE.json` on the merged tree |
| 7 | `tools/workflows.lock.json` | 1 | generated workflow lock | CI/CD lane | regenerate with the CI/CD lane's tool after `ci.yml` is resolved |

Auto-merged but needing attention: `protocol_adapters/analyze_pcap.py` and `protocol_engine/continuation.py`
(main's R1–R3 reference fix), `tools/go_ci.py` and `tools/check_go_drift.py` (main's minimum-Go mode),
`SECURITY-REQUIREMENTS.md`, `test_continuation.py`, `test_quic_isolation.py`.

### Divergence that is not a textual conflict

1. **Main's reference fix R1–R3 (`e8830db`) is not on this branch's Python, but the Go engine already
   implements all three** (STATUS.md, "Codex PR #25 findings"): R1 in `session.Tracker` (UDP invalidation
   withdraws the retained peer evidence), R2 in `analyzer.udpSession` (both ordered QUIC scopes reset), R3 in
   `textroute/continuation.go` (no-body statuses before CL/TE). The merge brings the reference up to Go. After
   the merge `migration/fixtures/cases.json` must be regenerated from the merged reference and `make
   parity-go` must still report 0 differences; any case that changes is one where the branch's Python and Go
   disagreed without a committed case showing it.
2. **`GOPROXY=off` in main's Go jobs vs this branch's module dependency: resolved by vendoring** (Hermes's
   decision, 2026-11-18; `76e467a`, `d65d21a`). `go/go.mod` requires `golang.org/x/crypto v0.59.0` (key-log TLS
   decryption, `4111a70`, after the earlier merge), and main's CI (`c58fe65`, `tools/go_ci.py`) runs the Go jobs
   with `GOPROXY=off`. Of the three options (vendor, a proxy exception for the module, a pre-populated module
   cache) vendoring is the one that keeps CI's rule intact: the code that is built is in the repository,
   reviewed and diffed like ours, and no build or test fetches anything. `go mod vendor` vendors only the packages
   the engine imports (x/crypto chacha20, chacha20poly1305, internal/alias, internal/poly1305; x/sys/cpu: 80
   files, about 670 KB). Every Go command in the Makefile runs with `GOFLAGS=-mod=vendor`, and `gofmt` skips
   `go/vendor`. `make go-vendor-check` re-vendors into `build/go-vendor-check` and fails when `go/vendor` is not
   what `go.mod` and `go.sum` select or has uncommitted changes; it is the one step that needs the modules, so CI
   runs it where they can be reached (the CI/CD lane has been told to expect `-mod=vendor`). Checked: with
   `GOPROXY=off` and a module cache holding only the toolchain, the vendored build and the decryption tests
   pass, and the same build with `-mod=mod` fails with "module lookup disabled by GOPROXY=off". Updating the
   dependency is now `go get` + `go mod vendor` + review of the vendored diff.
3. **Test and fixture counts** move on both sides (README, REVIEW-SCOPE, `check_docs_counts.py`): resolve them
   from the merged tree, not by hand-picking a side.
4. **Dependabot bumps** (actions group, Playwright in `tools/ui-test-deps`) merge cleanly; `make pin-drift`
   and the workflow lock must agree after the merge.

## What is done (branch head `7dcabb7`)

- **Go engine at parity with the Python reference on every committed case**: `make parity-go` 7,410 of 7,410
  (stream 5,253, datagram 1,122, session 1,035), records included, 0 gaps, 0 approved deltas.
- **All 88 families `parity-verified`**, computed from the evidence (`migration/parity/verify_families.py`:
  exact match, four case classes per transport, a session case for TCP families).
- **Capture-level differentials**, all 0 differences: parity-analyze, parity-decrypt, parity-live,
  parity-live-decrypt, schema-go, parity-control (live control plane), parity-server (dashboard service).
- **Adversarial suite**: 4,041 cases, Go equals the reference on all; one known finding (F-ADV-1, below).
- **Performance**: `make bench-gate` (allocations and retained bytes gated, p99 per flow reported, Lee
  2026-11-17); `make bench-load` reported only (STATUS.md "Throughput under load").
- **Fuzzing**: 25 Go fuzz targets in `make go-check`; the Python seeded fuzz in `make check`.
- **Default backend**: Go wherever the binary is installed (adapters, presentation, launcher `24e410e`);
  `--backend python` / `PROTODETECT_BACKEND=python` keep the reference.
- **Content**: release 2026.11.5 (research batches A `baa07b9`, B `6ab434d`, B2 `7dcabb7`; 540 applications, 438
  host entries); earlier releases reproduce their published digests (C11, `d1b63ee`), so batches B and B2
  re-pinned nothing; `--content-version` rollback in both engines.
- **Dependencies**: `golang.org/x/crypto` vendored, every Go build and test offline with `-mod=vendor`
  (`76e467a`, `d65d21a`); `make go-vendor-check` guards the vendor tree.
- **Contracts C1–C18**: all `experimental` with Go evidence (migration/CONTRACTS.md); none is claimed
  complete.

## What is verified, and by whom

| Evidence | Status |
|---|---|
| Local gates at `7dcabb7`: `make check` (856 Python tests, content, docs counts, manifest, coverage matrix, security requirements, policy lint, workflow policy) and `make go-check` (gofmt, vet, race tests, fuzz smoke, every differential above) | passed, this host |
| Hosted CI on the branch | applies to the commits each run contains; check the run for the merge candidate before merging |
| Independent review (Codex) | **pending** for every snapshot listed below; a missing review, green CI or a merged PR is never approval (AGENTS.md) |
| govulncheck | runs in CI (M10); not run locally by rule |

## Frozen snapshots awaiting Codex (from Sunday)

`61fd45a` (Milestone A), `fdb90e2` (Culvert-aligned performance gates), `68fb867` (Go live control plane and
dashboard service), `58a4701` (launcher switch, Milestone B), `9e51389` (one generation counter per capture,
family verification, container signature descriptions, content-version rollback), `6b280a6` (adversarial
suite, load benchmark), `024163f` (coverage cases: 88 of 88 parity-verified), `12e1ed0` (CoAP profile per RFC
7252 in both engines, F-ADV-1), `d1b63ee` (C11: earlier releases keep their published digests), `baa07b9`
(content 2026.11.3, research batch A), `aaa5a7e` (this document), `93cbf2a` (signature repeat counts 1001..4096 in
Go; `36e2c5e`, the presentation suite rebuilds the Go binary first), `76e467a` and `d65d21a` (x/crypto vendored,
`-mod=vendor`, `go-vendor-check`), `07b216e` (parity-server id canonicalization), `6ab434d` (content 2026.11.4,
batch B), `7dcabb7` (content 2026.11.5, batch B2). The list is kept in migration/STATUS.md.

## Known open items

- **D09, independent labelled corpus**: no longer blocked. The dataset is decided: ISCX VPN-nonVPN 2016, internal
  research evaluation only, with no redistribution, no data committed and no commercial right claimed (commercial use
  stays `UNVERIFIED`; non-commercial or academic-only datasets are excluded). The first measurement is done
  (`research/d09-iscx-vpn2016.md`, engine `2fd9452`: 63 scorable captures, 41 correct, 1 wrong, 14 unknown, 7
  background). Its findings are detection changes, so they are post-merge, Go-only items in
  `migration/POST-MERGE-BACKLOG.md` (PM-1..PM-7). They are tracked work, not merge blockers.
- **F-ADV-1 residual**: after the RFC 7252 tightening, 6 of 20,000 seeded random datagrams (0.030%, from
  0.200%) and 1 of the suite's 2,000 still pass as CoAP; they conform structurally. Listed in
  `NOISE_FINDINGS`, documented in PROTOCOLS.md.
- **Reference findings left as they are** (STATUS.md): syslog fraction digits differ between Python 3.9 and
  3.11+; `LiveManager.ingest` lets an `IndexError` end the reader; interpreter-specific texts; a worker child
  holding the output pipe. Go behaves as documented in each row.
- **Still answered by the reference**: signature patterns outside RE2 (inline flags, atomic groups, possessive
  repeats, a non-final `$`; repeat counts up to the rules' 4096 are answered by Go since `93cbf2a`); an external `--content` pack combined
  with `--content-version` (Go declines, exit 64).
- **Batch A follow-ups for the research lane**: `notebook.google.com` skipped (no source that it is
  NotebookLM); `www.` names of the Dropbox web fronts are not mapped (web fronts are exact names).
- **Gate ordering**: fixed in `36e2c5e` (the presentation suite rebuilds an existing Go binary first).
- **Production claims**: none. SLOs, capacity, soak at production scale and end-to-end SWG latency are out of
  this repository's evidence (AGENTS.md "Intended limits").

## Checklist before Lee decides

- [ ] Codex results for the frozen snapshots above (issue #2), findings fixed in later SHAs and recorded.
- [x] The `GOPROXY=off` / `x/crypto` question: vendored (Hermes, 2026-11-18; `76e467a`). CI side done by the
      CI/CD lane on `claude/cicd-next` `5442d05` (draft PR #30, not merged): a `go-vendor` job runs `make
      go-vendor-check` with module access (the only Go step with network); the tests (3.9/3.11/3.13) and
      presentation jobs build the Go binary offline first, so `GoServiceTests` runs instead of being skipped;
      `go_ci.py` sets `GOFLAGS=-mod=vendor` whenever `go/vendor` exists, which also covers main's
      `go-check-minimum`. Hosted evidence: probe `claude/cicd-engine-probe` `407bfcc` (`12fbc0e` plus those CI
      files), run 44388423818 green. PR #30 is merged into `main` (`7146ce1`); this branch's own CI stays red on the presentation step until `main` is merged in.
- [ ] Conflicts resolved as in the table, on a merge commit (no rebase, no force-push), CI/CD-owned files by
      the CI/CD lane.
- [ ] After the merge: `cases.json` regenerated from the merged reference; `make check` and `make go-check`
      green; `make parity-go` 0 differences; docs counts and manifest regenerated.
- [ ] Hosted CI green on the merge head, including main's `go-check-minimum` job (with `-mod=vendor`) and the
      vendor check.
- [ ] F-ADV-1's residual and the D09 findings (POST-MERGE-BACKLOG.md) acknowledged as post-merge work.
- [ ] Lee's decision to merge, after Codex's review on Sunday (this branch and the CI/CD lane's PR #30); no
      deployment follows from it.
