# Merge readiness: `claude/go-migration` into `main` (documentation only)

Written 2026-11-18 at branch head `baa07b9` against `origin/main` `b79e447`. Nothing here merges, rebases,
opens a pull request or changes history: whether and when to merge is Lee's decision (AGENTS.md), and the
review of the frozen snapshots is Codex's. The draft pull-request text is `migration/PR-DRAFT.md`.

## Where the two branches stand

| | |
|---|---|
| Merge base | `c121ada` (main's merge of PR #19, the earlier state of this branch) |
| This branch since the base | 67 commits, 194 files, about +413,000 / −3,300 lines (most of it the regenerated fixtures `migration/fixtures/cases.json`, `content.json`, `go/internal/content/history.json`) |
| `main` since the base | 11 commits, 21 files, +605 / −135 lines: PR #25 (Codex's reference fix R1–R3, `e8830db`), PR #27 (README rewrite, `b7b98ac`), PR #28 (CI/CD lane: the Go minimum-version job, `c58fe65`), two Dependabot bumps (actions group, Playwright) |
| Trial merge | `git merge-tree --write-tree HEAD origin/main` (no ref changed): **7 files conflict**, everything else merges cleanly |

### Conflicts today (trial merge)

| File | Hunks | Nature | Owner | Resolution |
|---|---|---|---|---|
| `.github/workflows/ci.yml` | 1 | comment block of the Go job: this branch lists the extra gates (parity-analyze, parity-decrypt, ...), main adds the toolchain-line rule and `GOPROXY=off` | CI/CD lane | keep main's wording and add this branch's gate list; see the `GOPROXY=off` blocker below |
| `Makefile` | 1 | `.PHONY` line: this branch's new targets vs main's `go-check go-check-minimum parity-go` | engine (Makefile) with CI/CD | union of both lists; check that main's `go-check-minimum` target body merged and runs |
| `README.md` | 3 | main's README rewrite (PR #27, PR #25 counts) vs this branch's counts and rows | engine | take main's structure, then the current numbers (`tools/check_docs_counts.py` decides) |
| `REVIEW-SCOPE.md` | 1 | test count: 856 here, 833 on main | engine | regenerate from the merged tree's count (856 plus main's new tests) |
| `SSDLC.md` | 1 | the CI job table: main adds the "declared minimum Go" row | CI/CD lane | keep both rows |
| `presentation/SOURCE.json` | — | generated build manifest | engine | regenerate: `python3 -B tools/build_manifest.py --write presentation/SOURCE.json` |
| `tools/workflows.lock.json` | — | generated workflow lock | CI/CD lane | regenerate with the CI/CD lane's tool after `ci.yml` is resolved |

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
2. **`GOPROXY=off` in main's Go jobs vs this branch's module dependency (blocker).** `go/go.mod` here requires
   `golang.org/x/crypto v0.59.0` (key-log TLS decryption, `4111a70`, after the earlier merge); main's CI
   (`c58fe65`, `tools/go_ci.py`) runs the Go jobs with `GOPROXY=off` on the premise that "the engine has no
   module dependency". Merged as is, the Go jobs cannot fetch the module. Options for the two lanes (a CI/CD
   and engine decision, raised to Codex rather than decided here): vendor the dependency (`go mod vendor`,
   reviewed like code), allow the module proxy for that one module, or a pre-populated module cache in CI.
3. **Test and fixture counts** move on both sides (README, REVIEW-SCOPE, `check_docs_counts.py`): resolve them
   from the merged tree, not by hand-picking a side.
4. **Dependabot bumps** (actions group, Playwright in `tools/ui-test-deps`) merge cleanly; `make pin-drift`
   and the workflow lock must agree after the merge.

## What is done (branch head `baa07b9`)

- **Go engine at parity with the Python reference on every committed case**: `make parity-go` 7,404 of 7,404
  (stream 5,253, datagram 1,122, session 1,029), records included, 0 gaps, 0 approved deltas.
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
- **Content**: release 2026.11.3 (research batch A, `baa07b9`); earlier releases reproduce their published
  digests (C11, `d1b63ee`); `--content-version` rollback in both engines.
- **Contracts C1–C18**: all `experimental` with Go evidence (migration/CONTRACTS.md); none is claimed
  complete.

## What is verified, and by whom

| Evidence | Status |
|---|---|
| Local gates at `baa07b9`: `make check` (856 Python tests, content, docs counts, manifest, coverage matrix, security requirements, policy lint, workflow policy) and `make go-check` (gofmt, vet, race tests, fuzz smoke, every differential above) | passed, this host |
| Hosted CI on the branch | applies to the commits each run contains; check the run for `baa07b9` before merging |
| Independent review (Codex) | **pending** for every snapshot listed below; a missing review, green CI or a merged PR is never approval (AGENTS.md) |
| govulncheck | runs in CI (M10); not run locally by rule |

## Frozen snapshots awaiting Codex (from Sunday)

`61fd45a` (Milestone A), `fdb90e2` (Culvert-aligned performance gates), `68fb867` (Go live control plane and
dashboard service), `58a4701` (launcher switch, Milestone B), `9e51389` (one generation counter per capture,
family verification, container signature descriptions, content-version rollback), `6b280a6` (adversarial
suite, load benchmark), `024163f` (coverage cases: 88 of 88 parity-verified), `12e1ed0` (CoAP profile per RFC
7252 in both engines, F-ADV-1), `d1b63ee` (C11: earlier releases keep their published digests), `baa07b9`
(content 2026.11.3, research batch A), `aaa5a7e` (this document), `93cbf2a` (signature repeat counts 1001..4096 in
Go; `36e2c5e`, the presentation suite rebuilds the Go binary first). The list is kept in migration/STATUS.md.

## Known open items

- **D09, independent labelled corpus**: blocked on input (no independent corpus); release thresholds that
  depend on it stay unproven. Not a merge blocker by itself, a release blocker.
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
- [ ] The `GOPROXY=off` / `x/crypto` question settled between the lanes (vendor, proxy exception or cache).
- [ ] Conflicts resolved as in the table, on a merge commit (no rebase, no force-push), CI/CD-owned files by
      the CI/CD lane.
- [ ] After the merge: `cases.json` regenerated from the merged reference; `make check` and `make go-check`
      green; `make parity-go` 0 differences; docs counts and manifest regenerated.
- [ ] Hosted CI green on the merge head, including main's `go-check-minimum` job.
- [ ] D09 and F-ADV-1 acknowledged as open (release, not merge, blockers).
- [ ] Lee's decision to merge; no deployment follows from it.
