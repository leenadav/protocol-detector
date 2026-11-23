# Drift of the Culvert integration package against the current engine (2026-11-21, PRO-91)

What happens when the lane's public package meets the engine lane's current tree. This is measured in a
throwaway merge, not done on any branch: nothing was merged, rebased or pushed.

| | Commit |
|---|---|
| Lane head | `claude/culvert-integration-prep` `3efda9224bd87eb56ee4224ca10b4b5f5793a440` (39 ahead, 148 behind the engine) |
| Engine head | `claude/go-migration` `0081f6f94d50ac12183221ff99c35f79973ab4a5` (PR #40) |
| Throwaway tree | a local worktree of `3efda92` with `git merge origin/claude/go-migration`, conflicts resolved as below, never committed |
| Culvert lab | local branch `lab/protocol-detector-ef94311` `8a50573c` on Culvert `ef94311` |

Toolchain go1.27.4, on the cloud container (4 vCPU, shared).

## 1. Merge conflicts: 23 files

**Taken from the engine side** (files other lanes own, or data):
- `.github/workflows/ci.yml`, `.gitignore`, `AGENTS.md`, `Makefile`, `README.md`, `REVIEW-SCOPE.md`;
- `go/go.mod`;
- `go/internal/content/pack.json` (182 hunks), `digest.go`, `content.go`, `embedded_test.go`;
- `migration/CONTENT-DIGEST.md`, `migration/STATUS.md`, `migration/fixtures/cases.json`;
- `presentation/SOURCE.json`;
- `tools/check_go_drift.py`, `tools/go_ci.py`, `tools/workflows.lock.json`.

**Resolved by hand, with semantic conflicts underneath:**

| File | Lane side | Engine side | Throwaway choice |
|---|---|---|---|
| `go/internal/protocols/tlsx/tls.go` | memory `Credit`, `RetainedBytes` | record-layer continuation, certificate watch, `Refined` | both. The engine's new buffers are not charged to the credit. |
| `go/internal/protocols/textroute/ssh.go` | KEXINIT lists copied through the credit | lists kept as sub-slices of the packet buffer | lane |
| `go/internal/protocols/textroute/http.go` | target copied through the credit; Upgrade kept as a closed token | target as a sub-slice; Upgrade as a copy; `ascii.Upper`/`Lower` | lane, with the engine's `ascii` helpers |
| `go/internal/engine/inspector.go` | private `ported` registry (#15) | `signatures` import, heuristics and retain-contexts now ported, exported `Ported` | engine, using the private name |
| `go/internal/engine/datagram.go` | `framed.DatagramValidatorFor` (#15) | QUIC and DTLS validation | engine, through the accessor |

**Needed after the merge, with no textual conflict:**
- `go/internal/content/embedded.go`: both lanes embed the pack (#16). The engine's `Embedded()` in `content.go` collides with the lane's, so the lane's pin had to sit on the engine's `embedded` variable, as `EmbeddedPinned()`.
- `go/cmd/protodetect/{analyze,live}.go`: four uses of the exported `engine.Ported`, which #15 made private, moved to `engine.IsPorted` and `engine.PortedNames`.
- `gofmt` on the two hand-merged files.

After that the tree builds, and `go vet` is clean.

## 2. Test failures on the merged tree

`go test ./...`, and `make go-check` with `-race`: **35 packages pass, 5 fail.** `go/consumertest` does not build.

| Failure | Cause | Owner |
|---|---|---|
| `go/consumertest`: `module ../ requires go >= 1.27.4 (running go 1.27.0)` | the engine's `go/go.mod` says `go 1.27.4` | **decision**: plan item #3 promises Culvert a minimum of 1.27.0 |
| `TestModuleIsStandardLibraryOnly` | `require golang.org/x/crypto v0.59.0` (vendored, with `x/sys`) | resolved by rule (a), PRO-107 and PRO-151: the test is now `TestDetectorImportsStandardLibraryOnly` and checks the import graph of `go/detector`, which passes on the merged tree |
| `TestNoPackageExportsAMutableRegistry` | new exported `livedecrypt.ErrorCodes`, `x509x.WeakSignatures`, `signatures.Contexts` | engine, or this lane's allow-list |
| `TestProfileEvidenceFieldsAreClassified` | new HTTP evidence fields `http_host_variation`, `http_messages`, `http_methods` | this lane: classify them |
| `TestProfileOutcomes` | HTTP/2 is ported now: `outside_profile` where the test expects `unsupported` | this lane: test expectation |
| `TestOtherRetainedStatesAreCovered` | live heap is above the reported retained figure: long target 14,192 B against 12,297 B; Upgrade 4,960 B against 3,080 B | engine and this lane: buffers that are not counted |
| textroute `TestRetainedBuffersGrowOnlyFromTheCredit` | stream 470 retains 280 B after a call that charged 32 | engine and this lane: the engine's new text-route buffers bypass the credit |
| textroute `TestContinuationIsRefused`, tlsx `TestOptionsTheParserLacksAreRefused` | continuation, fingerprints and certificates are ported now | this lane: obsolete tests |
| tlsx `TestFixturesAreSplitInvariant` | "only 20 fixtures completed a hello": the fixture labels changed | this lane: test selector |
| content pin tests (3) | release 2026.11.9 has pack digest `b05065ebb142d917053ff0999e9c1cde5a762208d36368a59fb9f369e8dc2754`, not the lane's pinned one | this lane: update `EmbeddedPackDigest` with the pack |
| content `TestNoCodeOutsideThePackageWritesAValidatedPack` | `internal/livedecrypt` has build-tagged platform files, and the test type-checks every file regardless of tags (`KeyLog redeclared`) | **this lane: defect in the test** (it must filter files by build constraints) |
| replay `TestPortedFamiliesMatchThePythonReference` | 7 mismatches: `tls-23-server12-unknown-ext` and `tls-27-server13-bad-group` (whole, bytes, sevens) and `datagram/036-dtls/mutated` report encryption where the reference has none; 27 stream results unported | engine and this lane: both changed `tlsx` |

## 3. Lab on the merged tree

The lab binary was built from the throwaway tree (workspace `go 1.27.4`, since the module requires it) and run with
`LAB_CULVERT_BASE=ef94311 tools/start-lab-visibility.sh`:
- **74 of 74 observation checks passed** on builds A to E;
- byte identity held on all 7 hashed scenarios;
- **no cell differs** from the run against detector `0aa53ac`.

The public package's API did not drift: the lab adapter compiled unchanged.

## 4. Allocations per flow

Two different quantities, both valid. The lane's earlier "191 allocations per flow" is the first; Research Lab's
figures (PRO-82) are the second.

**A. Whole flow through the public package** (`go/detector`): `NewFlow`, the client and server flights, `Close`.
Command: `cd go && go test -run NONE -bench 'BenchmarkFlow$' -benchtime 3000x -count 5 ./detector`. All five runs
gave the same count:

| Workload | Lane `3efda92` | Merged tree |
|---|---|---|
| TLS | 191 | 192 |
| HTTP | 128 | 124 |
| SSH | 89 | 87 |
| unknown | 15 | 15 |

**B. Engine inspector on the benchgate workloads** (`go/internal/bench`). Command:
`cd go && go test -tags benchgate -run TestBenchGate_AllocationsPerFlow -v ./internal/bench`.

| Workload | Research Lab at `0081f6f` (median of 5) | Merged tree |
|---|---|---|
| tls_whole | 33 | 31 |
| tls_fragmented | 37 | 35 |
| http_small | 26 | 26 |
| http_fragmented | 38 | 38 |
| ssh_banner_kexinit | 34 | **38** (the gate's ceiling) |
| unknown_16x1KiB | 10 | 8 |

Retained bytes per finished flow on the merged tree: 631 to 1,388 (bound 4,096).

What the two tables say:
- **The engine core is inside the plan's 64-allocation budget.** Most of the gap to Culvert is in this lane's public
  package, not in the engine.
- **The public package's TLS flow costs about 160 allocations more than the engine's.** An allocation profile of
  `BenchmarkFlow/tls` at `3efda92` puts **54% of all allocations in `detector.bounded`**, through `copyObservation`.
  It copies every evidence and result string to detach the snapshot from engine memory, closed vocabulary values
  included.
- **SSH rises by 4 in the merge.** The lane's copying of the KEXINIT name lists, which the engine had made
  sub-slices, is the likely cause. The merged SSH workload sits exactly at its regression ceiling.
- **Culvert's comparable figures at `ef94311`** (`-tags benchgate`): one whole proxied HTTP request costs 82
  allocations (gate 85); policy evaluation costs 0.

### Update 2026-11-22 (PRO-148): the public package's copies

`go/detector` no longer copies strings that cannot hold flow input:
- **Closed-vocabulary values** (evidence field names, strengths, family names) map to the package's own static
  strings.
- **Engine-composed labels** (source labels, encryption names, scopes, categorical evidence values) are kept as
  the engine made them.
- **Input-derived values** (hostname, ALPN offers, asserted and hostname-class evidence values, detail) are copied
  once and reused while unchanged. The snapshot's internal slices are reused across revisions.

Go strings are immutable and the engine uses no `unsafe`, so no held snapshot can change. The copies that remain
keep a snapshot from holding larger engine allocations. `TestHeldSnapshotsStayDetached` proves the detachment,
under `-race`, with the input buffers overwritten.

Same command, five runs each, all identical:

| Workload | Before (`f649377`) | After | Gate ceiling (was) |
|---|---|---|---|
| TLS | 191 allocs, 15,306 to 15,381 B | **89**, 13,846 to 13,920 B | 110 (240) |
| HTTP | 128, 8,538 to 8,600 B | **76**, 7,768 to 7,830 B | 95 (160) |
| SSH | 89, 6,644 to 6,681 B | **53**, 6,119 to 6,157 B | 65 (115) |
| unknown | 15, 2,352 B | **11**, 2,288 B | 15 (25) |

Under `-race` the counts are 96, 84, 55 and 11; at go1.27.0 they are the same as above.

What is left in a TLS flow is mostly engine-side: the inspector's result building, the parsers' accumulator growth
(`parsing.Credit.Append`) and the hello parsers.

A lower floor without engine code would take three things:
- preallocating the snapshot's evidence slice to the engine's row count (a few allocations);
- skipping the first copy of asserted values, the hostname and ALPN offers. That needs an engine guarantee that
  these strings are exact-size copies, never slices of a larger buffer (about 6 to 8 per TLS flow);
- exact-fit accumulator growth in `internal/parsing` when the record or handshake length is already known. That
  is on the parsers' path, so it should be agreed with the engine lane.

None of this was done, and none of it was tuned against a final budget: Culvert's number is still open.

## 5. What this asks for

- **Decided on 2026-11-22** (PRO-107 and PRO-151; Hermes, for Lee):
  - plan item #19 means rule (a), no non-standard code compiled into what Culvert imports. `golang.org/x/crypto`
    may stay in `go.mod`, and `TestDetectorImportsStandardLibraryOnly` checks `go/detector`'s import graph on four
    platforms;
  - the engine's `go.mod` returns to `go 1.27.0` with `toolchain go1.27.4` (Engine).

  The original question, kept for the record: `go 1.27.4` plus `golang.org/x/crypto` in `go/go.mod` against plan
  items #3 and #19. Culvert's `go.mod` says `go 1.27.0`, so importing the module as it stands would raise Culvert's
  `go` line and add a dependency.

  Options:
  - keep the engine's change and amend the plan;
  - split the module, so the public package's dependency graph stays standard-library-only at 1.27.0;
  - keep the dependency behind a build tag.
- **Reconcile before any merge (engine and this lane):**
  - `tlsx`, `textroute` and `engine` changed on both sides;
  - the credit must cover the engine's new continuation, certificate-watch and message buffers;
  - the SSH list ownership needs one rule;
  - the seven replay mismatches.
- **This lane, after the merge:**
  - classify the new HTTP evidence fields;
  - update the HTTP/2 outcome and the obsolete option tests;
  - re-pin the pack digest;
  - make the immutability test respect build tags;
  - extend the registry allow-list or unexport the three new tables.
- **This lane, separate from the merge:** the public package's own allocations, `bounded` first. That needs
  Culvert's budget number (team request item 3) before it is tuned.
