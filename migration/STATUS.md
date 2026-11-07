# Python → Go migration: status ledger

Plan: "Python → Go migration: implementation and acceptance plan" (Lee, 2026-11-07). States per item:
implemented · independently verified · blocked · deferred. Every entry names SHAs and commands. This file
never claims production readiness; release thresholds are pending (plan §5 M9/M10).

## M0 — stabilize and freeze the comparison baseline

| item | state | evidence |
|---|---|---|
| Baseline commit | implemented | `c2b7cc3b4eeae4d17ec60d6ca5dc7164375a61b8` on `claude/v066-smarthome` (PR #18, draft). Range since the independently reviewed architecture head: `e7af436..c2b7cc3`, 17 commits (listed below). |
| §2.1 live restart on the cursor path | implemented; independently reported by Lee's follow-up review, repaired in `036932c` | `store.liveBusy()` on `live/events` and `live/snapshot`; `run/error` on a failed start; stale-run guards kept. `store.test.js` case 6. |
| §2.2 "Clear sessions & reset capture" with run identity | implemented from the plan's contract (the Mac checkout was never pushed; reconciliation owed when it is) | `c2b7cc3`: `POST /api/live/reset {run_id}` → `LiveManager.reset`; stale/absent run id is a no-op; key logs untouched; `live/reset` store action under run identity. Tests in `test_live_bridge`, `test_http`, `test_security`, `store.test.js` case 7, browser test. |
| §2.3 frontend-only port/transport labels | implemented | `selectors.displayLabel` → `8081 tcp` for outcomes only; `app`, filters, exports unchanged. Browser test checks the unknown demo session. |
| §2.4 lazy compatibility rows after parity checks | implemented | `9bbc9f4`; behaviour diff vs `e7af436` no differences at every commit; `test_sessions::LazyCompatResultsTests`. |
| §2.5 CI reconciliation | implemented; hosted runs green | engine branch `ci`/`codeql` green on `ca841c8` (runs 42385014524 / 42385014523); integration branch `claude/cicd-next` `fcacb42` (merges `ca841c8`) green on 16 checks incl. no-skip presentation-ui and installed check on the exact wheel (CI/CD lane, run 42385293567). `c2b7cc3` hosted result: to be read on the next check-in. |
| §2.6 documentation reconciliation | implemented | docs/DETECTION-PLAN-STATUS.md header/summary (Actions run again; D11 acted on; D09 blocked), PR #18 description rewritten. |
| Source patch inventory | implemented | the 17 commits below; no uncommitted local modifications in this checkout; the Mac checkout (`/Users/lee/Desktop/protocol-v059-publication`) is not reachable from this session (no shared folder), so its patch set is **not** inventoried here. |
| Whole-product manifest | implemented | `presentation/SOURCE.json` build digest `e7d15f286739d0a2` (123 files); `make check` verifies it. |
| Capability inventory | implemented | `migration/CAPABILITIES.json` from `tools/capabilities.py` (88 families: 63 tcp, 33 udp, 9 hint-only, 10 midstream-capable; 156 applications, 54 host-named; content release 2026.11.0 digest 991c007668d263d1); `make check` → `capabilities`. Every Go status is `pending`. |
| Baseline results | implemented (local, this host) | engine 813 tests OK; presentation 63 tests OK incl. Playwright browser test; `make check` OK; fuzz 476,000 cases OK; sequence relations 0 violations (3 seeds × 6); behaviour diff vs `e7af436`: none; installed check `--require-all` OK (server, page, demo replay 18 sessions, decryption demo 3 connections, suite against the wheel, zero skips); synthetic corpus report TP 1593 / FN 0 / FP 28 (docs/CORPUS-REPORT-V065.md, a regression gate); soak docs/SOAK-V065.json. Benchmarks: `migration/benchmarks/baseline-engine-c2b7cc3.json` (benchmark_engine 300 iterations: http_small 30.3 µs p50, http_fragmented 509 µs, tls_fragmented 61 µs, rules_30000 31.7 µs) and `baseline-perf-profile-c2b7cc3.json` (perf_profile: small HTTP flow decode 14 / engine 38 / adapter 221 µs p50; half-closed connection 6.1 KB held). |
| Environment record | implemented | `migration/benchmarks/environment-c2b7cc3.json` (cloud container, 4 vCPU Xeon 2.10 GHz, 16 GiB, Python 3.13.16 + 3.9.25, Node 22.22.0, Go 1.24.7 present). |
| Exceptions kept explicit | — | D09 acceptance blocked (no independent corpus); production SLO/capacity/soak unproven; D11 numbers local; hosted CI evidence applies to the commits each run contains. |

M0 exit assessment: a single named Python commit (`c2b7cc3`) represents the integrated product on this
branch; the local-only features exist here as contract implementations but Lee's Mac versions are not
integrated (they were never pushed); CI gates passed on `ca841c8` and the hosted result for `c2b7cc3` is
pending. D09 and SLOs stay documented blockers for release, not for M1/M2.

### Commits since the reviewed architecture head e7af436

0b20ff3 D01/D02/P2 · 9f0918c D03 · c449d13 D04 · 01549d4 D05 · 9cbc4a9 D06 · 855442b D07 · 799d358 D08 ·
4bcb8e4 D09 · af91747 D10 · 12cbf6c D11 · 8653231 D12 · 6ddc3ea A01/A14 · 726007d round-2 repairs ·
9bbc9f4 D11 follow-up · 036932c live restart P2 · ca841c8 CI patch · c2b7cc3 M0.

## M1 — contracts and differential harness

| item | state | evidence |
|---|---|---|
| Contract matrix | implemented | `migration/CONTRACTS.md`: 17 contracts (C1–C17: stream, datagram, end of input, adapter reassembly, sticky invalidation, QUIC isolation, hints, configuration/budgets, observation modes, layered identity, content pin, unknown reasons, output schemas, cursor APIs, cancellation, fail-closed errors, no plaintext/keys), each with its Python reference, what is fixed, the cases that check it and Go status `pending`. |
| Language-neutral fixtures | implemented | `migration/fixtures/cases.json` (schema 1, generated from the Python reference by `migration/parity/cases.py`, seeded and deterministic): 1366 cases — 861 stream (every labelled stream fixture as whole / whole+FIN / 1-byte chunks / 7-byte chunks / truncated half / seeded mutation, plus continuation, byte-budget and fingerprint options), 279 datagram (whole / half / mutated, hinted rows included), 226 session (Ethernet frames with timestamps through the Analyzer: plain, split, reordered, conflicting retransmission for every hint-free family; lifecycle idle/RST/reuse; observation modes; continuation; DNS; QUIC reordered assembly and assembly conflict with sticky invalidation). Expectations are full event sequences (kinds, revisions, observations with evidence tuples), final observations, metrics, per-packet events and session records. Outcome coverage: identified 739 / malformed 165 / incomplete 159 / unknown 66 / budget_exhausted 11 (stream+datagram); session records identified 170 / invalidated 55 / incomplete 2 / no_handshake 1. |
| Canonicalization | implemented, minimal | only `content.digest` → `content.version` (hash definition pending M6); no wall clock or generated identifiers exist in the compared paths. Approved semantic deltas live in `migration/parity/deltas.json` (empty), one path of one case each with a justification, validated by the test. |
| Differential comparator | implemented | `migration/parity/compare.py --backend python` or `--results <file>` (another backend's output in the same shape): exact structural diff, bounded report, `--report` JSON. Python vs Python on the committed cases: 1366 compared, 1366 matched, 0 mismatched / missing / extra / exempted. |
| Planted-regression proof | implemented | `--plant wrong-positive · missing-retraction · wrong-port · dropped-event · boundary-shift` each reported on exactly the case it touched (and no other). `test_migration_parity.py` (6 tests) proves zero diffs, that the committed inputs are current with the fixture tables, determinism, all five plants, outcome coverage and delta hygiene; `make check` → `parity`. |
| Performance comparator | deferred to M9 | separate from parity by design; Python baselines in `migration/benchmarks/`. |
| Exceptions kept explicit | — | cursor/lifecycle contracts (C14, C15) are HTTP-level and covered by the presentation tests named in the matrix, not by `cases.json`; schema parity (C13) is compared field by field on records, not by validating the Go output against `schemas/` yet (M7). |

M1 exit assessment: the contract matrix, the fixtures and the comparator exist and the comparator is proven
to detect the five regression shapes; Go has produced no results yet, so every contract is `pending`.

## M2 — Go foundation

Not started (next): module skeleton, typed contracts, bounded buffers, deterministic clock, structured errors, ADR 0001 on ownership and resources, basic fuzz; on a dedicated migration branch once this baseline is stable.

## Open decisions and blockers

- Mac checkout patch set (reset, labels): needs a push or a description to reconcile with `c2b7cc3`.
- Codex round-3 result on `726007d`: pending (issue #2).
- Independent labelled corpus (D09): blocked on input.
- Release thresholds (latency, throughput, memory): unspecified by design; relative results only.
- Dedicated migration PR: to be opened only when authorized in the working session (plan §1).
