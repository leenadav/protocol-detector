# Progress record — architecture and security plan on v0.65

Companion to docs/ARCHITECTURE-REVIEW-V065-EN.md. Updated at every checkpoint with exact SHAs, the commands
that verify the claim, and what is still open. All verification is Claude-executed in a cloud container on
Linux with synthetic in-memory traffic; GitHub Actions does not start jobs on this repository (account
spending limit, which Lee will not raise), so no Actions result is claimed anywhere below.

## Checkpoints

| Stage | Branch / head | Scope | Verification |
|---|---|---|---|
| 0 | `claude/v065-stage0` `048c16a` | baseline record, `tools/stage0_baseline.py` reproductions | docs/STAGE0-BASELINE-V065.md |
| 1a | `claude/v065-stage1a` `b07a9e5` | presentation under lint; fragile decryption test fixed; `make presentation-test` | `make check`; engine 655 OK; presentation 31 OK |
| 1b | `claude/v065-stage1b` `e7d84ce` | one engine source, adapters package, product packaging, build manifest | clean-copy install classifies a capture; `check_wheel` ok |
| 1c | `claude/v065-stage1c` `19e7219` | canonical CI runs the presentation suite; `make check` runs it when the extra is present; A04 shutdown-wiring regression | `make check` both ways; 33 presentation tests, 1 expected failure; lock installs with `--require-hashes` |
| 2 | `claude/v065-stage2` `9e3bceb` | versioned event envelope, bounded log with cursors, named retractions, replayable reducer | A06 row |
| 3 | `claude/v065-stage3` (this commit) | one owner of reassembly deltas and of connection lifecycle on every capture path | A03/A04 rows |

Reproducible gate for every checkpoint from a clean checkout (needs the optional extra for the presentation):

```sh
python3 -m venv .venv && .venv/bin/pip install -e ".[decryption]" build
make check                                   # ruff, engine tests, pins, policy lint, coverage matrix, docs counts
make presentation-test PYTHON=.venv/bin/python
python3 -B tools/fuzz_fixtures.py --iterations 100 --seed 66
python3 -B tools/build_manifest.py --check presentation/SOURCE.json
.venv/bin/python -m build --wheel --outdir dist && .venv/bin/python -B tools/check_wheel.py "dist/*.whl"
python3 -B tools/stage0_baseline.py          # the A02/A04/A07 numbers; compare with docs/STAGE0-BASELINE-V065.md
```

## Finding map (A01–A16)

| Finding | State | Implementation | Verification | Remaining gap |
|---|---|---|---|---|
| A01 one source of truth, whole-product packaging | **partly done (1b, 1c)** | `presentation/engine/` removed; adapters moved into the `protocol_adapters` package (root files are shims); `pyproject` ships `protocol_engine` + `protocol_adapters` with the optional `decryption` extra; `presentation/` imports through `protocol_adapters`, no `sys.path` hacks except the two worker entry points that register the checkout root; launcher no longer hard-codes a Mac runtime path | clean copy → `pip install ".[decryption]"` → capture classified from the installed wheel with no checkout on the path; both suites green; `check_wheel` ok (78 modules, extra only) | `presentation/` itself is not yet a package in the wheel (it runs from the checkout). CI: the `verify` job now installs the hash-pinned extra (`presentation/requirements-decryption.lock.txt`), checks the build manifest and runs the presentation suite on 3.9/3.11/3.13; `make check` runs `manifest` and `presentation-check` (the latter runs the suite when `cryptography` is importable and otherwise says it skipped). **Verification gap:** actionlint could not be run locally (its download was denied by this session's permission check); the workflow edit is validated by YAML parse and `tools/check_action_pins.py` only, and Actions itself does not run on this repository. The CI/CD session (owner of `.github/workflows`) was paused on 2026-10-23; it is being told about this edit so it merges rather than collides |
| A02 incremental decryption | reproduced | — | `stage0_baseline.py`: 5 decrypt calls / 5 unchanged snapshots; 4.4× re-analysis; full key-log reread per tick | stage 4 |
| A03 reassembly vs inspection ownership | **done (stage 3)** | `sessions.Stream` gains `StreamDelta` and `deltas()`: each contiguous byte is handed out exactly once, in order, after the Stream's own overlap/conflict/budget checks; `protocol_adapters/coordinator.py` `SessionCoordinator` is the single owner of the Analyzer's flow table and exposes `deltas(client, server)` so a second consumer (the TLS decoder, stage 4) reads from the same owner instead of keeping its own flow table | `test_coordinator.py` (8 tests: exactly-once deltas, gap holds bytes back, retransmission adds nothing, conflicting overlap raises before new bytes are admitted, one owner serves the deltas) | the decryption POC still copies bytes into its own `LiveDecoder` buffers until stage 4 moves it onto `deltas()` |
| A04 unified lifecycle | **done (stage 3)** | `SessionCoordinator.tick(now)` / `end(reason)` / `gap(reason, scope)` with injected time: idle expiry only on tick, finalization exactly once per (session, generation), gaps retract named sessions and drop state; `accept()` renews the generation on a fresh SYN over a tracked tuple; every session carries `capture_id`, `session_id`, `generation` (live-event schema extended). `live_capture.main` and `poc_decryption/live.py` both tick and end through the coordinator; `CaptureMonitor.invalidate_all` goes through `gap()` | `presentation/tests/test_live_decryption.py::test_no_fin_connection_gets_a_final_session_at_stop` is now a plain passing test (was `expectedFailure`); `tools/stage0_baseline.py` A04: 1 session at stop on both paths, 0 with no lifecycle call; `test_coordinator.py` (no-FIN finalized once at end, idle expiry needs tick, tuple reuse → generation 1, gap retracts named sessions, monitor and coordinator agree); engine 672 OK; presentation 33 OK; behaviour diff vs `1d1db29`: no differences; fuzz seed 68 ok | the offline decryption adapter (`poc_decryption/capture.py`) still runs `analyze_capture` without a coordinator; stage 4 moves it |
| A05 layered App-ID | open | — | `poc_decryption/capture.py` still `replace()`s observations | stage 5 |
| A06 versioned events, revisions, retractions | **done (stage 2)** | `protocol_adapters/events.py`: `Envelope` (schema_version, sequence, capture_id, session_id, generation, layer, revision, kind, source, quality, reason_code, budget, retracts, payload), `session_identity` (hashed, direction-independent, carries no address), `SessionGenerations` (tuple reuse bumps generation), `EventLog` (bounded deque, sequence assigned by the log never the producer, per-generation revisions, `read(cursor)` returns `reset_required` instead of a window with a hole), `reduce()` + `public_state()` (deterministic fold; duplicates ignored by a seen-set, not a high-water mark; older generation and stale revision never overwrite; a retraction marks dependents `retracted` with reason_code and clears their inner evidence, never deletes). `schemas/event-envelope.schema.json`. Producer: `CaptureMonitor.invalidate_all` now emits `session_ids` on `capture_gap` so retractions name their dependents (live-event schema grew the field). Compatibility: `wrap()` envelopes today's legacy events unchanged; `LiveManager` keeps every old snapshot key and adds `capture_id`, `cursor`, `events_since(cursor)`, `view()`; `GET /api/live/events?cursor=N` serves the cursor read | `test_events.py` (9 tests: schema validation, bad fields rejected, capture isolation, cursor/duplicate/reset, generation bump, stale revision & older generation, named and capture-wide retraction, live-vs-replay equality, producer names retracted sessions); engine 655+9 OK; presentation 33 OK; behaviour diff vs `1d1db29`: 0 of 84264 differ; fuzz seed 67 ok | the frontend still consumes the legacy `events` array (store rewrite is stage 6); `LiveDecoder`'s decryption reports are enveloped at ingest but the POC still re-sends whole reports (stage 4) |
| A07 aggregate budgets, lazy allocation | reproduced | — | 512 KiB per direction at `Stream` creation; 65.3 MiB for 64 flows | stage 4 |
| A08 responsive management plane | open | — | synchronous `HTTPServer`, 25 s worker timeout | stage 6 |
| A09 decryption as a trust boundary | open | — | — | stage 4 |
| A10 key handling, privilege separation | open | — | — | stage 8 (tests throughout) |
| A11 signature indexes | open | — | — | stage 7 |
| A12 registration contracts | open | — | — | stage 7 |
| A13 protocol vs application vs transaction | open | — | — | stage 5 |
| A14 frontend store | open | — | — | stage 6 |
| A15 boundary measurement | started | `stage0_baseline.py` | numbers above | stage 7 histograms/counters |
| A16 identify and secure the complete build | **partly done (1b)** | `tools/build_manifest.py` writes `presentation/SOURCE.json` with version, commit, per-file sha256 for engine/adapters/presentation/schemas and a `build_digest`; `/api/catalog` reports it; the launcher reuses a running server only on a matching build digest | `build_manifest.py --check` ok; `test_build_manifest_matches_the_tree` | SBOM/provenance for the extra; CI enforcement (stage 1c/8) |

## Divergent Mac v0.59 work

`claude/v059-unknowns-catalog-keylog` (`190e011`, smart-home LIFX/Tuya/TP-Link + mDNS repairs) is not in v0.65.
Inventory in docs/STAGE0-BASELINE-V065.md. It will be ported as its own version after the refactor stages, with
renamed test/benchmark files, a full gate and behaviour diff. Nothing from it is dropped or overwritten.
