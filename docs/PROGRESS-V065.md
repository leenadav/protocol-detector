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
| 1b | `claude/v065-stage1b` (this commit) | one engine source, adapters package, product packaging, build manifest | below |

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
| A01 one source of truth, whole-product packaging | **partly done (1b)** | `presentation/engine/` removed; adapters moved into the `protocol_adapters` package (root files are shims); `pyproject` ships `protocol_engine` + `protocol_adapters` with the optional `decryption` extra; `presentation/` imports through `protocol_adapters`, no `sys.path` hacks except the two worker entry points that register the checkout root; launcher no longer hard-codes a Mac runtime path | clean copy → `pip install ".[decryption]"` → capture classified from the installed wheel with no checkout on the path; both suites green; `check_wheel` ok (78 modules, extra only) | `presentation/` itself is not yet a package in the wheel (it runs from the checkout); CI does not run `presentation-test` (stage 1c) |
| A02 incremental decryption | reproduced | — | `stage0_baseline.py`: 5 decrypt calls / 5 unchanged snapshots; 4.4× re-analysis; full key-log reread per tick | stage 4 |
| A03 reassembly vs inspection ownership | open | — | by inspection (`sessions.py` unchanged) | stage 3 |
| A04 unified lifecycle | reproduced | — | `stage0_baseline.py`: no-FIN session 0 vs 1 at stop | stage 3 (+ shutdown/tick-wiring regression, Codex request) |
| A05 layered App-ID | open | — | `poc_decryption/capture.py` still `replace()`s observations | stage 5 |
| A06 versioned events, revisions, retractions | open | — | — | stage 2 |
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
