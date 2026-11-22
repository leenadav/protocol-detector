# chunk-41: Launcher, presentation glue, adapters and the Makefile

Tier 2 · about 408 changed lines of code · contracts: C15

**Exact scope**: `git diff dbe20f3 50ce5c0 -- Makefile presentation/launch.py presentation/live_decrypt_smoke_check.py presentation/poc_decryption/capture.py presentation/poc_decryption/live.py presentation/server.py` (51 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Default backend switch in the launcher (Go when installed; `--backend python` keeps the reference), presentation glue, and the Makefile (vendored `-mod=vendor` builds, `go-vendor-check`, the presentation suite rebuilding the binary).

## Questions to answer

1. Can `--backend go` ever fall back silently to Python (it must not)?
2. Does every Makefile Go command use `-mod=vendor`, and does `go-vendor-check` fail on drift and on untracked vendor files?

## Already run (do not re-run)

- `make check` (presentation suite 86 tests), `make go-vendor-check`
- hosted presentation jobs fail on this branch only because `GoServiceTests` skips without a built binary; the CI fix is PR #30, now on `main`
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `presentation/launch.py`: changed lines 1-11, 20-45, 57-68
- `presentation/server.py`: changed lines 84-122
- `presentation/poc_decryption/capture.py`: changed lines 22-72
- `presentation/poc_decryption/live.py`: changed lines 262-281
- `presentation/live_decrypt_smoke_check.py`: whole file (93 lines, new)
- `Makefile`: changed lines 1, 59, 69-76, 87, 105-123, 137-146, 163-282
- Supporting tests (read only to answer a question above): `presentation/tests/test_backend_selection.py`, `presentation/tests/test_launch_backend.py`, `test_backend.py`

## Out of scope

