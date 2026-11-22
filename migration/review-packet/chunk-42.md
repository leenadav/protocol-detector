# chunk-42: Benchmark and load harness

Tier 2 · about 400 changed lines of code · contracts: P2, D11

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/bench/benchgate_test.go go/internal/bench/load_test.go` (2 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

`make bench-gate` (allocations and retained bytes gated; p99 per flow reported) and `make bench-load` (reported only).

## Questions to answer

1. Does the gate measure the engine's retained bytes, not harness allocations (`Rows[:0]` retention was fixed)?
2. Is anything timing-based gated (it must only be reported)?

## Already run (do not re-run)

- `make bench-gate` in `make go-check`
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/bench/benchgate_test.go`: whole file (171 lines, new)
- `go/internal/bench/load_test.go`: whole file (229 lines, new)

## Out of scope

- benchmark numbers themselves
