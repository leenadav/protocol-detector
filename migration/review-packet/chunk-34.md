# chunk-34: Live run loop, job buffers and test frames

Tier 2 · about 453 changed lines of code · contracts: C15

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/jobs/buffer.go go/internal/live/run.go go/internal/testframes/testframes.go` (4 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Live run lifecycle (start, SIGINT/SIGTERM, finalize once), bounded job output buffers, and synthetic frame builders for tests.

## Questions to answer

1. Is finalization idempotent under a second signal?
2. Are job buffers bounded with truncation reported, never silently dropped?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential)
- `interrupt_test.go`
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/live/run.go`: whole file (337 lines, new)
- `go/internal/jobs/buffer.go`: whole file (40 lines, new)
- `go/internal/testframes/testframes.go`: changed lines 6-11, 91-161

## Out of scope

