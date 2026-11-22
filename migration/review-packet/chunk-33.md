# chunk-33: Live monitor and its outputs

Tier 2 · about 676 changed lines of code · contracts: C14, C15, C17

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/live/monitor.go go/internal/live/output.go` (4 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

The live capture monitor (tcpdump loop, selector, session suppression of Milestone B) and its event output.

## Questions to answer

1. Is the unbounded-record suppression (Milestone B) applied before output, with a counter of what was suppressed?
2. Does the tcpdump child get killed with its process group on every exit path?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential)
- `make parity-live`
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/live/monitor.go`: whole file (496 lines, new)
- `go/internal/live/output.go`: whole file (180 lines, new)
- Supporting tests (read only to answer a question above): `go/internal/live/reuse_test.go`

## Out of scope

