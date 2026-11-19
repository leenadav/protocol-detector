# chunk-36: Event log and reducer

Tier 2 · about 716 changed lines of code · contracts: C14

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/events/events.go` (1 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Versioned event envelope, revisions and retractions, and the reducer the dashboard reads (port of Stage 2).

## Questions to answer

1. Can a stale revision or an older generation overwrite a newer one (the reducer rule)?
2. Are cursors monotonic across restarts of a run?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential)
- `make parity-control`
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/events/events.go`: whole file (716 lines, new)

## Out of scope

