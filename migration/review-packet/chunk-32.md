# chunk-32: Offline analyze pipeline and telemetry

Tier 2 · about 638 changed lines of code · contracts: C13, C17

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/analyze/analyze.go go/internal/telemetry/telemetry.go` (4 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Offline `analyze` rows/summary built from the analyzer; telemetry counters and histograms.

## Questions to answer

1. Can telemetry carry any payload-derived string (C17), or only counts and closed labels?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential)
- `make parity-analyze`, `make schema-go`
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/analyze/analyze.go`: whole file (478 lines, new)
- `go/internal/telemetry/telemetry.go`: whole file (160 lines, new)
- Supporting tests (read only to answer a question above): `go/internal/analyze/present_test.go`

## Out of scope

