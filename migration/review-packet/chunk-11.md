# chunk-11: Stream inspector (engine/inspector.go)

Tier 1 · about 701 changed lines of code · contracts: C1, C3, C5, C7, C8, C9, C16

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/engine/inspector.go` (17 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

The per-direction inspector the Culvert/proxy path calls: dispatch, prefix buffering, application shifts (STARTTLS, CONNECT, WebSocket), continuation hand-off, retained-sink lifetime and the observation/event publication rules.

## Questions to answer

1. Is the prefix buffer bounded by `MaxBytes` across shifts (a shift must not reset the budget)?
2. After a terminal observation or `invalidate`, can any later Feed publish a non-terminal or different identification (C5)?
3. Does a hint only select the candidate, with the parser's own result deciding (C7)?
4. Midstream/one-direction modes (C9): is a family outside the midstream list forced to `incomplete`/`midstream`?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzInspectorNeverPanics`, `FuzzSelectNeverPanics`
- `make parity-go` (Go replay of all 7,430 committed cases, exact match, records included) (all 5,253 stream cases)
- `make adversarial` (4,041 deception cases, both engines, 0 unlisted misidentifications)
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/engine/inspector.go`: changed lines 7-23, 35-360, 400-403, 424-439, 475-495, 525-546, 584, 602-610, 626-633, 695-696, 713-716, 791-792, 801-805, 827-988
- Supporting tests (read only to answer a question above): `go/internal/engine/dispatch_test.go`, `go/internal/engine/engine_test.go`

## Out of scope

- individual protocol parsers (chunks 01-10)
- Python reference behaviour (frozen; Go is judged against it, and parity is already exact)
