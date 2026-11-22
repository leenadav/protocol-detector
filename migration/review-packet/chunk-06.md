# chunk-06: Continuation, heuristics and fingerprints

Tier 1 · about 677 changed lines of code · contracts: C3, C8, C12, C17; D07

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/protocols/fingerprint/fingerprint.go go/internal/protocols/heuristics/heuristics.go go/internal/protocols/textroute/continuation.go` (3 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Post-identification HTTP/1 continuation (D07: message framing, no-body statuses before CL/TE, Codex R3), unknown-traffic heuristics, and the JA3/JA4/JA3S/JA4S/HASSH/h2 fingerprints.

## Questions to answer

1. Continuation: can chunked framing with huge chunk sizes or many tiny chunks exceed the transaction/byte budget (C8)?
2. Is a framing error kept as an end of continuation without revoking the earlier identification (as documented)?
3. Heuristics: can a heuristic ever produce an identification rather than a labelled unknown?
4. Fingerprints: is GREASE excluded and sorting done exactly per the JA4 spec, with no raw SNI in the hash input that is logged?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzHTTPContinuationStaysBounded`
- `make parity-go` (Go replay of all 7,430 committed cases, exact match, records included) option re-runs with fingerprints, heuristics and continuation
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/protocols/textroute/continuation.go`: whole file (298 lines, new)
- `go/internal/protocols/heuristics/heuristics.go`: whole file (163 lines, new)
- `go/internal/protocols/fingerprint/fingerprint.go`: whole file (216 lines, new)
- Supporting tests (read only to answer a question above): `go/internal/engine/continuation_test.go`

## Out of scope

- Python reference behaviour (frozen; Go is judged against it, and parity is already exact)
