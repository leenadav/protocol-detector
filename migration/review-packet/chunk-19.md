# chunk-19: Signature documents, part 2: loading and the set digest

Tier 1 · about 492 changed lines of code · contracts: C11, C13, C16

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/signatures/signatures.go` (2 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

`FromJSON`: document validation with the reference's error texts, description rendering (Python `str()` of JSON objects), and the `signature_set` digest records carry.

## Questions to answer

1. Is the `signature_set` digest computed over a canonical form, so two documents with the same meaning cannot differ (or collide)?
2. Are document size, signature count and condition count bounded before allocation?
3. Does every refused document fail the whole load (no partial set)?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzDocumentNeverPanics`
- 20,000 generated documents compared at port time
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/signatures/signatures.go`: lines 482-973 of a new file
- Supporting tests (read only to answer a question above): `go/internal/signatures/signatures_test.go`

## Out of scope

- patterns (chunks 16-17)
