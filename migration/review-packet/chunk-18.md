# chunk-18: Signature documents, part 1: conditions and evaluation

Tier 1 · about 481 changed lines of code · contracts: C7, C8, C10

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/signatures/signatures.go` (2 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Signature conditions over parser contexts (pattern-match, equal-to, set membership), App-ID metadata and evaluation order.

## Questions to answer

1. Is the anchor prefilter checked on the same haystack (case-folded or not) as the reference's `Condition.evaluate`?
2. Can a signature's App-ID metadata overwrite a built-in application or claim authenticated identity (C10)?
3. Are contexts bounded (`SignatureBytes`) before a pattern runs on them?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzDocumentNeverPanics`
- random 60-signature sets over all cases (4 seeds): 0 mismatches at port time
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/signatures/signatures.go`: lines 1-481 of a new file
- Supporting tests (read only to answer a question above): `go/internal/signatures/signatures_test.go`, `go/internal/engine/signatures_test.go`

## Out of scope

- part 2 (chunk-19)
