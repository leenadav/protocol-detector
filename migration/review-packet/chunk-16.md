# chunk-16: Signature patterns, part 1: the re._parser port

Tier 1 · about 578 changed lines of code · contracts: C7, C8, C16

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/signatures/pattern.go` (2 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Port of CPython 3.13 `re._parser` so the literal-anchor rule sees exactly the reference's parse tree; constructs RE2 cannot express are refused as not ported (the reference answers them).

## Questions to answer

1. Can a pattern make the parser recurse or loop without bound (nested groups, long alternations), given `MaxPattern`?
2. Is every Python error message reproduced, so a refusal is never a different refusal or an acceptance?
3. Is the literal anchor computed from the same tree as the reference (the prefilter is a correctness boundary)?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzPatternNeverPanics`
- 20,000 generated patterns compared at port time (STATUS.md, custom signatures row)
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/signatures/pattern.go`: lines 1-578 of a new file
- Supporting tests (read only to answer a question above): `go/internal/signatures/pattern_test.go`

## Out of scope

- part 2 of the file (chunk-17)
