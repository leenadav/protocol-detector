# chunk-17: Signature patterns, part 2: compiling to RE2

Tier 1 · about 574 changed lines of code · contracts: C7, C8, C16

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/signatures/pattern.go` (2 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Group parsing and the translation to an equivalent Go regular expression over the Latin-1 image of the bytes, including `writeRepeat` (`93cbf2a`): counts 1001-4096 split into language-equivalent pieces.

## Questions to answer

1. Is every atom the same byte set as Python's bytes semantics (ASCII-only IGNORECASE, \d \w \s, DOTALL)?
2. `$` at the end compiles to `\n?\z`: is that the reference's meaning for a search, and is a non-final `$` always refused?
3. Is the `writeRepeat` expansion bounded before any string is built (pieces and bytes), so a pattern cannot amplify compile time?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzPatternNeverPanics`; `repeat_test.go` checks 9 patterns at 19 counts against CPython `re`
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/signatures/pattern.go`: lines 579-1152 of a new file
- Supporting tests (read only to answer a question above): `go/internal/signatures/pattern_test.go`, `go/internal/signatures/repeat_test.go`

## Out of scope

- inline flags, atomic groups, possessive repeats (refused by design)
