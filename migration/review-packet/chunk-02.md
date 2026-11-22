# chunk-02: X.509 leaf profile (x509x)

Tier 1 · about 821 changed lines of code · contracts: C1, C8, C16, C17

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/protocols/x509x/x509.go` (1 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

DER walker for the server leaf certificate (subject/SAN names, validity, key usage, basic constraints, key type and size) behind the `certificates` option. Structural only: no chain building, no signature check.

## Questions to answer

1. Is every DER length (including long-form lengths and indefinite-length refusal) bounded by its parent before reading?
2. Can OID or integer decoding overflow or loop (deep nesting, huge long-form length, zero-length INTEGER)?
3. Do SAN or subject names reach output only through the documented evidence fields, never as raw bytes (C17)?
4. Are time fields (UTCTime/GeneralizedTime) parsed strictly, with an invalid date refused instead of normalized?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzLeafProfileStaysBounded` over the 4,721-line `testdata/leaves.json` corpus
- `make parity-go` (Go replay of all 7,430 committed cases, exact match, records included)
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/protocols/x509x/x509.go`: whole file (821 lines, new)
- Supporting tests (read only to answer a question above): `go/internal/protocols/x509x/x509_test.go`

## Out of scope

- `testdata/leaves.json` (generated corpus, Tier 3)
- certificate trust or revocation (not a goal)
