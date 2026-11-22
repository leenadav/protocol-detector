# chunk-15: ojson parser (control-plane JSON)

Tier 1 · about 595 changed lines of code · contracts: C13, C14, C16

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/ojson/ojson.go` (2 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

CPython-compatible JSON parser used for policy, signature documents and the local control API bodies, so Go answers exactly like the reference (`json.loads`), including error texts.

## Questions to answer

1. Is nesting depth bounded (stack exhaustion on `[[[[...`)?
2. Are huge integers and exponents bounded the way CPython's int-digit limit requires, without big-number blowup?
3. Duplicate keys: is CPython's last-wins kept, and is the output key order preserved?
4. Is every error a `SyntaxError` with CPython's message and position, never a panic?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzDecodeIsAFixedPoint`
- `make parity-control`, `make parity-server`: 0 differences (424 exchanges)
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/ojson/ojson.go`: whole file (595 lines, new)
- Supporting tests (read only to answer a question above): `go/internal/ojson/ojson_test.go`

## Out of scope

- Python reference behaviour (frozen; Go is judged against it, and parity is already exact)
