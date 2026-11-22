# chunk-04: HPACK and HTTP/1 request line (hpack, textroute/http.go)

Tier 1 · about 620 changed lines of code · contracts: C1, C8, C16

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/protocols/hpack/hpack.go go/internal/protocols/hpack/tables.go go/internal/protocols/textroute/http.go go/internal/protocols/textroute/irc.go go/internal/protocols/textroute/services.go` (5 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

RFC 7541 HPACK decoder (static and dynamic tables, Huffman) used by the HTTP/2 HEADERS route, and HTTP/1 request-line and header changes (h2c upgrade settings value, method retention after the ownership repair).

## Questions to answer

1. Is the dynamic table size bounded by both SETTINGS and `Config` budgets, and is a size update above the limit refused?
2. Huffman: are padding longer than 7 bits, EOS inside a string and non-all-ones padding refused (RFC 7541 5.2)?
3. Integer decoding: is the continuation-byte loop bounded against overflow?
4. Does any decoded header value reach evidence other than the documented names (no credentials, C17)?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzDecoderStaysBounded`, `FuzzHTTP2StaysBounded`
- `make parity-go` (Go replay of all 7,430 committed cases, exact match, records included)
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/protocols/hpack/hpack.go`: whole file (323 lines, new)
- `go/internal/protocols/hpack/tables.go`: whole file (115 lines, new)
- `go/internal/protocols/textroute/http.go`: changed lines 10-30, 100, 131, 168, 226-231, 242-249, 270-302, 353, 369-371, 397-405, 444, 503, 521-526, 586-590 (+10 more hunks)
- `go/internal/protocols/textroute/irc.go`: changed lines 5, 90, 108, 129-132, 142, 151, 255
- `go/internal/protocols/textroute/services.go`: changed lines 6, 359, 391, 462
- Supporting tests (read only to answer a question above): `go/internal/protocols/hpack/hpack_test.go`

## Out of scope

- `tables.go` static table contents (RFC data; compare only if a question needs it)
