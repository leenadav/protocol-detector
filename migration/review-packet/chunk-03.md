# chunk-03: QUIC Initial validation and CRYPTO assembly (quicx)

Tier 1 · about 610 changed lines of code · contracts: C2, C5, C6, C8; PM-6

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/protocols/quicx/assembler.go go/internal/protocols/quicx/quic.go` (3 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

QUIC v1/v2 Initial header validation, Initial packet protection removal with the RFC 9001 salts, and the per-scope, per-direction CRYPTO assembler (C5/C6, Codex R2 two-scope reset).

## Questions to answer

1. Does the assembler bound total retained CRYPTO bytes and offsets per scope (C8), including far-future offsets?
2. Are overlapping CRYPTO frames byte-compared, with a contradiction invalidating and retracting (C5) and never overwriting?
3. Is header protection removal bounded for short packets (sample offset past the end)?
4. Does retirement reset both ordered scopes (R2) on every path: end, idle, Finish, with and without a session callback?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzValidateStaysBounded`
- `make parity-go` (Go replay of all 7,430 committed cases, exact match, records included) incl. QUIC datagram and session cases; ~16,500 generated datagrams compared at port time (STATUS.md, QUIC row)
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/protocols/quicx/quic.go`: whole file (383 lines, new)
- `go/internal/protocols/quicx/assembler.go`: whole file (227 lines, new)
- Supporting tests (read only to answer a question above): `go/internal/protocols/quicx/quic_test.go`, `go/internal/analyzer/quic_test.go`

## Out of scope

- pre-RFC 9000 gQUIC (PM-6, post-merge)
- Python reference behaviour (frozen; Go is judged against it, and parity is already exact)
