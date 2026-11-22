# chunk-01: TLS, DTLS and certificate-continuation parsing (tlsx)

Tier 1 · about 647 changed lines of code · contracts: C1, C3, C5, C8, C16; PM-3

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/protocols/tlsx/certificate.go go/internal/protocols/tlsx/continuation.go go/internal/protocols/tlsx/dtls.go go/internal/protocols/tlsx/tls.go` (6 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Go port of the reference's ClientHello/ServerHello profiles, DTLS 1.2 hellos (M5) and the TLS 1.2 server Certificate continuation (D07/v0.39). Every record and handshake length is checked against its container before slicing; ServerHello posture follows the reference's cipher table (PM-3 widens it after the merge; not here).

## Questions to answer

1. Can any nested length (record → handshake → extension → name list) slice past its container or past `Config.MaxBytes` on a split delivery?
2. Does the certificate continuation stop at its byte budget without buffering an unbounded certificate chain (C8)?
3. DTLS: are cookie, fragment offset and fragment length validated before use, and is a fragmented hello refused rather than reassembled?
4. Does any error path return an identification (C16: errors fail closed)?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzDTLSStaysBounded`, `FuzzInspectorNeverPanics`
- `make parity-go` (Go replay of all 7,430 committed cases, exact match, records included) incl. 128 `stream/tls-*` cases
- `make adversarial` (4,041 deception cases, both engines, 0 unlisted misidentifications)
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/protocols/tlsx/tls.go`: changed lines 14, 25-30, 118, 128-147, 192-195, 231-239, 248-250, 323-361, 395-399, 410-445, 503, 520-526, 536-566, 832-896
- `go/internal/protocols/tlsx/dtls.go`: whole file (200 lines, new)
- `go/internal/protocols/tlsx/certificate.go`: whole file (110 lines, new)
- `go/internal/protocols/tlsx/continuation.go`: whole file (109 lines, new)
- Supporting tests (read only to answer a question above): `go/internal/protocols/tlsx/dtls_test.go`, `go/internal/analyzer/postmerge_test.go`

## Out of scope

- PM-3 ServerHello widening (post-merge; prepared test only)
- Python reference behaviour (frozen; Go is judged against it, and parity is already exact)
