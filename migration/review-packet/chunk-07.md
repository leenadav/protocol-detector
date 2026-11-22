# chunk-07: SMB1/SMB2 negotiation and small framed changes

Tier 1 · about 732 changed lines of code · contracts: C1, C8, C16

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/protocols/framed/database.go go/internal/protocols/framed/datagram_services.go go/internal/protocols/framed/datagram_text.go go/internal/protocols/framed/datagram_wire.go go/internal/protocols/framed/kasa.go go/internal/protocols/framed/sessions.go go/internal/protocols/framed/smb.go` (6 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

SMB1 NEGOTIATE request/response and SMB2/3 NEGOTIATE with security posture (M5 batch 19); `datagram_wire.go` carries the RFC 7252 CoAP tightening (F-ADV-1, `12e1ed0`); the rest are one-line ports.

## Questions to answer

1. SMB2 negotiate contexts: are context count, offsets and lengths validated against the message before iterating?
2. Is the dialect list bounded, and is a security-mode or capability bit read only inside the header?
3. CoAP: are option delta/length nibbles 13/14 with their extended bytes bounded, and is 15 refused except as the payload marker?
4. Is anything an SMB server or client sends emitted as identity (no domain or challenge values, C17)?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzFramedNeverPanics`, `FuzzKasaNeverPanics`
- `make parity-go` (Go replay of all 7,430 committed cases, exact match, records included)
- `make adversarial` (4,041 deception cases, both engines, 0 unlisted misidentifications) incl. 2,000 seeded random datagrams (CoAP rate 1 of 2,000)
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/protocols/framed/smb.go`: whole file (654 lines, new)
- `go/internal/protocols/framed/database.go`: changed lines 6, 721
- `go/internal/protocols/framed/datagram_services.go`: changed lines 431-455
- `go/internal/protocols/framed/datagram_text.go`: changed lines 5, 36
- `go/internal/protocols/framed/datagram_wire.go`: changed lines 6, 36, 226-244, 257, 283, 308-319
- `go/internal/protocols/framed/kasa.go`: changed lines 17-19
- `go/internal/protocols/framed/sessions.go`: changed lines 279-280
- Supporting tests (read only to answer a question above): `go/internal/protocols/framed/smb_test.go`, `go/internal/protocols/framed/coap_test.go`

## Out of scope

- CoAP flow rule and reason attribution (PM-1, PM-2: post-merge)
- Python reference behaviour (frozen; Go is judged against it, and parity is already exact)
