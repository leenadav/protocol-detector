# chunk-09: LDAP and IKEv2

Tier 1 · about 677 changed lines of code · contracts: C1, C2, C8

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/protocols/framed/ikev2.go go/internal/protocols/framed/ldap.go` (3 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

LDAP BER framing and StartTLS shift (v0.54), IKEv2 SA_INIT/AUTH headers and payload chain (M5 batch 21). **`ldap.go` is byte-identical to `b0beb3a`, which Codex reviewed in full (6946510458): confirm with `git rev-parse 50ce5c0:go/internal/protocols/framed/ldap.go b0beb3a:go/internal/protocols/framed/ldap.go` (both `08522a3def5e…`) and skip it.** Read `ikev2.go` only: about 312 lines.

## Questions to answer

1. IKEv2: is the payload chain walk bounded (count and total length) and is each payload length ≥ 4 and inside the message?
2. Is the IKE SPI/length header checked before the first payload, including the NAT-T non-ESP marker variant?
3. Is the critical bit honoured as documented (refuse unknown critical payloads)?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzFramedNeverPanics`
- `make parity-go` (Go replay of all 7,430 committed cases, exact match, records included) incl. the IKEv2 vectors and UDP hint cases
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/protocols/framed/ldap.go`: whole file (365 lines, new)
- `go/internal/protocols/framed/ikev2.go`: whole file (312 lines, new)
- Supporting tests (read only to answer a question above): `go/internal/protocols/framed/ldap_test.go`, `go/internal/protocols/framed/ikev2_test.go`

## Out of scope

- `ldap.go` content (reviewed; blob identical)
- Python reference behaviour (frozen; Go is judged against it, and parity is already exact)
