# chunk-08: GSS/SPNEGO token classifier

Tier 1 · about 596 changed lines of code · contracts: C1, C8, C17

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/ascii/ascii.go go/internal/names/hostname.go go/internal/protocols/dnsx/dns.go go/internal/protocols/framed/gss.go` (3 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

SPNEGO/Kerberos/NTLM token classifier used by LDAP bind, SMB session setup and HTTP Authorization (v0.56). **Codex already inspected its LDAP entry points** at `b0beb3a` (issue #2 comment 6946510458), where `gss.go` is byte-identical to this head (blob `git rev-parse 50ce5c0:go/internal/protocols/framed/gss.go`).

## Questions to answer

1. Beyond the inspected entry points: is the mechanism list bound (8) enforced inside nested NegTokenInit/NegTokenResp?
2. Are NTLM message offsets/lengths checked against the token before reading flags or version?
3. Does only a closed label (mechanism name, ntlm message type) reach evidence, never a user, domain or workstation string (C17)?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzGSSNeverPanics` (1,879,169 executions in Codex's own 10 s run at `b0beb3a`)
- `make parity-go` (Go replay of all 7,430 committed cases, exact match, records included)
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/protocols/framed/gss.go`: whole file (552 lines, new)
- `go/internal/protocols/dnsx/dns.go`: changed lines 10, 125, 519-520
- `go/internal/ascii/ascii.go`: whole file (35 lines, new)
- `go/internal/names/hostname.go`: changed lines 7, 21
- Supporting tests (read only to answer a question above): `go/internal/protocols/framed/fuzz_test.go`

## Out of scope

- the LDAP entry points already inspected in 6946510458
- Python reference behaviour (frozen; Go is judged against it, and parity is already exact)
