# chunk-12: Session analyzer (analyzer/analyzer.go)

Tier 1 · about 693 changed lines of code · contracts: C4, C5, C9, C10, C12, C18

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/analyzer/analyzer.go` (12 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Packet-to-session analyzer: TCP/UDP tracking, both directions, session records, peer events, correlation (CONNECT, LDAP StartTLS), QUIC scope resets (R2), UDP invalidation withdrawal (R1) and the generation counter (C18, option 2).

## Questions to answer

1. Does every retirement path (FIN, RST, idle, table eviction, Finish) release sinks and produce exactly one record?
2. UDP: once a flow is invalidated, can any later datagram or the peer's retained identification revive it (R1)?
3. Are retained-sink counts bounded under many open/close cycles on one tuple (Codex R1 of 2026-11-14, `6375457`)?
4. Is any record field built from payload bytes other than the documented evidence (C17)?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential) incl. 1,000 open/close cycles per end reason
- `make parity-go` (Go replay of all 7,430 committed cases, exact match, records included) (1,055 session cases with records)
- `make parity-analyze`, `make parity-live`: 0 differences
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/analyzer/analyzer.go`: changed lines 5-59, 78-280, 289-340, 351-370, 382-384, 418-450, 493-897
- Supporting tests (read only to answer a question above): `go/internal/analyzer/analyzer_test.go`, `go/internal/analyzer/postmerge_udp_test.go`

## Out of scope

- the UDP flow rule (PM-1/PM-2, post-merge)
- Python reference behaviour (frozen; Go is judged against it, and parity is already exact)
