# chunk-10: TPKT/RDP, datagram dispatch, budgets and contracts

Tier 1 · about 581 changed lines of code · contracts: C2, C4, C7, C8

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/buffer/buffer.go go/internal/contracts/contracts.go go/internal/engine/datagram.go go/internal/parsing/parsing.go go/internal/protocols/framed/tpkt.go go/internal/reassembly/stream.go` (11 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

TPKT/X.224 (RDP security negotiation, ISO-TSAP), the datagram candidate selection and UDP hint table, the shared contracts types, and the capacity-accounting buffer (Codex R3 of the 2026-11-14 review).

## Questions to answer

1. Datagram dispatch: can a hint ever turn a refused structure into an identification (C7)?
2. Is the candidate list order exactly the reference's, so an ambiguity is reported rather than the first match taken?
3. Buffer: is capacity (not only length) reserved before growth and returned on shrink, with no path that allocates first?
4. TPKT: is the X.224 length indicator checked against the TPKT length before reading the negotiation request?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzSelectNeverPanics`, `FuzzAppendNeverExceedsLimits`, `FuzzFeedInvariants`, `FuzzObservationJSONNeverPanics`
- `make parity-go` (Go replay of all 7,430 committed cases, exact match, records included)
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/protocols/framed/tpkt.go`: whole file (263 lines, new)
- `go/internal/engine/datagram.go`: changed lines 8-15, 24-90, 268-279, 290-305, 315-342, 361-367, 396-408, 419-424, 434-452
- `go/internal/contracts/contracts.go`: changed lines 216-260
- `go/internal/reassembly/stream.go`: changed lines 51-65
- `go/internal/parsing/parsing.go`: changed lines 47-49, 70-77
- `go/internal/buffer/buffer.go`: changed lines 6-13, 38, 83-86, 100-161, 173-184
- Supporting tests (read only to answer a question above): `go/internal/protocols/framed/tpkt_test.go`, `go/internal/buffer/buffer_test.go`, `go/internal/engine/postmerge_test.go`

## Out of scope

- Python reference behaviour (frozen; Go is judged against it, and parity is already exact)
