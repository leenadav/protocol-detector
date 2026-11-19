# chunk-13: Session tracker, App-ID, session ids, replay

Tier 1 · about 559 changed lines of code · contracts: C4, C10, C11, C12, C18

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/appid/appid.go go/internal/appid/layers.go go/internal/appid/risks.go go/internal/replay/replay.go go/internal/session/tracker.go go/internal/sessionid/sessionid.go` (14 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Connection tracker changes (UDP invalidation, tables), App-ID layers and risks, session id derivation (C18), and the replay command's case runner, which the parity gate depends on (`tcp_hint`/`udp_hint` session options, `28406ca`).

## Questions to answer

1. Replay: can an unknown session option be silently ignored, making a case pass without exercising what it names?
2. Session id: is it a keyed or salted digest that cannot be reversed to endpoints, and stable within one generation (C18)?
3. App-ID layers: can a client-asserted server name become `authenticated` identity anywhere (C10)?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential)
- `make parity-go` (Go replay of all 7,430 committed cases, exact match, records included); `make parity-control`: 0 differences
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/session/tracker.go`: changed lines 5, 49, 60-72, 88-91, 105, 129-146, 191-300, 313-321, 345-347, 369-370, 383-389, 426-430, 442-449, 478-481 (+3 more hunks)
- `go/internal/appid/appid.go`: changed lines 3-4, 13, 144, 168-172, 284-303, 318-324
- `go/internal/appid/layers.go`: changed lines 5-127, 139-141, 151, 172-215
- `go/internal/appid/risks.go`: changed lines 8-12, 64-66, 119-126, 250, 265-271
- `go/internal/sessionid/sessionid.go`: whole file (100 lines, new)
- `go/internal/replay/replay.go`: changed lines 7, 21, 78-80, 107-109, 140-173, 201-208, 243-253
- Supporting tests (read only to answer a question above): `go/internal/session/session_test.go`, `go/internal/sessionid/sessionid_test.go`

## Out of scope

- Python reference behaviour (frozen; Go is judged against it, and parity is already exact)
