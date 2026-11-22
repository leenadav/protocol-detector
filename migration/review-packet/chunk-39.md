# chunk-39: Dashboard service: HTTP server

Tier 2 · about 706 changed lines of code · contracts: C14, C16, C17

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/serve/server.go` (1 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Local dashboard HTTP service (static page, API routes, CSP headers, token) that replaces the Python server when the binary is installed.

## Questions to answer

1. Note: `server.go` has no unit test of its own; it is covered by `make parity-server` only. Is that differential enough for the routes below, or is a direct test needed?
2. Is the token compared in constant time and required on every state-changing route?
3. Are request bodies size-limited before parsing, and is Host checked against loopback (DNS rebinding)?
4. Are CSP and other headers identical to the reference's (the parity gate compares them)?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential)
- `make parity-server`: 424 exchanges, 0 mismatched
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/serve/server.go`: whole file (706 lines, new)
- Supporting tests (read only to answer a question above): `go/internal/serve/pytext_test.go`

## Out of scope

