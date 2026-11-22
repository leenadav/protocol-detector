# chunk-22: Key-log coordinator and live key-log tailing

Tier 1 · about 605 changed lines of code · contracts: C14, C15, C17, C18

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/keylogcap/coordinator.go go/internal/livedecrypt/decoder.go go/internal/livedecrypt/keylog.go` (4 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Coordinator that matches key-log entries to connections (retained tier), and the live key-log file tailer (append-only reading, truncation and rotation handling).

## Questions to answer

1. Tailing: is a truncated or replaced key-log file detected, and does it restart cleanly without replaying old secrets?
2. Is the retained tier bounded (connections waiting for keys, bytes held), with eviction reported?
3. Is the drain-before-`Retain` ordering (the earlier generation fix) preserved on every path?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzReplayNeverPanics`
- `make parity-live-decrypt`: 0 differences
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/keylogcap/coordinator.go`: whole file (412 lines, new)
- `go/internal/livedecrypt/keylog.go`: whole file (100 lines, new)
- `go/internal/livedecrypt/decoder.go`: whole file (93 lines, new)
- Supporting tests (read only to answer a question above): `go/internal/livedecrypt/livedecrypt_test.go`

## Out of scope

- Python reference behaviour (frozen; Go is judged against it, and parity is already exact)
