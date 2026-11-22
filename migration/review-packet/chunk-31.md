# chunk-31: CLI commands, part 2: live and serve

Tier 2 · about 618 changed lines of code · contracts: C14, C15

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/cmd/protodetect/live.go go/cmd/protodetect/serve.go go/internal/analyze/present.go` (5 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

`live` (capture loop options, `--check`), `serve` (the dashboard service entry point) and the present renderer.

## Questions to answer

1. Does `serve` bind only to loopback by default and refuse other addresses without an explicit option?
2. Are live limits validated (connections, bytes, CRC bytes) before capture starts?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzPresentNeverPanics`
- `make parity-live`, `make parity-server`
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/cmd/protodetect/live.go`: whole file (292 lines, new)
- `go/cmd/protodetect/serve.go`: whole file (105 lines, new)
- `go/internal/analyze/present.go`: whole file (221 lines, new)

## Out of scope

