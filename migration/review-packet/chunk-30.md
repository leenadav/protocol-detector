# chunk-30: CLI commands, part 1

Tier 2 · about 563 changed lines of code · contracts: C13, C15, C16

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/cmd/protodetect/analyze.go go/cmd/protodetect/controlreplay.go go/cmd/protodetect/decrypt.go go/cmd/protodetect/livedecrypt.go go/cmd/protodetect/main.go go/cmd/protodetect/present.go` (10 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

`analyze`, `decrypt`, `live-decrypt`, `present`, control replay: flag parsing, exit statuses (64 = not ported, the adapter falls back to the reference), stderr texts.

## Questions to answer

1. Is every not-ported path exit 64 with nothing written to stdout, so the Python fallback never mixes outputs?
2. Do invalid flags fail with the reference's usage text and status, never a partial run?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential) (cmd tests)
- `make parity-analyze`, `make parity-decrypt`
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/cmd/protodetect/analyze.go`: whole file (213 lines, new)
- `go/cmd/protodetect/controlreplay.go`: whole file (92 lines, new)
- `go/cmd/protodetect/decrypt.go`: whole file (73 lines, new)
- `go/cmd/protodetect/livedecrypt.go`: whole file (63 lines, new)
- `go/cmd/protodetect/main.go`: changed lines 28, 39, 48-63, 94-106
- `go/cmd/protodetect/present.go`: whole file (94 lines, new)
- Supporting tests (read only to answer a question above): `go/cmd/protodetect/main_test.go`

## Out of scope

- Python reference behaviour (frozen; Go is judged against it, and parity is already exact)
