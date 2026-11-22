# chunk-23: Decryptor and the live decryption run

Tier 1 · about 796 changed lines of code · contracts: C15, C16, C17

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/keylogcap/decryptor.go go/internal/livedecrypt/run.go` (3 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

The decryptor that feeds decrypted inner bytes to a layered inspector, and the `live-decrypt` run loop (signals, finalization, outputs).

## Questions to answer

1. Does SIGINT finalize exactly once and leave the key log unchanged (C15)?
2. Is the inner (decrypted) observation kept as a separate layer, never replacing the outer TLS identity (C10)?
3. Can a failure in the inner inspector abort the outer session or leak plaintext into an error?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential)
- `make parity-live-decrypt`: 0 differences
- `interrupt_test.go` (SIGINT) in `go test -race ./...`
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/keylogcap/decryptor.go`: whole file (453 lines, new)
- `go/internal/livedecrypt/run.go`: whole file (343 lines, new)
- Supporting tests (read only to answer a question above): `go/internal/keylogcap/keylogcap_test.go`, `go/cmd/protodetect/interrupt_test.go`

## Out of scope

- Python reference behaviour (frozen; Go is judged against it, and parity is already exact)
