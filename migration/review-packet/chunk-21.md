# chunk-21: Key schedule and key-log capture

Tier 1 · about 551 changed lines of code · contracts: C15, C17, C18

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/decrypt/keys.go go/internal/keylogcap/capture.go go/internal/keylogcap/generations.go` (4 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

TLS 1.2 PRF and TLS 1.3 HKDF key derivation from key-log secrets, the key-log capture reader, and the one-generation-per-capture counter (C18, option 2).

## Questions to answer

1. HKDF-Expand-Label: are labels, context hashes and lengths exactly RFC 8446 7.1 (a wrong one silently yields garbage)?
2. Is a key-log line with the wrong secret length, a duplicate client random or a non-hex value refused, never truncated?
3. Are secrets zeroed or at least never copied into long-lived structures beyond the connection that needs them?
4. Generations: can two captures share a counter, letting one capture's keys decrypt the other's flows?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzAnalyzeNeverPanics`
- `make parity-decrypt`: 0 differences
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/decrypt/keys.go`: whole file (345 lines, new)
- `go/internal/keylogcap/capture.go`: whole file (168 lines, new)
- `go/internal/keylogcap/generations.go`: whole file (38 lines, new)
- Supporting tests (read only to answer a question above): `go/internal/keylogcap/keylogcap_test.go`

## Out of scope

- `tools/check_no_keylogs.py` policy (Tier 3)
