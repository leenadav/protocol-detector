# chunk-05: HTTP/2 route and SSH posture (textroute/http2.go, ssh.go)

Tier 1 · about 753 changed lines of code · contracts: C1, C3, C8, C10

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/protocols/textroute/http2.go go/internal/protocols/textroute/ssh.go` (5 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

HTTP/2 connection preface, SETTINGS and the first HEADERS frame (prior knowledge and h2c), gRPC detection; SSH banner and KEXINIT posture rows (v0.58) as `refined` continuation.

## Questions to answer

1. Are frame lengths checked against SETTINGS_MAX_FRAME_SIZE and the byte budget before buffering CONTINUATION frames?
2. Can a HEADERS + CONTINUATION sequence grow without bound or interleave another stream?
3. SSH: is the KEXINIT name-list grammar enforced (no empty names, commas, length bound) before posture is derived?
4. Is the Terrapin pairing (cipher and MAC per direction) computed only from the received lists?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzHTTP2StaysBounded`, `FuzzKexinitPostureMatchesTheOracle`
- `make parity-go` (Go replay of all 7,430 committed cases, exact match, records included)
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/protocols/textroute/http2.go`: whole file (632 lines, new)
- `go/internal/protocols/textroute/ssh.go`: changed lines 4, 56, 78, 95-108, 173-264
- Supporting tests (read only to answer a question above): `go/internal/analyzer/http2_test.go`

## Out of scope

- Python reference behaviour (frozen; Go is judged against it, and parity is already exact)
