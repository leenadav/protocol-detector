# chunk-20: TLS record decryption (decrypt/connection.go)

Tier 1 · about 764 changed lines of code · contracts: C8, C15, C16, C17

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/decrypt/connection.go` (1 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Per-connection TLS 1.2/1.3 record decryption from a key log (AES-GCM, ChaCha20-Poly1305 via vendored x/crypto): sequence numbers, key updates, nonce construction, and the plaintext handed to the inner inspector.

## Questions to answer

1. Is the per-record nonce built exactly per RFC 8446 5.3 / RFC 5288, with the sequence number never reused after a KeyUpdate?
2. Is an authentication failure terminal for that direction (no plaintext from a failed record, C16)?
3. Is buffered ciphertext/plaintext bounded per connection and in aggregate (C8)?
4. Can plaintext or key bytes reach a log line, error text or record (C17)?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzConnectionNeverPanics`
- `make parity-decrypt`, `make parity-live-decrypt`: 0 differences
- canary test (C17): no key-log secret in any output
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/decrypt/connection.go`: whole file (764 lines, new)
- Supporting tests (read only to answer a question above): `go/internal/decrypt/decrypt_test.go`

## Out of scope

- vendored x/crypto (Tier 3, `make go-vendor-check`)
