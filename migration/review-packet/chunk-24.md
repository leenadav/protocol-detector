# chunk-24: Content-pack loader, digests and C11 rollback (both engines)

Tier 1 · about 785 changed lines of code · contracts: C11

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/content/content.go go/internal/content/digest.go migration/content_history.py protocol_engine/content.py tools/check_content.py` (14 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Go pack loader and the language-neutral release/pack digests (`migration/CONTENT-DIGEST.md`); `EmbeddedRelease` for `--content-version`; the C11 rule that earlier releases reproduce the digests they were published with (`d1b63ee`), in Python and Go. **Codex reviewed the digest delta `e57d294..7afc8f6` already (no code finding).**

## Questions to answer

1. `computeDigests(earlier=true)` recomputes only `host_catalog`: can a crafted history entry state any other component and pass?
2. Is the C11 refusal (`check_content.py --update`) unbypassable when a new release is cut?
3. Can an external `--content` pack be combined with `--content-version` in a way that runs an unverified catalog?
4. Is the pack digest computed over the CJ1 canonical form exactly as documented, including key order and escapes?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzCanonicalIsAFixedPoint`, `FuzzParseNeverPanics`
- `make content content-pack` and `make check`: ok
- `test_content.py` (C11 published digests, refusal paths) and `history_test.go` (earlier-release host catalog)
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/content/content.go`: changed lines 10-15, 116-124, 144-146, 244-251, 365-391, 419-482
- `go/internal/content/digest.go`: whole file (363 lines, new)
- `protocol_engine/content.py`: code only: lines 264-270 (`_hash`), 332-361 (`_host_component`, `component_digests`) and 418-470 (`check`, the C11 checks); lines 27-209 and 278-331 are release-history data tables (Tier 3, `make content`)
- `migration/content_history.py`: whole file (64 lines, new)
- `tools/check_content.py`: changed lines 28-34
- Supporting tests (read only to answer a question above): `go/internal/content/digest_test.go`, `go/internal/content/history_test.go`, `test_content.py`

## Out of scope

- `e57d294..7afc8f6` (reviewed)
- pack.json, history.json, content_lock.json and host data (Tier 3)
