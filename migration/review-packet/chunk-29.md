# chunk-29: Live, schema and adversarial differentials

Tier 1 · about 713 changed lines of code · contracts: C5, C7, C13, C15

**Exact scope**: `git diff dbe20f3 50ce5c0 -- migration/parity/adversarial.py migration/parity/live_decrypt_diff.py migration/parity/live_diff.py migration/parity/schema_go.py` (5 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Live-capture differentials (replayed through the live monitor), output-schema validation of Go output, and the adversarial identification suite with its finding lists (F-ADV-1 at 1 of 2,000 noise datagrams).

## Questions to answer

1. Adversarial: does a listed finding that stops reproducing fail the suite (stale-entry rule), as documented?
2. Is the `honest` set per case strict enough (a misidentification counted as honest would hide a bug)?
3. schema_go: are all output kinds validated, not just session rows?

## Already run (do not re-run)

- `make parity-live`, `make parity-live-decrypt`, `make schema-go`, `make adversarial` (4,041 deception cases, both engines, 0 unlisted misidentifications)
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `migration/parity/live_diff.py`: whole file (190 lines, new)
- `migration/parity/live_decrypt_diff.py`: whole file (167 lines, new)
- `migration/parity/schema_go.py`: whole file (103 lines, new)
- `migration/parity/adversarial.py`: whole file (253 lines, new)

## Out of scope

