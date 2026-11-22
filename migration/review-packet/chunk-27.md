# chunk-27: Capture-level differentials: analyze and decrypt

Tier 1 · about 756 changed lines of code · contracts: C1, C13, C15, C16

**Exact scope**: `git diff dbe20f3 50ce5c0 -- migration/parity/analyze_diff.py migration/parity/decrypt_diff.py` (7 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Generated-capture differentials comparing the Go binary with the reference on rows, exit status and error text, and on key-log decryption.

## Questions to answer

1. Are generated captures varied enough to reach error paths (truncated blocks, bad link types), not only happy paths?
2. Is a run that produces no rows at all on both sides treated as a pass only when that is the expected result?
3. Are random seeds recorded so a failure is reproducible?

## Already run (do not re-run)

- `make parity-analyze`, `make parity-decrypt`: 0 differences at `50ce5c0`
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `migration/parity/analyze_diff.py`: whole file (354 lines, new)
- `migration/parity/decrypt_diff.py`: whole file (402 lines, new)

## Out of scope

