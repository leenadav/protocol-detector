# chunk-28: Control-plane and dashboard differentials

Tier 1 · about 688 changed lines of code · contracts: C14, C15

**Exact scope**: `git diff dbe20f3 50ce5c0 -- migration/parity/control_diff.py migration/parity/server_diff.py` (4 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Drives the Go dashboard service and control plane and the reference with the same requests and compares responses; includes the id-canonicalization fix (`07b216e`).

## Questions to answer

1. Does the normalizer replace only volatile values (ids, times), so a real difference cannot be normalized away?
2. Can request order or timing make both sides agree by accident (for example both empty)?

## Already run (do not re-run)

- `make parity-control` (120 runs), `make parity-server` (424 exchanges): 0 differences
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `migration/parity/server_diff.py`: whole file (466 lines, new)
- `migration/parity/control_diff.py`: whole file (222 lines, new)

## Out of scope

