# chunk-26: Case generator (parity/cases.py)

Tier 1 · about 819 changed lines of code · contracts: C1-C9 (what the gate exercises)

**Exact scope**: `git diff dbe20f3 50ce5c0 -- migration/parity/cases.py` (10 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Generator of the committed cases (`--head` label, byte-reproducible): coverage cases for nine families (`62b7668`), the CoAP profile cases, host-catalog samples. It must only add cases, never change an existing one's meaning.

## Questions to answer

1. Is generation deterministic (seeded RNGs only, sorted iteration) so regeneration is byte-identical?
2. Do the coverage cases exercise what their ids claim (session, mutated, foreign), or could a class be satisfied vacuously?
3. Can an expectation be computed from Go output anywhere (the reference must be the only oracle)?

## Already run (do not re-run)

- regeneration reproduces `cases.json` byte for byte (`make parity` uses the committed file)
- `make parity-go` (Go replay of all 7,430 committed cases, exact match, records included)
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `migration/parity/cases.py`: changed lines 268-925, 962-965, 1606-1607, 2572-2573, 2662-2814
- Supporting tests (read only to answer a question above): `test_migration_parity.py`

## Out of scope

- `migration/fixtures/cases.json` (generated, Tier 3)
