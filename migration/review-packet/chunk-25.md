# chunk-25: Parity comparator, family verification, reference fixes

Tier 1 · about 491 changed lines of code · contracts: C1-C18 (the gate itself)

**Exact scope**: `git diff dbe20f3 50ce5c0 -- migration/parity/compare.py migration/parity/gaps.json migration/parity/verify_families.py protocol_adapters/analyze_pcap.py protocol_adapters/coordinator.py protocol_adapters/events.py protocol_adapters/live_capture.py protocol_engine/applications.py protocol_engine/engine.py protocol_engine/extended.py protocol_engine/smarthome.py protocol_engine/wire.py protodetect.py schemas/live-event.schema.json` (20 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

The comparator that decides 0 differences (gaps and approved-delta lists, family claims), the computed `parity-verified` rule, and the Python reference's own changes on this branch: CoAP RFC 7252 (F-ADV-1), the generation counter (C18) and live-capture suppression, plus small reference edits (the port-table cache keyed by port list, the live-event schema field, `gaps.json`, the list of unsupported answers the comparator accepts).

## Questions to answer

1. Can an unlisted gap, a stale gap entry or an `unsupported` answer make the comparator report ok (Codex R2 of 2026-11-14)?
2. Is canonicalization limited to `content.digest` → `content.version`, so nothing else is silently normalized away?
3. Can `verify_families.py` promote a family whose cases were never all matched (count by kind, gaps, deltas)?
4. Reference CoAP change: is the Go `datagram_wire.go` change (chunk-07) the same rule, line for line?
5. `gaps.json`: does each listed gap name an exact case id and reason, so it cannot excuse anything else?

## Already run (do not re-run)

- `make parity` (Python reference on all 7,430 cases) and `make parity-go` (Go replay of all 7,430 committed cases, exact match, records included)
- the six planted-regression shapes in `test_migration_parity.py`
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `migration/parity/compare.py`: changed lines 16-30, 41-53, 108-117, 127-131, 142-150, 187-189, 209-211, 222-252
- `migration/parity/verify_families.py`: whole file (124 lines, new)
- `protocol_engine/wire.py`: changed lines 451-466, 476-483, 509-517
- `protocol_adapters/analyze_pcap.py`: changed lines 238-242, 699-749, 772-797
- `protocol_adapters/coordinator.py`: changed lines 17-22, 31, 69-70, 104-127, 172-173, 209, 298-299
- `protocol_adapters/live_capture.py`: changed lines 20, 388-424, 457-459, 468-475
- `protocol_adapters/events.py`: changed lines 13-15
- `protocol_engine/applications.py`: changed lines 57-62, 72
- `protocol_engine/engine.py`: changed lines 58-61, 146, 178, 287
- `protocol_engine/extended.py`: changed lines 16-30, 625
- `protocol_engine/smarthome.py`: changed lines 52-64, 145
- `protodetect.py`: changed lines 126-131
- `schemas/live-event.schema.json`: changed lines 506
- `migration/parity/gaps.json`: whole file (5 lines, new)
- Supporting tests (read only to answer a question above): `test_migration_parity.py`, `test_verify_families.py`

## Out of scope

- `protocol_fixtures.py` test vectors (Tier 3 data)
