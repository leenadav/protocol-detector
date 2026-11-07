# Detection engine plan: status and evidence map (D01–D12)

Companion to the "Detection Engine: Correctness, Security and Product Maturity Plan" handed over on PR #18
(draft, branch `claude/v066-smarthome`). Every row names the commits, the tests, the measurements and the
limits that remain. States: open, in progress, done (acceptance met), blocked (acceptance input unavailable).
All verification is Claude-executed on the cloud container with synthetic traffic; GitHub Actions does not
run on this repository.

| item | state | implementation | verification | remaining |
|---|---|---|---|---|
| D01 QUIC assembly isolation | **done** | `QuicAssembler` entries keyed by (flow scope, QUIC version, DCID); the Analyzer passes `(source, destination)` as the scope (endpoints and direction) and its clock; idle expiry with the flow table, LRU eviction, `reset(scope)` when the flow ends; DCID/tuple reuse inside the idle window with different bytes is a reported contradiction, never a merge or migration (`protocol_engine/quic.py`, `datagram.py` `inspect(scope=, now=)`, `analyze_pcap.py`) | `test_quic_isolation.py`: same DCID on unrelated endpoints never combines (public Analyzer path with protected synthetic Initials), reordered and three-way-split fragments assemble, tuple reuse after expiry starts clean, bare inspector namespaces; `test_quic.py` adapted; behaviour diff vs the pre-change head: no differences | a bare `DatagramInspector` without a scope still shares one namespace per inspector (documented) |
| D02 contradictory CRYPTO overlaps | **done** | `assemble()` compares every overlapping pair before building and returns `complete`/`partial`/`conflict`; the assembler keeps a completed entry so a later contradiction is detected, marks the connection as a conflict until expiry, and `quic()` answers with `crypto_assembly=conflict` and `retracts=True`; the inspector turns that into an `invalidated` observation without hostname, ALPN or fingerprints; the Analyzer replaces the flow's established identification with it (session verdict `not-applicable`, no hostname, no fingerprints) | `test_quic_isolation.py`: reviewer reproduction, partial and exact-range contradictions in every permutation, agreeing overlaps with gaps stay partial, late contradiction after a published result withdraws it through the public path, nothing revives the connection, budget → `exhausted` (BudgetError on the packet path) | detector-correctness fix; no claim about a real-world exploit |
| P2 decision latency | **done** | `session_lifetime_seconds` (was `time_to_verdict_seconds`), `time_to_first_decision_seconds`, `time_to_stable_verdict_seconds`; session records carry `decision.first_seconds`/`stable_seconds` (schemas updated) | `test_decision_latency.py`: a connection identified at 0.02 s and retired at 300.5 s; undecided connections carry no decision; UDP flows decide on the first identified datagram | — |
| D03 affiliation vs family vs activity | open | | | |
| D04 typed policy predicates | open | | | |
| D05 observation modes | open | | | |
| D06 input quality contracts | open | | | |
| D07 budgeted continuation | open | | | |
| D08 content governance | open | | | |
| D09 independent corpus | open | | | |
| D10 stateful/metamorphic sequences | open | | | |
| D11 separated performance measurement | open | | | |
| D12 structured unknown reasons | open | | | |
| A01 whole-product artifact | open (gap carried from the v0.65 plan) | | | |
| A14 cursor-based live UI | open (gap carried from the v0.65 plan) | | | |
