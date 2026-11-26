# Limits audit: every limit, counter and mixed outcome must reach the output (PRO-477)

Security reviewer (AppSec), read-only audit, 2026-11-26. Base: `main` at `6c6d4dd` (`claude/go-migration`, named in
the task, is fully merged into `main`, which is 364 commits ahead and adds the SEC-SESS-1 half-open budget).
Trigger: an external proof of concept (kidcarmi) found that the UDP flow limit was hit silently: 800 flows,
32 records, no counter. This audit asks the same question for every limit, budget, cap and eviction of the Go
engine, and for every place where a later result can hide an earlier one.

Outputs checked: `protodetect analyze` (rows and the summary row), `Present` (the presentation service and
`/api/analyze`), the live monitor's progress and summary events, the live control API (`/api/live/*`, the
versioned event log and its view), and the decrypt reports. There is no public Culvert package on this branch
yet (`go/detector` does not exist; `contracts/importgraph_test.go` waits for it), so "Culvert API" below means
the engine and analyzer types Culvert would embed: `analyzer.Analyzer` (`Records`, `LastEvents`, `Tracker`)
and the event log.

## Reproducers

Each gap has a test that reproduces it at scale and asserts the behaviour asked for. While the gap persists the
test skips with its finding id (`limitGap`, the convention of `engine/postmerge_test.go`); when a fix makes it
pass, it fails and asks for the marker to be removed. Synthetic frames only. They check their own reproducer
first and fail (never skip) if it drifts.

| ID | Test | Today (skip message) |
|---|---|---|
| SEC-LIM-1 | `analyze.TestLimitGapAnalyzeUDPFlowLimitInSummary` | 800 flows, 32 sessions, summary `{"frames":800,"sessions":32,"udp":800}` |
| SEC-LIM-2 | `analyze.TestLimitGapAnalyzeTCPConnectionLimitInSummary` | 768 `LIMIT` frame messages, no summary counter |
| SEC-LIM-3 | `analyze.TestLimitGapAnalyzeTCPWithoutStartInSummary` | 800 TCP data segments, 0 sessions, no counter |
| SEC-LIM-4 | `analyze.TestLimitGapPresentFlowLimitInMeta` | 800 flows, 256 sessions, no meta counter |
| SEC-LIM-5 | `analyze.TestLimitGapPresentSessionEventCap` | record carries 60 of 100 events, no marker |
| SEC-LIM-6 | `analyze.TestLimitGapAnalyzeUDPMixedOutcomeHidden` | frames identify dns and stun; record names dns only |
| SEC-LIM-7 | `live.TestLimitGapLiveUDPFlowLimitInSummary` | counts `identified:800, sessions:32`, no flow-limit entry |
| SEC-LIM-8 | `analyzer.TestLimitGapQUICAssemblerEvictionIsReported` | evicted CRYPTO state: SNI lost, reason "ClientHello incomplete" |
| SEC-LIM-9 | `analyzer.TestLimitGapUDPRecordHidesLaterCompleteObservation` | last datagram asserts SNI; record hostname `null` |
| SEC-LIM-10 | `livectl.TestLimitGapEventViewQualityOutlivesRetention` | after 4096 events a degraded run reads `quality: intact` |

Run them: `cd go && go test ./internal/analyze ./internal/analyzer ./internal/live ./internal/livectl -run LimitGap -v`.

## Every limit and where hitting it is reported

"Reported" means a counter or a reason in that output. MISSING is a gap; n/a means the output never runs the
limit.

| Limit (file) | Value | analyze | Present | live | Culvert-facing API | Test |
|---|---|---|---|---|---|---|
| UDP flow table, `session/tracker.go:489` | `MaxUDPFlows` (analyze 32, present 256, live = connections) | MISSING (`Tracker.Counts` never copied) | MISSING | MISSING | `Tracker.Counts["udp_flow_limit"]` only | SEC-LIM-1, -4, -7 |
| TCP tracked connections, `session/tracker.go:600` | `MaxConnections` (full of established connections) | MISSING (frame message only) | MISSING | `connection_limit` | frame message only | SEC-LIM-2 |
| TCP half-open budget (SEC-SESS-1), `session/tracker.go:290` | 3/4 of the table, 5 s | record with `end_reason` "Half-open budget full…"; counter `half_open_evicted` MISSING from the summary | record reason | record reason; counter MISSING | `Tracker.Counts` | SEC-LIM-1 (same fix) |
| UDP half-open budget (SEC-SESS-1), same | 3/4 of the flow table, 5 s | record reason; counter `udp_half_open_evicted` MISSING | record reason | record reason; counter MISSING | `Tracker.Counts` | SEC-LIM-1 (same fix) |
| Connection table, `session/manager.go` (`Open`) | `maxConnections` | as above (checked after the tracked limit, same value) | | | | SEC-LIM-2 |
| TCP start not observed, `session/tracker.go:616` | handshake mode | MISSING | MISSING | `tcp_without_start`, `tcp_control_without_state` | frame message | SEC-LIM-3 |
| Reassembly window, `reassembly/stream.go:120` | 1..65536 | invalidation reason (offline) | silent clip in prefix mode, then the parser's `budget_exhausted` | same | same | sound |
| Retained window and aggregate, `keylogcap/coordinator.go:379` | 256 KiB / 4 MiB | n/a | n/a | `budget.rejected_bytes` + reason | report | sound |
| Retained connections, `keylogcap/coordinator.go:327` | 64 | n/a | n/a | `budget.rejected_connections` (live report); offline refuses | report | sound (see note 1) |
| Retained consumer queue, `keylogcap/coordinator.go:147` | 8192 | n/a | n/a | `StreamError` ends the run, `events.dropped` | error | sound |
| QUIC CRYPTO assembler LRU, `quicx/assembler.go:270` | min(UDP flows, 1024) | MISSING | MISSING | MISSING | `Assembler.Counts` unexported via analyzer | SEC-LIM-8 |
| QUIC assembler idle expiry, `quicx/assembler.go:182` | idle timeout | MISSING | MISSING | MISSING | | SEC-LIM-8 (same fix) |
| QUIC server-name store, `quicx/assembler.go` (`MaxNames`, PRO-291) | 2 × flows + 2 | `NameEvictions` never output | | | | sound sizing (unreachable while names are reset with flows); counter MISSING, P3 |
| QUIC fragments/bytes, `quicx/assembler.go` | `MaxFragments`, `MaxCrypto` | status `exhausted` in the observation | same | same | same | sound (counter missing, status present) |
| Parser byte/header/line budgets (`framed`, `textroute`, `tlsx`, `hpack`) | per family | `budget_exhausted` status + reason | same | counted by status | same | sound |
| TLS continuation records, `tlsx/continuation.go:104` | 256 | continuation `end: records` | same | same | same | sound |
| HTTP continuation methods, `textroute/continuation.go:189` | 8 distinct | silent | silent | silent | silent | P3, no test (informational list) |
| Present frames / sessions / events, `analyze/present.go:90,105,114` | 20000 / 500 / 4000 | n/a | refusal (fail closed) | n/a | | sound |
| Present per-session events, `analyze/present.go:181` | 60 | n/a | MISSING | n/a | | SEC-LIM-5 |
| Live legacy deques, `livectl/state.go:20-21` | 200 events / 500 sessions | n/a | n/a | `events_total`, `sessions_total`, `retained_sessions` | snapshot | sound |
| Event log retention, `events/events.go:299` | 4096 | n/a | n/a | `start` / `reset_required` on the page | view quality MISSING | SEC-LIM-10 |
| Event retractions per envelope, `events/events.go:237` | 1024 | n/a | n/a | refused without a counter | | P3, unreachable today (live max 1024 connections) |
| Telemetry series, `telemetry/telemetry.go:103,127` | 64 | silent drop (the reference raises) | | | | P3, unreachable today (fixed names) |
| Key log size / entries, `decrypt/keys.go:207,244` | 256 Ki chars / 1024 | n/a | n/a | `budget_exhausted` error | | sound |
| Decrypt stream / records, `decrypt/connection.go:45,73` | 256 KiB / 65536 | n/a | n/a | `budget_exhausted` / unsupported reason | | sound |
| Live decryption capture / frames, `livedecrypt/decoder.go:42,50` | 2 MiB / 20000 | n/a | n/a | `budget_exhausted` error | | sound |
| Serve handlers, `serve/server.go:132` | 8 | n/a | n/a | `rejected_requests` in `/api/health` | | sound |
| Policy rules / file, signature counts, pack size, JSON depth | load time | refusal at load | | | | sound |

Note 1: the org memory's P2 on `livedecrypt/decoder.go:57` (rejected connections ignored by Live Feed): on
`f2e9916` the live report carries `budget.rejected_connections` and `rejected_bytes` (`keylogcap/capture.go:156`),
so the count is visible (checked on `6c6d4dd`). Whether the dashboard renders it is a presentation question; not re-raised here.

## Places where a later result hides an earlier one

| Where | What is hidden | Finding |
|---|---|---|
| `session/tracker.go:500-540` (`ProcessUDP`) | A flow keeps its first identified observation; a later datagram identifying another family leaves no trace on the record | SEC-LIM-6 |
| same | A later, complete QUIC ClientHello (SNI, ALPN) never replaces the first partial identification: record hostname `null` | SEC-LIM-9 |
| `events/events.go:681` (`View`) | Quality is reduced over the retained window only: a gap ages out and the run reads intact | SEC-LIM-10 |
| `analyze/present.go:181` | Events after the 60th of a session, an invalidation included | SEC-LIM-5 |
| TCP invalidation after identification | Reported: invalidation wins and is never revived | sound |
| UDP invalidation | Reported: withdraws the retained peer identification (R1 of PR #25) | sound |
| TCP shift (STARTTLS, CONNECT, h2c) | Reported as `shifted_from` | sound |

The same summary drop covers the tracker's other counters: `midstream_connections`, `asymmetric_connections`,
`connect_tunnels_correlated`, `ldap_starttls_correlated` and `http2_servers_expected` are counted in
`Tracker.Counts` and never reach the analyze summary or the live counts. The fix for SEC-LIM-1 (copy
`Tracker.Counts` into the summary) closes them together.

## Side observation for the engine lane (not a limits gap)

In the SEC-LIM-1 reproducer, a plain DNS query with ID 9 (`00 09 01 00 00 01 …`, one question `example.com A`)
is classified `budget_exhausted`, "A competing datagram candidate exhausted its budget", instead of `dns`: the
outcome is reported, so it is not silent, but a sender can choose DNS IDs that keep a DNS flow unidentified. It
deserves its own look (which candidate, and whether its budget should block a validated DNS parse).

## Parity note

Every gap above also exists in the Python reference (the Go port is faithful: `Analyzer.counts["udp_flow_limit"]`
is likewise not in the summary). Fixing them in Go changes output, so each fix needs approved entries in
`migration/parity/deltas.json`, or a Frozen-Python exception from Lee. That is the engine lane's call.
