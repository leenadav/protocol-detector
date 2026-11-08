# Python → Go migration: status ledger

Plan: "Python → Go migration: implementation and acceptance plan" (Lee, 2026-11-07). States per item:
implemented · independently verified · blocked · deferred. Every entry names SHAs and commands. This file
never claims production readiness; release thresholds are pending (plan §5 M9/M10).

## M0 — stabilize and freeze the comparison baseline

| item | state | evidence |
|---|---|---|
| Baseline commit | implemented | `c2b7cc3b4eeae4d17ec60d6ca5dc7164375a61b8` on `claude/v066-smarthome` (PR #18, draft). Range since the independently reviewed architecture head: `e7af436..c2b7cc3`, 17 commits (listed below). |
| §2.1 live restart on the cursor path | implemented; independently reported by Lee's follow-up review, repaired in `036932c` | `store.liveBusy()` on `live/events` and `live/snapshot`; `run/error` on a failed start; stale-run guards kept. `store.test.js` case 6. |
| §2.2 "Clear sessions & reset capture" with run identity | implemented from the plan's contract (the Mac checkout was never pushed; reconciliation owed when it is) | `c2b7cc3`: `POST /api/live/reset {run_id}` → `LiveManager.reset`; stale/absent run id is a no-op; key logs untouched; `live/reset` store action under run identity. Tests in `test_live_bridge`, `test_http`, `test_security`, `store.test.js` case 7, browser test. |
| §2.3 frontend-only port/transport labels | implemented | `selectors.displayLabel` → `8081 tcp` for outcomes only; `app`, filters, exports unchanged. Browser test checks the unknown demo session. |
| §2.4 lazy compatibility rows after parity checks | implemented | `9bbc9f4`; behaviour diff vs `e7af436` no differences at every commit; `test_sessions::LazyCompatResultsTests`. |
| §2.5 CI reconciliation | implemented; hosted runs green | engine branch `ci`/`codeql` green on `ca841c8` (runs 42385014524 / 42385014523); integration branch `claude/cicd-next` `fcacb42` (merges `ca841c8`) green on 16 checks incl. no-skip presentation-ui and installed check on the exact wheel (CI/CD lane, run 42385293567). `c2b7cc3` hosted result: to be read on the next check-in. |
| §2.6 documentation reconciliation | implemented | docs/DETECTION-PLAN-STATUS.md header/summary (Actions run again; D11 acted on; D09 blocked), PR #18 description rewritten. |
| Source patch inventory | implemented | the 17 commits below; no uncommitted local modifications in this checkout; the Mac checkout (`/Users/lee/Desktop/protocol-v059-publication`) is not reachable from this session (no shared folder), so its patch set is **not** inventoried here. |
| Whole-product manifest | implemented | `presentation/SOURCE.json` build digest `e7d15f286739d0a2` (123 files); `make check` verifies it. |
| Capability inventory | implemented | `migration/CAPABILITIES.json` from `tools/capabilities.py` (88 families: 63 tcp, 33 udp, 9 hint-only, 10 midstream-capable; 156 applications, 54 host-named; content release 2026.11.0 digest 991c007668d263d1); `make check` → `capabilities`. Every Go status is `pending`. |
| Baseline results | implemented (local, this host) | engine 813 tests OK; presentation 63 tests OK incl. Playwright browser test; `make check` OK; fuzz 476,000 cases OK; sequence relations 0 violations (3 seeds × 6); behaviour diff vs `e7af436`: none; installed check `--require-all` OK (server, page, demo replay 18 sessions, decryption demo 3 connections, suite against the wheel, zero skips); synthetic corpus report TP 1593 / FN 0 / FP 28 (docs/CORPUS-REPORT-V065.md, a regression gate); soak docs/SOAK-V065.json. Benchmarks: `migration/benchmarks/baseline-engine-c2b7cc3.json` (benchmark_engine 300 iterations: http_small 30.3 µs p50, http_fragmented 509 µs, tls_fragmented 61 µs, rules_30000 31.7 µs) and `baseline-perf-profile-c2b7cc3.json` (perf_profile: small HTTP flow decode 14 / engine 38 / adapter 221 µs p50; half-closed connection 6.1 KB held). |
| Environment record | implemented | `migration/benchmarks/environment-c2b7cc3.json` (cloud container, 4 vCPU Xeon 2.10 GHz, 16 GiB, Python 3.13.16 + 3.9.25, Node 22.22.0, Go 1.24.7 present). |
| Exceptions kept explicit | — | D09 acceptance blocked (no independent corpus); production SLO/capacity/soak unproven; D11 numbers local; hosted CI evidence applies to the commits each run contains. |

M0 exit assessment: a single named Python commit (`c2b7cc3`) represents the integrated product on this
branch; the local-only features exist here as contract implementations but Lee's Mac versions are not
integrated (they were never pushed); CI gates passed on `ca841c8` and the hosted result for `c2b7cc3` is
pending. D09 and SLOs stay documented blockers for release, not for M1/M2.

### Commits since the reviewed architecture head e7af436

0b20ff3 D01/D02/P2 · 9f0918c D03 · c449d13 D04 · 01549d4 D05 · 9cbc4a9 D06 · 855442b D07 · 799d358 D08 ·
4bcb8e4 D09 · af91747 D10 · 12cbf6c D11 · 8653231 D12 · 6ddc3ea A01/A14 · 726007d round-2 repairs ·
9bbc9f4 D11 follow-up · 036932c live restart P2 · ca841c8 CI patch · c2b7cc3 M0.

## M1 — contracts and differential harness

| item | state | evidence |
|---|---|---|
| Contract matrix | implemented | `migration/CONTRACTS.md`: 17 contracts (C1–C17: stream, datagram, end of input, adapter reassembly, sticky invalidation, QUIC isolation, hints, configuration/budgets, observation modes, layered identity, content pin, unknown reasons, output schemas, cursor APIs, cancellation, fail-closed errors, no plaintext/keys), each with its Python reference, what is fixed, the cases that check it and Go status `pending`. |
| Language-neutral fixtures | implemented | `migration/fixtures/cases.json` (schema 1, generated from the Python reference by `migration/parity/cases.py`, seeded and deterministic): 1366 cases — 861 stream (every labelled stream fixture as whole / whole+FIN / 1-byte chunks / 7-byte chunks / truncated half / seeded mutation, plus continuation, byte-budget and fingerprint options), 279 datagram (whole / half / mutated, hinted rows included), 226 session (Ethernet frames with timestamps through the Analyzer: plain, split, reordered, conflicting retransmission for every hint-free family; lifecycle idle/RST/reuse; observation modes; continuation; DNS; QUIC reordered assembly and assembly conflict with sticky invalidation). Expectations are full event sequences (kinds, revisions, observations with evidence tuples), final observations, metrics, per-packet events and session records. Outcome coverage: identified 739 / malformed 165 / incomplete 159 / unknown 66 / budget_exhausted 11 (stream+datagram); session records identified 170 / invalidated 55 / incomplete 2 / no_handshake 1. |
| Canonicalization | implemented, minimal | only `content.digest` → `content.version` (hash definition pending M6); no wall clock or generated identifiers exist in the compared paths. Approved semantic deltas live in `migration/parity/deltas.json` (empty), one path of one case each with a justification, validated by the test. |
| Differential comparator | implemented | `migration/parity/compare.py --backend python` or `--results <file>` (another backend's output in the same shape): exact structural diff, bounded report, `--report` JSON. Python vs Python on the committed cases: 1366 compared, 1366 matched, 0 mismatched / missing / extra / exempted. |
| Planted-regression proof | implemented | `--plant wrong-positive · missing-retraction · wrong-port · dropped-event · boundary-shift` each reported on exactly the case it touched (and no other). `test_migration_parity.py` (6 tests) proves zero diffs, that the committed inputs are current with the fixture tables, determinism, all five plants, outcome coverage and delta hygiene; `make check` → `parity`. |
| Performance comparator | deferred to M9 | separate from parity by design; Python baselines in `migration/benchmarks/`. |
| Exceptions kept explicit | — | cursor/lifecycle contracts (C14, C15) are HTTP-level and covered by the presentation tests named in the matrix, not by `cases.json`; schema parity (C13) is compared field by field on records, not by validating the Go output against `schemas/` yet (M7). |

M1 exit assessment: the contract matrix, the fixtures and the comparator exist and the comparator is proven
to detect the five regression shapes; Go has produced no results yet, so every contract is `pending`.

## M2 — Go foundation (minimal skeleton)

Branch: `claude/go-migration`, created from the M1 head `1b2b218` of `claude/v066-smarthome`; Go work stays here and
never edits the engine branch's snapshot. No migration PR is opened until authorized (plan §1).

| item | state | evidence |
|---|---|---|
| Toolchain | implemented | `go/go.mod` pins `go 1.27.3` (supported releases on 2026-11-07: 1.27.3, 1.26.10; the container's 1.24.7 is out of support and unused). Pure Go, standard library only; ADR 0002. |
| Typed contracts | implemented | `go/internal/contracts`: Status/Kind closed vocabularies, Evidence as the 4-tuple array, nullable fields, `Initial()` defaults, `Config` decoding over the Python defaults with unknown-field and non-positive-limit rejection. Tests: round trip of the Python shape, null lists never emitted, vocabularies closed, defaults; fuzz `FuzzObservationJSONNeverPanics`. |
| Fixture contract proof | implemented | `go/internal/parity` loads `migration/fixtures/cases.json` (bounded size, schema check, unique ids, cancellation between cases, fail-closed on bad expectations) and the test re-encodes every stream and datagram expectation (1140 cases) through the Go types with structural equality to the Python output. `protodetect cases` does the same from the CLI. |
| Bounded buffer primitives | implemented | `go/internal/buffer`: `Bounded` (per-direction limit, copies input, zeroes on discard/release) charging an `Account` (aggregate limit with a stated scope). Tests: input mutation after the call, per-buffer limit with scope and limit in the error, aggregate limit across buffers, discard/release accounting, zeroed tails; fuzz `FuzzAppendNeverExceedsLimits`. |
| Deterministic clock | implemented | `go/internal/clock`: `Clock` interface, `Real`, `Fake` (monotonic, settable). |
| Structured errors | implemented | `go/internal/errs`: codes malformed / budget / unsupported / invalid / cancelled, scopes direction / flow / capture / worker / process, limits named in budget errors, no input in details. |
| Cancellation | implemented (loader) | `parity.Load` honours context cancellation; the CLI wires SIGINT to the context. Engine-level cancellation arrives with M3. |
| Ownership/resource ADR | implemented | `migration/adr/0001-ownership-and-resources.md`; layout, toolchain and dependency policy in `0002-toolchain-layout-dependencies.md`. |
| Gate | implemented (local) | `make go-check`: gofmt, vet, `go test -race ./...` (6 packages OK), fuzz runs of both targets (15 s each locally, no failures). Hosted Go CI is the CI/CD lane's M10 work; not wired yet. |
| Not claimed | — | no detection capability exists in Go (`protodetect version` says so); `CAPABILITIES.json` keeps every Go status `pending`. |

M2 exit assessment: contract serialization, bounded allocation, input-mutation, cancellation and basic fuzz
tests pass; nothing panics on malformed input in the fuzzed surfaces. Pooling and concurrency are
deliberately absent (ADR 0001).

## M3 — session and reassembly infrastructure (Go)

| item | state | evidence |
|---|---|---|
| Frame decoding | implemented | `go/internal/transport`: Ethernet (≤2 VLAN tags), BSD/OpenBSD loopback, Linux cooked v1/v2, raw IPv4 → IPv4 TCP/UDP with the Python reject kinds (link, network, fragment, length, transport, checksum) and endpoints on a readable first fragment; checksum policies ignore/audit/verify. Tests: every reject kind, every link type, three-tag rejection, checksum policies, Python tuple ordering of endpoints, and all 1501 fixture frames decode under `verify`; fuzz `FuzzDecodeNeverPanics`. |
| Per-direction reassembly | implemented | `go/internal/reassembly.Stream`: modulo-2^32 offsets, lazy window allocation (never above 2 × limit), byte-compared overlaps checked **before** any byte of the segment is admitted, identical duplicates deliver nothing, gap fill delivers the whole newly contiguous run once, permanent failure after a conflict or an out-of-window segment (reason sentences identical to Python), prefix-only (live) clipping, zeroing release. The stream owns no inspector: it returns owned deltas, so one reassembler can serve the engine and a second consumer. |
| Exactly-once proof (trivial inspector) | implemented | `stream_test.go`: every split point in both orders, gap/fill/duplicates/consistent overlap, conflict before and after the gap (nothing admitted, stream unusable), wraparound, window limit, lazy allocation, input not retained, 300 seeded random permutations with consistent retransmits; fuzz `FuzzFeedInvariants` (delivered == contiguous ≤ stored ≤ highest_end ≤ limit, delivered bytes == retained prefix). |
| Connection lifecycle | implemented | `go/internal/session`: `Manager` (bounded table, idle expiry, open/feed/finish/close with the Python error sentences) and `Tracker` (port of `Analyzer.process` for TCP and the UDP flow table: SYN / SYN retransmission / SYN-ACK validation and retransmission / Fast Open rejection / RST / URG or missing ACK / FIN consistency rules / half close / both-FIN close / tuple reuse / connection limit / idle timeout / truncated-record end / handshake, asymmetric and midstream modes / midstream restart). Each direction ends through its `Sink` with the same reason sentence as Python; the engine attaches as a Sink in M4. |
| Differential proof against Python | implemented | `cases.json` session packets now carry `streams` (per direction: contiguous, stored, highest_end, SHA-256 prefix digest) and `tables` (tracked, connections, UDP flows) after every packet (`migration/parity/cases.py stream_state`). `TestSessionCasesMatchThePythonReassembly`: 226 session cases, 1501 packets; per-packet messages, both directions' windows and digests, and the three table sizes match Python exactly; the delivered bytes of every direction equal its retained prefix. 223 zero-payload FIN messages are left to the inspector (their wording depends on whether the observation changed) and are compared in M4. |
| Required sequences (plan M3) | implemented | split at every byte, out of order, identical/contradictory retransmits, holes, overlap before/after delivery, SYN retransmit, tuple reuse, wraparound, FIN-before-data, half close, RST, EOF (`Finish`), idle timeout, connection-table eviction, truncated capture record (`NoteInput`), modes. Documented unsupported behaviour is unchanged: Fast Open, URG, IPv4 fragments, IPv6. |
| Gate | implemented (local) | `go vet`, `go test -race ./...` (9 packages), fuzz targets for buffer, contracts, reassembly and transport in `make go-check`. |
| Deferred, named | — | pcap/pcapng file reading (`capture_stream.py`) and the live coordinator/queue are M4/M8 work; `reassembly.Stream` exposes `Allocated()` but is not yet charged to a `buffer.Account` (wired when the flow table owner exists in M4); compact/prefix-only tracking is implemented but not differential-tested (the live path is M8); CONNECT/LDAP/HTTP2 peer correlation (`open_shift`, replay) needs the engine and is M4/M6; session records and verdicts are M6. |

M3 exit assessment: public-adapter reassembly results match the baseline on every fixture packet; no byte of a
conflicting segment is admitted or delivered; all state is released on retirement (tables return to zero,
windows zeroed). Retained-memory limits under many short/half-open flows are measurable through
`Allocated()` but the aggregate account is not yet enforced in this layer (see deferred).

## M4 — first vertical slice (Go)

| item | state | evidence |
|---|---|---|
| Bounded dispatch | implemented | `go/internal/engine/dispatch.go` ports `dispatch.select` completely (every first-byte route and probe). `migration/parity/dispatch_cases.py` exports the Python decisions for every prefix length of every labelled stream fixture plus seeded mutations (`migration/fixtures/dispatch.json`, 10,621 prefixes); `TestSelectMatchesThePythonDecisionTable`: 0 differences. |
| Inspector | implemented (ported paths) | `go/internal/engine/inspector.go`: feed/end/invalidate with the Python metrics accounting, candidate selection, hint handling (selects, never establishes), structural shifts (CONNECT/Upgrade carrier → inner phase → merged `shifted` events). Not ported, explicit as `NotPorted`: signature/heuristic unknown buffering, post-identification continuation (SSH KEXINIT, STARTTLS watch, D07 continuation), fingerprints, certificate watch, decrypted-plaintext path. |
| HTTP/1 | implemented | `go/internal/protocols/httpx`: the text route's first-line dispatch (HTTP recognised; other text families end in `NotPorted` after the same gating checks, the 220 ambiguity and the POP3/IMAP/command syntax errors reproduced), start-line, header rules, Host authority, content-type/accept classes, auth scheme and challenge classes, Upgrade/WebSocket/h2c/CONNECT boundaries. |
| TLS hellos | implemented | `go/internal/protocols/tlsx`: ClientHello (SNI, ALPN, supported_versions, ECH outer/inner structure, weak-suite classes), TLS 1.2 and 1.3 ServerHello and HelloRetryRequest profiles with the Python unsupported/malformed sentences. 32 new hello vectors in `cases.py tls_cases()` (whole / 1-byte / 7-byte / truncated). |
| DNS layout | implemented | `go/internal/protocols/dnsx`: probe, the full `dns_details` validator (names with pointer rules, record walks, EDNS/TXT/SOA/MX/SRV/NSEC checks, NetBIOS record data, mDNS profiles, LLMNR flags) and the TCP framing parser. |
| Datagram inspector | implemented (DNS validators) | `go/internal/engine/datagram.go` ports the candidate preselection chain; a payload that selects any validator the Go backend lacks is `NotPorted` (the Python outcome cannot be known), never guessed. |
| Replay | implemented | `protodetect replay --cases … --out …` writes `{"backend": "go", "results": {...}}`; unanswerable cases are `{"unsupported": reason}`. Sessions run the tracker with the engine as the Sink (events per packet, windows, tables); records are M6. |
| Differential result | implemented | `make parity-go` → `compare.py --families http,tls,dns,mdns,netbios-ns,llmnr --ignore $.records`: **369 compared, 369 matched, 0 mismatched, 0 gaps in the claimed families; 1,125 unsupported with a named gap**. Matched by kind/family: stream http 55, tls 128, dns 6; datagram dns 12, mdns 25, netbios-ns 16, llmnr 9; session http 10, dns 4; plus every unported-family case whose outcome the dispatcher alone decides (unknown/incomplete/ambiguous) matched exactly. `go/internal/replay` runs the same comparison as a Go test. |
| Unit and fuzz | implemented | input not retained by the inspector, hint never establishes, unported options refused up front; `FuzzInspectorNeverPanics` (chunked feeds, metrics bounds, terminal invariants, datagram path), `FuzzSelectNeverPanics`. |
| Capability statuses | implemented | `migration/CAPABILITIES.json`: Go `experimental` for http, tls, dns, mdns, netbios-ns, llmnr with the matched counts and the named gaps; every other family stays `pending`. |
| Not claimed | — | no verdict/App-ID/record layer (M6); no pcap file reading or live capture (M8); UDP flows inside session replay (datagram flow state) are M6; continuation, fingerprints, certificates, signatures, heuristics are named gaps; zero-payload FIN messages are now compared for the ported families (they depend on the inspector) and skipped only through `unsupported`. |

| Feed-loop benchmark (engine only) | implemented (local, this host) | `migration/benchmarks/bench_compare.py --iterations 300 --rounds 5` writes `workloads.json` (the exact `benchmark_engine.py` bytes the Go backend answers), builds `protodetect`, and alternates Python and Go rounds (seed 402) on the same host; result `migration/benchmarks/engine-go-vs-python-1113a91.json`. Medians per flow, Python 3.13.16 vs Go 1.26.10, 4 vCPU container: http_small 45.5 µs vs 3.5 µs (13×); http_fragmented (6050 B in 190 chunks) 485.9 µs vs 19.8 µs (24×); tls_whole 57.0 µs vs 3.4 µs (17×); tls_fragmented 59.1 µs vs 3.0 µs (20×); http_after_identification (64 × 1 KiB after the request) 50.4 µs vs 2.3 µs (22×). Go allocations per flow: 26–39, 2.7–34 KB (the fragmented HTTP case copies its growing prefix; no pooling by ADR 0001). Scope: engine feed loop only, correctness asserted on every flow, no capture/reassembly/output, not SWG latency; relative numbers, no target claimed (plan M9). |

M4 exit assessment: positive, negative, ambiguity, budget and fragmentation parity holds on every answered case
of the claimed families, and the backend never advertises an unported profile as available. The engine
feed-loop benchmark runs on identical bytes in both languages (above); the adapter-level benchmark through
pcap input is M8/M9 work, so end-to-end CPU and memory remain unmeasured.

## M6 — App-ID, evidence semantics and session records (Go)

Taken before M5 so that session records become comparable for every family as it is ported.

| item | state | evidence |
|---|---|---|
| One versioned content source | implemented | `tools/export_content.py` writes `migration/fixtures/content.json` from the Python catalogs: 156 applications (host-named services included), the engine-label map, the server-name catalog tables of the current release (entries, service domains, exact web fronts), 41 flow risks, the closed vocabularies, and the content release with its digest and component digests. `make check` → `content-pack` fails when the Python content and the pack differ. |
| Fail-closed loading | implemented | `go/internal/content` validates like `applications._validate` and `host_apps.build_tables` (duplicate names/domains/web fronts, unknown category/technology/characteristic, port specifications, unresolved references, outcomes without entries, schema, release); `TestPackFailsClosed` covers eight corruptions plus garbage. |
| Verdicts | implemented | `go/internal/appid`: `session_verdict` rules in order (identified direction wins, server disagreement recorded, host catalog refines ssl/quic/web-browsing from a client-asserted name with the explicit reason, ECH outer never mapped, provider web fronts affiliate only; bidirectional ambiguity intersection; unknown before invalidated before insufficient-data before incomplete), web-application refinement (CONNECT, WebDAV, RPC-over-HTTP, gRPC, DNS-over-HTTPS, IPP/OCSP/SOAP), NetBIOS and TURN refinements, port usage incl. carrier ports after a shift, D03 attribution, midstream outcomes. Custom signatures and RuleIndex mappings are absent by construction (the Go engine never sets `application`). |
| Flow risks | implemented | `appid/risks.go` ports every `flow_risks` branch that needs no x509 helper; certificate-validity and key classification are unreachable until the certificates option is ported (M7). |
| Layered view and structured unknown reasons | implemented | `appid/layers.go` (wire-only: inner layer absent, identity basis, claims, chain), `appid/unknown.go` (`explain`, `session_unknown` with the inspector's resolved family and bytes received). |
| Session records | implemented | `go/internal/analyzer`: the tracker with the engine as each direction's sink, decision timing (`first_seconds`/`stable_seconds` from identified events), the UDP flow state (first identification kept, invalidation sticky, per-direction observations), record fields as `Analyzer._record` emits them (observation block, input quality → capture quality, layers, unknown, content pin). Telemetry, policy, hostnames-in-records, fingerprints, certificates and continuation summaries are not produced (named gaps). |
| Differential result | implemented | `make parity-go` now compares session **records** too (only `content.digest` is canonicalized, on both sides): 386 compared, 386 matched, 0 mismatched, 0 gaps in the claimed families; the 29 answered session cases (http, dns, lifecycle, modes, UDP dns) match record for record. Unit tests: verdict order, ports, host catalog/ECH/web front, ambiguity, web refinement, unknown codes. |
| Not claimed | — | content hash definition shared by both runtimes (the pack carries Python's digest; a Go-side recomputation is M6 follow-up once the hash input is specified language-neutrally); regex/signature subset, fingerprints, policy predicates, continuation (named gaps). |

## M5 — protocol profiles in bounded batches (Go)

### Batch 1 — text-route families and Telnet

| item | state | evidence |
|---|---|---|
| Families | implemented | ssh (identification line, KEXINIT reader, posture classes: kex class, weak-algorithm classes, Terrapin), smtp (EHLO/HELO identity, STARTTLS watch bounded by `max_headers`), nats (INFO/CONNECT over the bounded JSON profile: nesting, field and digit budgets, duplicate members, non-standard constants, type rules), imap (server greeting/capability lines, tagged client commands, STARTTLS), pop3 (status lines, client commands, STLS), ftp (command grammar, AUTH TLS, shared commands ambiguous), irc (registration lines, unprefixed server openings, `:`-prefixed server lines as the dispatched family), sip and rtsp (start-line and header framing incl. compact SIP names), telnet (two IAC commands). `go/internal/protocols/textroute`. |
| Engine | implemented | post-identification continuation ported (`continuing`, `refined`, `End` through a pending shift): an SSH banner publishes `updated`, the KEXINIT adds posture rows as `refined`; a bad KEXINIT keeps the identification silently; SMTP/IMAP/POP3/FTP STARTTLS-class boundaries open the TLS phase with `shift:<boundary>` as the hint source and merge as `shifted`. |
| Fixtures | implemented | `cases.py text_cases()`: 95 vectors × 4 chunkings + one budget case (381 stream cases) covering identifications, ambiguities (220 greeting, USER/PASS, untagged IMAP, FTP/IRC USER), malformed and budget outcomes; deterministic ClientHello for the shifts. |
| Differential result | implemented | `make parity-go` with the 16 claimed families: **852 compared, 852 matched, 0 mismatched, 0 gaps**; per family (stream/session): ssh 44/0, smtp 45/0, nats 60/4, imap 52/4, pop3 48/4, ftp 50/4, irc 96/4, sip 34/4, rtsp 26/4, telnet 22/4; records included. |
| Not claimed | — | HASSH and every fingerprint (option refused), signature contexts, the STARTTLS *server* correlation (LDAP-style peer opening), IRC/SMTP hints (hint-only routing for these families is not wired: `Ported` lists only text, tls, dns, irc, telnet). |

### Batch 2 — framed binary TCP families and two line protocols

| item | state | evidence |
|---|---|---|
| Families | implemented | postgresql (startup parameters, SSL/GSS requests with the `postgresql-sslrequest` shift, authentication, error and NegotiateProtocolVersion server messages), rfb (version banner), bittorrent (peer handshake), memcached (binary request/response headers, per-command size rules, status labels), fins (node address exchange, frame header), afp (DSI GetStatus/OpenSession with options), zmtp (3.0/3.1 greeting), bolt (handshake; version response only with the hint), rsync (daemon greeting), stomp (handshake frame, escapes, heart-beat). `go/internal/protocols/framed`: one `FrameParser` port (header, advertised size checked against `max_bytes` before the buffer grows, validation of the complete frame) plus the two line parsers. |
| Fixtures | implemented | `cases.py framed_cases()`: 63 vectors × 4 chunkings, three hinted Bolt responses, a STOMP header budget and a PostgreSQL byte budget (257 stream cases); identifications, malformed sizes, unsupported versions and budget outcomes. |
| Differential result | implemented | `make parity-go` with the 26 claimed families: **1284 compared, 1284 matched, 0 mismatched, 0 gaps**; per family (stream/session): postgresql 103/4, memcached 50/4, fins 42/4, stomp 41/4, afp 37/4, rsync 34/4, zmtp 32/4, bolt 31/4, rfb 18/4, bittorrent 14/4; records included. |
| Not claimed | — | giop (CDR reader), x11, x11-server and spice remain in a later batch; one DSI vector with an unknown command dispatches to kafka and stays a named gap. |

### Batch 3 — GIOP, X11 and SPICE

| item | state | evidence |
|---|---|---|
| Families | implemented | giop (1.2 KeyAddr Request/LocateRequest, Reply, LocateReply; the CDR cursor with message-relative alignment, sequence budgets from `max_line`/`max_bytes`, service-context count capped by `max_headers` and preflighted against the remaining bytes), x11 (client setup request; the server reply only under the `x11-server` hint), spice (link header with the client message tried before the reply layout). `go/internal/protocols/framed/desktop.go`, on the batch-2 frame base. |
| Fixtures | implemented | `cases.py desktop_cases()`: 38 vectors × 4 chunkings, eight hinted X11 replies × 2 chunkings and two GIOP budget cases (170 stream cases). |
| Differential result | implemented | `make parity-go` with the 29 claimed families: **1503 compared, 1503 matched, 0 mismatched, 0 gaps**; per family (stream/session): giop 100/4, x11 60/4, spice 52/4; records included. |

### Batch 4 — databases and data infrastructure

| item | state | evidence |
|---|---|---|
| Families | implemented | mysql (server HandshakeV10, HandshakeResponse41, SSLRequest with the `mysql-sslrequest` shift; hint only), mongodb (OP_MSG with CRC-32C from `hash/crc32` Castagnoli, the checksum budget checked from the fixed header, and the bounded BSON validator: depth 16, 128 documents, field and name budgets, wire-order body fields; hint only), tds (PRELOGIN request/response), tns (CONNECT/ACCEPT/REFUSE/RESEND), cql (v4 requests and four responses), kafka (request header). `go/internal/protocols/framed/database.go`, `bson.go`. |
| Fixtures | implemented | `cases.py database_cases()`: 39 automatic and 32 hinted vectors × 4 chunkings plus five budget cases (289 stream cases). |
| Fuzzing | implemented | `FuzzFramedNeverPanics` drives every framed parser, including the hint-only profiles the dispatcher never selects; part of `make go-check`. |
| Differential result | implemented | `make parity-go` with the 35 claimed families: **1912 compared, 1912 matched, 0 mismatched, 0 gaps**; per family (stream/session): mongodb 94/0, cql 74/4, tns 70/4, mysql 69/0, tds 48/4, kafka 38/4; records included. |
| Not claimed | — | A CQL v3 vector dispatches to `tpkt` and stays a named gap. |

## M5 batches 5+ / M7+ — next

Remaining registry batches (the other binary framed families; UDP/control/media; network and
smart-home; QUIC/DTLS/HTTP2/SMB2/Kerberos/LDAP/RDP with dedicated review) with record-level parity per batch; passive
TLS decryption (M7); frontend and API integration (M8); adapter-level benchmarks (M9); CI wiring with the CI/CD lane (M10).

## Open decisions and blockers

- Mac checkout patch set (reset, labels): needs a push or a description to reconcile with `c2b7cc3`.
- Codex round-3 result on `726007d`: pending (issue #2).
- Independent labelled corpus (D09): blocked on input.
- Release thresholds (latency, throughput, memory): unspecified by design; relative results only.
- Dedicated migration PR: to be opened only when authorized in the working session (plan §1); the branch `claude/go-migration` exists and is pushed.
