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
| Toolchain | implemented | `go/go.mod` pins `toolchain go1.27.4` as the build compiler (moved from 1.27.3 on 2026-11-10; supported releases then: 1.27.4, 1.26.11; the container's 1.24.7 is out of support and unused) and states `go 1.27.0` as the consumer minimum (2026-11-14, integration preparation; `make go-check` runs vet and race tests at both). Pure Go, standard library only; ADR 0002. |
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

### Batch 5 — industrial control

| item | state | evidence |
|---|---|---|
| Families | implemented | modbus (MBAP; request, response and exception shapes), dnp3 (link frame, header and block CRCs), ethernet-ip (encapsulation header), iec-104 (APCI; only U-format frames select automatically), opcua (HEL/ACK/ERR/RHE), s7comm (PDU header and Setup Communication; hint only until iso-tsap ports the `cotp-connect` shift). `go/internal/protocols/framed/ics.go`; the fuzz target covers all six. |
| Fixtures | implemented | `cases.py ics_cases()`: 41 automatic and 16 hinted vectors × 4 chunkings plus an OPC UA byte budget (229 stream cases). |
| Differential result | implemented | `make parity-go` with the 41 claimed families: **2209 compared, 2209 matched, 0 mismatched, 0 gaps**; per family (stream/session): modbus 74/4, opcua 65/4, s7comm 54/0, ethernet-ip 34/4, dnp3 30/4, iec-104 30/4; records included. |
| Not claimed | — | iso-tsap stays with the TPKT route and RDP in the dedicated-review batch; bacnet is a datagram family for the UDP batch. |

### Batch 6 — messaging and RPC

| item | state | evidence |
|---|---|---|
| Families | implemented | mqtt (3.1.1/5.0 CONNECT, v5 properties, Will and UTF-8 rules), resp (command array; numeric headers capped at 24 bytes, numbers beyond int64 treated as over budget), amqp (protocol headers, 0-9-1 Connection.Start), onc-rpc (TCP record marking, CALL/REPLY, opaque_auth with AUTH_SYS), diameter (CER/CEA AVP framing and mandatory AVPs). `go/internal/protocols/framed/messaging.go`, `rpc.go`; the fuzz target covers all five. |
| Fixtures | implemented | `cases.py messaging_cases()`: 59 vectors × 4 chunkings plus three budget cases (239 stream cases). |
| Differential result | implemented | `make parity-go` with the 46 claimed families: **2507 compared, 2507 matched, 0 mismatched, 0 gaps**; per family (stream/session): onc-rpc 80/4, diameter 69/4, mqtt 63/4, resp 41/0, amqp 34/4; records included. |
| Not claimed | — | The ONC RPC UDP datagram path waits for the datagram batch (a named `datagram candidate` gap). The engine test that checks an unported hint is refused now names smb2 instead of the newly ported mqtt. |

### Batch 7 — routing, tunnels and FastCGI

| item | state | evidence |
|---|---|---|
| Families | implemented | bgp (OPEN, capability parameters), openvpn (TCP-framed hard-reset control packets, plain and tls-auth layouts), pptp (SCCRQ/SCCRP), fastcgi (BEGIN_REQUEST and the PARAMS stream across records, or one application-server record; record, wire-size and parameter budgets). `go/internal/protocols/framed/routing.go`; the fuzz target covers all four. |
| Fixtures | implemented | `cases.py tunnel_cases()`: 38 vectors × 4 chunkings plus three budget cases (155 stream cases). |
| Differential result | implemented | `make parity-go` with the 50 claimed families: **2722 compared, 2722 matched, 0 mismatched, 0 gaps**; per family (stream/session): fastcgi 68/4, bgp 47/4, openvpn 44/4, pptp 44/4; records included. |
| Not claimed | — | The OpenVPN UDP datagram path waits for the datagram batch. |

### Batch 8 — DCE/RPC, WebSocket, XMPP and syslog

| item | state | evidence |
|---|---|---|
| Families | implemented | dcerpc (bind, bind_ack, bind_nak; both data representations), websocket (one frame header; reached through the HTTP upgrade shift or a hint), xmpp (stream header in both directions with the asserted `xmpp_stream` hostname; the declaration's quote pairs are spelled out because RE2 has no backreferences, and attributes are scanned byte by byte so the 64/1023 bounds count bytes as in Python), syslog (RFC 5424 over RFC 6587 TCP framing). `go/internal/protocols/framed/services.go`; the fuzz target covers all four. |
| Fixtures | implemented | `cases.py service_cases()`: 44 automatic and 11 hinted vectors × 4 chunkings plus five budget cases (225 stream cases). |
| Differential result | implemented | `make parity-go` with the 54 claimed families: **3011 compared, 3011 matched, 0 mismatched, 0 gaps**; per family (stream/session): syslog 82/4, xmpp 76/4, dcerpc 71/4, websocket 50/0; records included. |
| Reference discrepancy | open | The Python syslog profile checks timestamp values with `datetime.fromisoformat`, which accepts 1-6 fraction digits on Python 3.11+ but only 3 or 6 on Python 3.9; RFC 5424 allows 1-6. Go follows the fixtures' generator (3.11+ semantics). The fixtures use 3- and 6-digit fractions only, so `make parity` agrees on both interpreters (verified on 3.9.25). Fixing the Python reference (an explicit date check) is a separate engine-lane change. |
| Not claimed | — | The syslog UDP datagram path waits for the datagram batch; git (the git/text discriminator) is next. |

### Batch 9 — Git and a fuzz-found repair

| item | state | evidence |
|---|---|---|
| Families | implemented | git (pkt-line service requests with `host=`, extra parameters and version offers; the first server pkt-line: ref advertisement or `version 2`). The git/text discriminator (`git_text`) scans for the first NUL or LF within `max_line`, replays that field once into the git or text parser and forwards `ResolvedFamily`/`Refined` to it. `go/internal/protocols/framed/git.go`. |
| Fixtures | implemented | `cases.py git_cases()`: 23 vectors × 4 chunkings plus a hinted case and three budget cases (96 stream cases). |
| Repair | implemented | The engine fuzz target found a panic in the batch-2 PostgreSQL port: an 8-byte v3 startup ends in `\0\0` through its version bytes, and `data[8:len-1]` inverted where Python's slice clamps to empty. Fixed to clamp; the crashing input is kept as `go/internal/engine/testdata/fuzz/FuzzInspectorNeverPanics/8088a95f887cfb87`, and `postgresql-empty-startup` joins the fixtures ("PostgreSQL startup requires a user" in both backends). Every other end-relative slice in the framed package was audited and is guarded by an earlier length or terminator check. |
| Differential result | implemented | `make parity-go` with the 55 claimed families: **3130 compared, 3130 matched, 0 mismatched, 0 gaps**; git 114 stream / 4 session cases; records included. |

### Batch 10 — NetBIOS session, TACACS+ and SOCKS5

| item | state | evidence |
|---|---|---|
| Families | implemented | netbios-ss (session request names), tacacs-plus (header, unencrypted START and REPLY bodies), socks5 (both directions; IPv6 targets formatted by `net/netip`, matching Python's `ipaddress` text including IPv4-mapped addresses). `go/internal/protocols/framed/sessions.go`; the fuzz target covers all three. |
| Fixtures | implemented | `cases.py session_cases_v()`: 30 vectors × 4 chunkings plus the longest SOCKS5 client exchange (121 stream cases). |
| Differential result | implemented | `make parity-go` with the 58 claimed families: **3292 compared, 3292 matched, 0 mismatched, 0 gaps**; per family (stream/session): socks5 69/4, tacacs-plus 60/4, netbios-ss 22/4; records included. |
| Not claimed | — | smb1 needs the GSS token classifier and moves to the dedicated-review batch with smb2, kerberos and ldap; SOCKS5 signature contexts (`retain_contexts`) remain with the signature option. |

### Batch 11 — the Go datagram inspector generalized; first UDP validators

| item | state | evidence |
|---|---|---|
| Engine | implemented | `engine.Datagram` runs a validator table (`framed.DatagramValidators`) beside the DNS layout. A validator returns either a bare (protocol, reason) result, for which the inspector adds the `application_protocol` row, or a full match with encryption and evidence rows carrying their final provenance; the hint row, ambiguity, competing-budget and error-precedence rules are unchanged. |
| Validators | implemented | syslog (the RFC 5424 profile shared with TCP), onc-rpc (shared `rpcParse`, `wire:` provenance), openvpn (shared hard-reset check), wireguard and bacnet. `go/internal/protocols/framed/datagram.go`. |
| Fixtures | implemented | `cases.py udp_cases_1()`: 20 payloads, whole and truncated (40 datagram cases). |
| Differential result | implemented | `make parity-go` with the 60 claimed families: **3370 compared, 3370 matched, 0 mismatched, 0 gaps**; datagram: onc-rpc 20, wireguard 14, bacnet 13, openvpn 10, syslog 9; records included. |

### Batch 12 — more UDP validators

| item | state | evidence |
|---|---|---|
| Validators | implemented | tftp, ntp (hint), l2tp, coap, rip, rtcp (hint), lifx-lan, tuya-lan (CRC32 via `hash/crc32`), and ethernet-ip over UDP (one complete encapsulation message, reusing the TCP parser). UDP validators now receive both budgets (`framed.Limits`: max_bytes, max_headers), so L2TP's AVP budget reads `min(max_headers, 64)` as in Python. `go/internal/protocols/framed/datagram_wire.go`. |
| Fixtures | implemented | `cases.py udp_cases_2()`: 42 payloads, whole and truncated, plus an L2TP AVP budget case (85 datagram cases). |
| Differential result | implemented | `make parity-go` with the 68 claimed families: **3500 compared, 3500 matched, 0 mismatched, 0 gaps**; datagram: tftp 27, lifx-lan 19, rip 19, l2tp 17, ntp 14, coap 13, rtcp 11, tuya-lan 9, ethernet-ip 7; records included. |
| Not claimed | — | tplink-smarthome parses its de-obfuscated payload with Python's `json.loads` (NaN/Infinity, duplicate keys, big numbers), which needs a faithful bounded JSON port of its own. |

### Batch 13 — flow export, STUN/TURN, DHCP and RADIUS

| item | state | evidence |
|---|---|---|
| Validators | implemented | netflow (v5 records, v9 flowsets) and ipfix, sflow (v5), stun (Binding and the TURN methods; FINGERPRINT checked with `hash/crc32`), dhcp (v4 options), radius (four codes; hint only). `go/internal/protocols/framed/datagram_services.go`. |
| Fixtures | implemented | `cases.py udp_cases_3()`: 30 payloads, whole and truncated, plus a RADIUS attribute budget case (61 datagram cases). |
| Differential result | implemented | `make parity-go` with the 74 claimed families: **3601 compared, 3601 matched, 0 mismatched, 0 gaps**; datagram: netflow 14, ipfix 7, sflow 9, stun 31, dhcp 18, radius 27; records included. |
| Not claimed | — | ssdp (needs the HTTP line parser exposed outside the text route), sip over UDP (same), snmp (BER profile, next), rtp (hint), tplink-smarthome (faithful `json.loads`), kerberos, quic, dtls and ikev2 (dedicated review). |

### Batch 14 — SNMP and RTP

| item | state | evidence |
|---|---|---|
| Validators | implemented | snmp (v1/v2c PDUs, v1 traps, v3 with USM security parameters and a plaintext or encrypted scoped PDU; the BER helpers `berLength`/`berField` port `framing.ber_length`/`ber_field`; OID subidentifiers bounded as in Python), rtp (hint only). `go/internal/protocols/framed/snmp.go`. |
| Fixtures | implemented | `cases.py udp_cases_4()`: 23 payloads, whole and truncated (46 datagram cases). |
| Differential result | implemented | `make parity-go` with the 76 claimed families: **3673 compared, 3673 matched, 0 mismatched, 0 gaps**; datagram: snmp 58, rtp 15; records included. |

### Batch 15 — SSDP and SIP over UDP

| item | state | evidence |
|---|---|---|
| Validators | implemented | ssdp (one complete HTTP header block plus the SSDP headers of its start line) and sip over UDP (the text route must resolve to SIP and finish; a Content-Length must equal the bytes after the headers). The text route gains `Options.ForceHTTP` (Python's `LineParser(config, "http")`: the first-line route is skipped, the start line is still validated) and a read-only `ControlField` accessor; UDP validators also receive `max_line`. `go/internal/protocols/framed/datagram_text.go`. |
| Fixtures | implemented | `cases.py udp_cases_5()`: 15 payloads, whole and truncated, plus an SSDP header budget case (31 datagram cases). |
| Differential result | implemented | `make parity-go` with the 77 claimed families: **3710 compared, 3710 matched, 0 mismatched, 0 gaps**; datagram: ssdp 20, sip 17; records included. The first run caught a bug in the new option (the start-line branch was skipped with the route), fixed before commit. |

### Batch 16 — TP-Link Smart Home

| item | state | evidence |
|---|---|---|
| Validator | implemented | tplink-smarthome: one pass undoes the autokey with the printable-ASCII and nesting checks in byte order, then `jsonDocument` decides whether the plaintext is one JSON document. It ports the grammar of CPython's `json.loads` (C scanner, defaults) rather than using `encoding/json`, because the two differ where the reference accepts `NaN`/`Infinity`/`-Infinity` and where it refuses an integer literal of more than 4300 digits (`sys.int_info.default_max_str_digits`, a `ValueError` the Python validator reports as malformed). A repeated key keeps its first position and last value, as a Python dict does. Only module names from the fixed vocabulary are emitted. `go/internal/protocols/framed/kasa.go`. |
| Fixtures | implemented | `cases.py udp_cases_6()`: 56 payloads, whole and truncated (112 datagram cases, 4027 total): literals, number forms, escapes and surrogates, repeated keys, trailing data, the nesting budget at 8 and 9, the digit limit at 4300 and 4301. |
| Go tests | implemented | `kasa_test.go`: grammar table, key order and last-value rule, the six validator outcomes, no value in evidence; fuzz `FuzzKasaNeverPanics` (no panic; verdict equal to `encoding/json` on printable ASCII outside the Python-only rules), added to `make go-check`. |
| Differential result | implemented | `make parity-go` with the 78 claimed families: **3828 compared, 3828 matched, 0 mismatched, 0 gaps**; datagram: tplink-smarthome 118; records included. Matched on the first run. One-off check outside the committed set: 30,000 seeded mutations of the vectors through both backends, 30,000 matched (832 identified, 26,496 malformed, 2,672 unknown). |
| Stated dependency | resolved | the 4300-digit limit was CPython's default (absent before the 3.9.14 / 3.10.7 security releases, adjustable with `PYTHONINTMAXSTRDIGITS`); since review R6 it is the explicit profile limit `smarthome.MAX_JSON_INTEGER_DIGITS`, enforced by a `parse_int` hook on every interpreter. |

### Batch 17 — Kerberos

| item | state | evidence |
|---|---|---|
| Validator | implemented | kerberos over TCP (`NewKerberos`: 4-byte record length, extension bit refused, 40-byte minimum) and UDP: AS/TGS-REQ, AS/TGS-REP and KRB-ERROR with the Python field walk (context tags strictly increasing, interleaved checks in the order of the Python generator), required field sets, pvno/msg-type, padata count bounded by `min(max_headers, 32)`, GeneralizedTime, microseconds 0..999999, error codes 0..127, non-empty realms and principals. Etype rows (offered, preferred, reply, ticket) follow the Python helpers, which drop the rows on any error, budget included, without rejecting the message. No principal, realm, ticket or pre-authentication value is emitted. `go/internal/protocols/framed/kerberos.go`. |
| Fixtures | implemented | `cases.py kerberos_cases()`: 37 vectors (requests with weak, other, negative, non-minimal, empty, 32 and 33 etypes; replies with kvno, short tickets, empty ciphers; KRB-ERROR codes, times, microseconds, realms, sname, ctime, e-text, e-data; unknown tag; trailing byte) as streams (whole / 1-byte / 7-byte / truncated) and datagrams (whole / truncated), plus padata budget, extension bit and byte budget options (226 cases, 4253 total). |
| Go tests | implemented | `kerberos_test.go`: etype rows and provenance, rows dropped on a non-minimal etype, byte-at-a-time stream feed, scope, TCP framing rejections, tag/trailing/pvno/order rejections; `NewKerberos` joins `FuzzFramedNeverPanics`. |
| Differential result | implemented | `make parity-go` with the 79 claimed families: **4084 compared, 4084 matched, 0 mismatched, 0 gaps**. Matched on the first run. One-off check outside the committed set: 20,000 seeded mutations of the vectors, each as a datagram and as a TCP stream (40,000 cases), all matched. |

### Batch 18 — SPNEGO/GSS token classifier and LDAP

| item | state | evidence |
|---|---|---|
| Token classifier | implemented | `gss.classify_token` in Go (`classifyToken`, `go/internal/protocols/framed/gss.go`): raw NTLMSSP, direct Kerberos GSS tokens (TOK_ID then exactly one AP-REQ, AP-REP, KRB-ERROR or user-to-user TGT-REQ; the KRB-ERROR case reuses `kerberosBody`), SPNEGO NegTokenInit and NegTokenResp with a carried NTLMSSP or Kerberos token, and other GSS mechanisms. Bounds are the Python ones: 4096-byte token, 8 listed mechanisms, 8 principal name components. Only closed labels are returned (kind, mechanism, NTLM message, negState); principals, realms, tickets, challenges and MICs are not decoded. It is unexported and reachable only through the LDAP parser until SMB is ported. |
| LDAP parser | implemented | `binary.LDAPParser` in Go (`NewLDAP`, `ldap.go`): BindRequest (simple, SASL, `GSS-SPNEGO` credentials through the classifier), BindResponse (LDAPResult, at most 16 non-empty referrals, optional server credentials), ExtendedRequest and ExtendedResponse (numeric OID grammar, StartTLS without a value). A named StartTLS success sets the `ldap-starttls` shift with the `tls` hint; DN, diagnostic text, credentials and extended values are not emitted. |
| Fixtures | implemented | `cases.py ldap_cases()`: 151 vectors as streams (whole / 1-byte / 7-byte / truncated), a ServerHello after the named, unnamed and refused StartTLS responses (separate and coalesced), and a byte budget (597 cases, 4850 total). |
| Go tests | implemented | `ldap_test.go`: classifier labels and rejections (budgets included), closed labels on a `GSS-SPNEGO` bind, no classification under another SASL mechanism, shift only on a named success, OID grammar; fuzz `FuzzGSSNeverPanics` (classifier and message validator, labels stay in the closed sets) added to `make go-check`; `NewLDAP` joins `FuzzFramedNeverPanics`. |
| Differential result | implemented | `make parity-go` with the 80 claimed families: **4733 compared, 4733 matched, 0 mismatched, 0 gaps**. Matched on the first run. One-off checks outside the committed set: 40,000 seeded byte mutations of the vectors (39,932 compared and matched; 68 dispatched to families not yet ported) and 40,000 structure-aware mutations of the tokens inside a well-formed bind (40,000 matched, 109 distinct reasons). |
| Host correlation | implemented (after batch 18) | see "Host-side shift correlation" below. |

### Host-side shift correlation (LDAP StartTLS, HTTP CONNECT)

| item | state | evidence |
|---|---|---|
| Inspector | implemented | `OpenShift(boundary, expected)` and `Replay(data)` port `Inspector.open_shift` / `replay` (terminal unshifted identification, 64-byte budget floor, `:peer` shift source, replayed bytes not counted twice); the LDAP message id travels as `parsing.Result.LDAPMessageID`, never as evidence; `Announcement` keeps the identification that announced a shift after the shifted phase merges. |
| Analyzer | implemented | `Tracker.Correlate` runs after a data segment's identifications are recorded and before its FIN is applied, as in Python; `correlateConnect` (server 2xx to CONNECT opens the tunnel phase) and `correlateLDAP` (a success for the same message id opens the client, and the server when unnamed); bytes a direction carried past its message are replayed from the reassembly window once; replayed events of the packet's direction join its events, the other direction's are `PeerEvents`; a replay marks that direction changed for its next segment. HTTP/2 prior-knowledge correlation (`_correlate_http2`) waits for the HTTP/2 port. |
| Reference fix | implemented | Found while porting: a named StartTLS success coalesced with the ServerHello shifted the Python server inside that packet, so `_correlate_ldap` compared the request with a TLS observation and never opened the client (record `ldap`, client `ldap`, although the client carried the ClientHello). `Inspector.announcement` and the correlation's fallback to it fix both runtimes; `test_v054` regression (fails without the fix). |
| Fixtures | implemented | `cases.py correlation_session_cases()`: 20 sessions (CONNECT tunnel, coalesced ServerHello, early ClientHello, refusal, GET 200; LDAP named, unnamed, early and coalesced ClientHello, refusal, other message id, whoami success, response before request, bind followed by a response; FIN and no-FIN variants), 5385 cases in total. |
| Differential result | implemented | `make parity-go`: all 20 correlation sessions match with packets, peer events and records. One-off checks outside the committed set: 12,000 random conversations (seeds 5, 11 and 12, 4,000 each; random message ids, names, result codes, coalescing, interleaving, segment splits and FIN placement) matched. |

## Independent review of 2026-11-14 (snapshot `dbe20f3`, issue #2 comment 6877159227)

Each finding was reproduced before it was changed. Commits are on `claude/go-migration` after batch 18 (`a2cf4e8`).

| finding | verdict | change and evidence |
|---|---|---|
| R1 (P1) retired TCP inspectors accumulate and are scanned per packet | confirmed | `6375457`: the connection owns its sinks; the analyzer keeps only the sinks the packet in progress reached and forgets them at the next packet or at `Finish`. `analyzer_test.go`: 1000 open/close cycles on one tuple with `MaxConnections=1` ending by RST, FIN and idle expiry (records drained; at most two sinks retained; 1000 records; request events reported), 50 open connections released by `Finish`, an invalidation event kept across the retirement in the same packet. Parity unchanged. |
| R2 (P1) the differential gate passes when every capability disappears | confirmed | `321e088`: unsupported answers are accepted only when `migration/parity/gaps.json` lists the case id with exactly that reason; unlisted, reworded and stale entries fail, unknown result ids fail, every `--families` name needs a matched case. The reviewer's reproduction now returns `ok=False` with 4850 unlisted gaps. Sixth planted regression `supported-to-unsupported`. `replay_test.go` applies the same list. |
| R3 (P2) the account releases bytes whose backing arrays stay allocated | confirmed | `e3200fd`: the account counts allocated capacity, reserved before allocation and returned when an array is freed or replaced by a smaller one; the per-buffer limit still counts logical bytes. Regressions for the 100-buffer case, kept capacity, reuse, shrink, growth and refused growth; the fuzz target checks `Cap() == Used()`. ADR 0001 updated. No parser uses `Account` yet, as the review notes. |
| R4 (P2) Go `Config` rejects `max_crc32c_bytes=0` and has no upper bounds | confirmed | `181fcbe`: one table, `contracts.ConfigRanges`, with the nine inclusive ranges of `model.Config.__post_init__`; both ends of every option tested at boundary-1 / boundary / boundary+1 in Go and, from the same table, on the Python `Config`. The shifted phase needs no exception (both runtimes require 64 bytes of budget). |
| R5 (P2) explicit `kerberos` hint refused | confirmed | `d2ebcbd`: the factory is a map and the hint set is derived from it (minus the internal `git_text` route). `cases.py hint_cases()`: every registry candidate as an explicit hint with a fixture it identifies and with four foreign inputs (513 cases); all answered cases match; the hinted cases of unported candidates are listed gaps. |
| R6 (P2) the committed oracle depends on the Python patch release | confirmed | reproduced here on CPython 3.12.3 (three SOCKS5 IPv4-mapped cases; 3.9.25, 3.11.17 and 3.13.16 print the dotted form). `extended.wire_address` writes the mapped form out (`::ffff:192.0.2.1`, as Go's `netip` prints it) and `smarthome.MAX_JSON_INTEGER_DIGITS` (4300) is enforced by a `parse_int` hook instead of by the interpreter's `int()` limit. `test_migration_parity` passes on 3.9.25, 3.11.17, 3.12.3 and 3.13.16; `test_extended.WireAddressTextTests` and `test_v066` (with the interpreter limit switched off) pin both. Not verified on 3.9.6 itself, which is not installed here. |
| R7 (P2) stale whole-product manifest | confirmed | `a4d39c3` (before the review arrived): `presentation/SOURCE.json` regenerated after the six shim commits; regenerated again with the R6 engine change. |

The review's two host-dependent TLS fixture failures on the Mac's Python 3.9.6 (TLS 1.3 ClientHello generation by the host
TLS library) are not reproduced here and are not changed.

## Culvert integration preparation (branch `claude/culvert-integration-prep`, base `f239c65`)

Contract: `docs/integration/PROTODETECT-CULVERT-WORKING-PLAN.md` (work items #2, #3, #8–#13, #19). Go-only: no
detection change; `make parity-go` and the Python parity are unchanged.

| item | state | evidence |
|---|---|---|
| #2 scope | implemented | `AGENTS.md` states the Go port and in-process preparation for Culvert are in scope; no Culvert-side authority. |
| #3 Go minimum | implemented | `go 1.27.0` with `toolchain go1.27.4`; `make go-check` runs vet and `-race` tests at both (ADR 0002). |
| #8 public package | implemented | `go/detector`: `New(Config)`, `Engine.NewFlow(id)`, `Flow.Feed(dir, data)`, `EndDirection`, `Expire`, `Snapshot`, `Close` (idempotent, returns the admission slot once). One lazily created inspector per direction; released as soon as the direction is final. |
| #9 typed outcomes | implemented | closed `Outcome` (detecting, identified, unknown, malformed, incomplete, budget_exhausted, invalidated, unsupported, outside_profile, failed) and `Reason` (none, engine, not_ported, outside_profile, ended, expired, closed, panic); `Inspector.NotPorted` becomes `unsupported`/`not_ported`, never a silent `detecting`. |
| #10 panic boundary | implemented | every engine call runs under `recover`; the flow is quarantined (inspectors dropped, never re-entered, outcome `failed`/`panic`, panic value dropped); `PanicLimit` disables admission; tests inject panics in feed, end and expire. |
| #11 vocabularies | implemented | `All*`/`Valid`/`String` for directions, outcomes, reasons, end causes and evidence classes; exhaustive tests. |
| #12 hostname type | implemented | `Hostname` type; evidence classes categorical / asserted / hostname / withheld; unclassified fields are withheld; values bounded to 255 bytes, 32 items, 16 ALPN offers. |
| #13 profile | implemented | profile families `http`, `tls`, `ssh`, `smtp`; any other family the engine selects or resolves ends as `outside_profile` without its evidence. |
| #19 external consumer | implemented | `go/consumertest` (own module, `GOWORK=off`, built at the minimum) imports the package from an empty working directory through a host-owned interface and adapter. A test keeps `go/go.mod` free of `require`/`replace`. |
| Facade vs engine | implemented | `cases_test.go`: every unhinted stream case of `cases.json` through a Flow and a bare Inspector: 633 compared, 2876 outside the profile, 77 not ported, all consistent; every evidence field of identified profile cases is classified. |
| Fuzz | implemented | `FuzzFlowInvariants` (both directions, arbitrary splits, end and expiry): 923,720 executions in 60 s locally, no failure; 15 s in `make go-check`. |
| Known gap pinned | open (#4) | `TestPostQuantumServerHelloGap`: a crypto/tls ServerHello selecting X25519MLKEM768 is `unknown` ("Server key share group outside supported profile"); X25519 is identified. Inverted when #4 lands in both runtimes. |
| Not in this slice | — | #4–#7 detection fixes (Python and Go), #14 `buffer.Account` wiring, #16 embedded content, #17 `DeepEqual` removal, #18 benchmarks and per-parser fuzzing; hints, content attribution and host-opened shifts are not exposed. |

## M5 batches 18+ / M7+ — next

Remaining registry batches (8 families: HTTP2, SMB1, SMB2, RDP, ISO-TSAP, QUIC, DTLS, IKEv2, each with dedicated review) and the host-side shift correlation (LDAP StartTLS, HTTP CONNECT) with record-level parity per batch; passive
TLS decryption (M7); frontend and API integration (M8); adapter-level benchmarks (M9); CI wiring with the CI/CD lane (M10).

## Open decisions and blockers

- Mac checkout patch set (reset, labels): needs a push or a description to reconcile with `c2b7cc3`.
- Codex round-3 result on `726007d`: pending (issue #2).
- Independent labelled corpus (D09): blocked on input.
- Release thresholds (latency, throughput, memory): unspecified by design; relative results only.
- Dedicated migration PR: to be opened only when authorized in the working session (plan §1); the branch `claude/go-migration` exists and is pushed.
