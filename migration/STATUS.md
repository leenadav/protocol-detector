# Python → Go migration: status ledger

Plan: "Python → Go migration: implementation and acceptance plan" (Lee, 2026-11-07). States per item:
implemented · independently verified · blocked · deferred. Every entry names SHAs and commands. This file
never claims production readiness; release thresholds are pending (plan §5 M9/M10).

Lane rule (Hermes, PRO-6, 2026-11-20): a fresh chat reads `migration/LANE-BRIEF.md` first, and every task ends by
updating that brief (state, open items, frozen SHAs, new pitfalls) in the same push.

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
| Toolchain | implemented | `go/go.mod` pins `go 1.27.4` (moved from 1.27.3 on 2026-11-10; supported releases then: 1.27.4, 1.26.11; the container's 1.24.7 is out of support and unused). Pure Go; standard library plus `golang.org/x/crypto` (ChaCha20-Poly1305 only, M7) and its indirect `golang.org/x/sys`; ADR 0002. |
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

### Batch 19 — SMB1 and SMB2/3

| item | state | evidence |
|---|---|---|
| Parsers | implemented | `NewSMB1` (`windows.SMB1Parser`) and `NewSMB2` (`network.SMB2Parser`) in `go/internal/protocols/framed/smb.go`: NEGOTIATE requests and responses in either direction (SMB1 dialect strings bounded by `min(max_headers, 32)` and the 17/13/1-word response layouts; SMB2 dialect offers, fixed fields, 3.1.1 negotiate contexts with preauthentication, cipher and signing posture, the per-dialect encryption row), then a watch of exactly one more frame: a SESSION_SETUP whose security buffer goes through `classifyToken` (SMB1 also reports legacy LM/NTLM response lengths and the response action; SMB2 the session flags and the signed-only-on-final-success rule). Only closed labels are emitted. Field reads use `le`, which reads short slices as Python's `int.from_bytes` does. |
| Fixtures | implemented | `cases.py smb_vectors()`: 101 vectors (negotiate variants and every rejection branch of both parsers, session setups with each token layout and each rejection) as streams (whole, without FIN, 1-byte, 7-byte, truncated), plus a dialect budget and a byte budget (512 cases, 5897 total). |
| Go tests | implemented | `smb_test.go`: short-slice reads, refinement with closed labels only, the watch ending on a foreign frame without consuming it, a bad token, the SESSION_SETUP byte budget; both parsers join `FuzzFramedNeverPanics`. |
| Differential result | implemented | `make parity-go` with smb1 and smb2 claimed: **5785 compared, 5785 matched, 112 listed gaps**; the 68 SMB cases previously listed as gaps are answered (the gap list rejected them as stale until regenerated). Matched on the first run. One-off check outside the committed set: 40,000 seeded mutations biased to header and fixed-field offsets of both frames (two seeds), all matched. |
| Not claimed | — | SMB2 compounded requests, signed session binding and SMB 3.1.1 request priority remain outside the Python profile and the port. |

### Batch 20 — TPKT: RDP and ISO-TSAP

| item | state | evidence |
|---|---|---|
| Parsers | implemented | `go/internal/protocols/framed/tpkt.go`: the automatic `tpkt` route (`ics.TPKTParser`, an internal candidate like `git_text`, never a hint) frames with the TPKT bound 11..1024 and resolves the family from the bytes after the X.224 header; `NewRDP` (`remote.RDPParser`, explicit hint, bound 11..260: cookie framing, RDP_NEG_REQ offers and credential modes, correlation block, RDP_NEG_RSP selection and server flags, RDP_NEG_FAILURE codes, `rdp-negotiation` shift to TLS unless standard RDP security) and `NewCOTP` (`ics.COTPParser`: X.224 request and confirm, unique parameters, TPDU size and TSAP lengths, `cotp-connect` shift to S7comm). Cookies and correlation ids are not emitted. |
| Fixtures | implemented | `cases.py tpkt_vectors()`: 56 vectors (every rejection path of the three parsers, the route's choice, shifts into TLS and S7comm) automatically (whole / 1-byte / 7-byte / truncated) and under both hints (329 cases, 6226 total). |
| Go tests | implemented | `tpkt_test.go`: route resolution, evidence rows, the TLS shift only for non-standard security, the hint's own length bound; the three parsers join `FuzzFramedNeverPanics`. |
| Differential result | implemented | `make parity-go` with rdp and iso-tsap claimed: **6156 compared, 6156 matched, 70 listed gaps**; the 42 TPKT cases previously listed (rdp, iso-tsap and a CQL vector the dispatcher routes to tpkt) are answered. Matched on the first run. One-off check outside the committed set: 30,000 seeded mutations with random hints, all matched. |

### Batch 21 — IKEv2, and the UDP hint table

| item | state | evidence |
|---|---|---|
| Validator | implemented | `go/internal/protocols/framed/ikev2.go` ports `ikev2.ikev2` and `_sa`: header at offset 0 or after the non-ESP marker, declared length, a `min(max_headers, 128)` work budget over payloads, proposals and transforms, AES-CBC/GCM key-length attributes, HMAC-SHA PRF and integrity, MODP 14..18 with exact KE widths, the PRF-dependent nonce minimum, a responder's single proposal with one transform per type, NAT-detection, cookie and responder capability notifications, CERTREQ and Vendor ID bounded by `max_line`. Only the exchange and the DH group number are emitted. |
| UDP hint table | fixed | Found while porting: Go's datagram hint set was a hand-kept subset of Python's `VALIDATORS` and refused 15 valid hints (bacnet, ethernet-ip, ikev2, kerberos, l2tp, lifx-lan, mdns, netbios-ns, netflow, onc-rpc, openvpn, rip, sflow, tplink-smarthome, tuya-lan) with NotPorted even where the validator was ported, the datagram counterpart of review R5. `engine.DatagramHints` now is the Python table, the `mdns` and `netbios-ns` hints run the DNS-layout validator as in Python, and `test_migration_parity.test_go_udp_hints_equal_the_python_validators` compares the two tables. |
| Fixtures | implemented | `cases.py ikev2_vectors()`: 66 vectors (each acceptance and rejection path) automatically, hinted and truncated, plus work, field and byte budgets (201 cases); `datagram_hint_cases()`: every `VALIDATORS` entry as a hint on a datagram it identifies, truncated and on three foreign payloads (160 cases); 6584 total. |
| Go tests | implemented | `ikev2_test.go`: offer evidence, marker, width, group/offer agreement, work and byte budgets, trailing bytes. |
| Differential result | implemented | `make parity-go` with ikev2 claimed: **6510 compared, 6510 matched, 74 listed gaps** (DTLS, QUIC, HTTP/2, STUN over TCP and two options). Matched on the first run. One-off check outside the committed set: 30,000 seeded IKEv2 mutations with random hints and budgets, all matched. |

### Codex PR #25 findings (R1–R3 of issue #2 comment 6889957362), compared with this branch

Codex fixed these in the Python reference on its own branch (`codex/fix-quic-retirement-http304`, `e8830db`, draft PR #25).
This branch does not duplicate that Python change; it arrives here when PR #25 reaches `main` and `main` is merged.

| finding | Go on this branch | action |
|---|---|---|
| R1: an invalidated UDP flow kept the peer's retained identification | same gap in `session.Tracker.ProcessUDP` (unreachable through replay today: only QUIC invalidates a UDP flow, and QUIC is not ported) | fixed: the invalidation clears every retained direction observation; `TestUDPInvalidationWithdrawsRetainedPeerEvidence` covers both directions and a later peer identification, and fails without the fix |
| R2: flow retirement reset only one ordered QUIC scope | no Go QUIC assembler yet | requirement for the QUIC batch: retirement (end, idle expiry, Finish, with or without a session callback) resets both ordered scopes |
| R3: an HTTP 304 (and 1xx, 204) with Content-Length or Transfer-Encoding took the next response as its body | Go HTTP continuation is not ported (`option continuation (HTTP)` is a listed gap) | requirement for the continuation port: no-body statuses end at the header boundary before CL/TE are read |

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

## Remaining families and options, M7 (2026-11-15)

The sections above are a ledger: a "Not claimed" or "NotPorted" row records the state at its commit and is
superseded by the rows below. Every command was run on the head named in the row; parity numbers are
`make go-check` (`compare.py --families`, every registry family, 0 unlisted gaps, `gaps.json` empty).

| item | state | evidence |
|---|---|---|
| QUIC | implemented | `d2a8469`: Initial protection (v1/v2), CRYPTO assembler per capture scope and direction (C5/C6), D02 retraction, R2 two-scope reset. All committed QUIC cases match; ~16,500 generated datagrams (10,558 with JA4) compared with the reference, 0 mismatches. |
| HTTP/2, http2-server, HPACK | implemented | `4b21369`: 7,000 generated scenarios, 0 mismatches. |
| DTLS | implemented | `8c5a9c1`: 12,000 generated datagrams, 0 mismatches. |
| STUN over TCP | implemented | `fd92ed0`: 4,000 generated streams, 0 mismatches. |
| Fingerprints (JA3/JA4, JA3S/JA4S, HASSH, h2, QUIC/DTLS JA4) | implemented | `0b13a2b`: every committed case re-run with the option, 0 mismatches; `gaps.json` emptied. |
| Certificates (TLS 1.2 leaf watch, RFC 5280 structural profile, validity risks) | implemented | `9e7432d`: 12,584 generated leaves, 2,500 flights and sessions with records, 0 mismatches. |
| Heuristics | implemented | `17aa6f1`: 6,000 generated inputs, 0 mismatches; fixed a Unicode case-mapping bug (`ſtarttls` opened a STARTTLS boundary). |
| Custom signatures (`retain_contexts`) | implemented | `957ff39`: parser contexts, unknown-payload signatures, App-ID metadata, `signature_set` digest, `replay --signatures`. Random 60-signature sets over all 6,584 cases (4 seeds) and over HTTP/2, DTLS, STUN, heuristics and QUIC corpora, 0 mismatches; 20,000 signature documents and 20,000 patterns (accept/reject, digest, every invalid-pattern message). RE2 cannot express possessive or atomic groups, inline flags or a non-final `$`: such a pattern is refused as not ported, never guessed (3.2% of the random pattern corpus, which then also counted repeats above 1000; those are answered by Go since 2026-11-18, see "Open after M7"). |
| Key-log TLS decryption (M7) | implemented (engine) | `4111a70`: `go/internal/decrypt` (KeyProvider, TLS 1.3 and TLS 1.2 ECDHE AES-GCM record engines, TlsConnection states and reason codes) and `Inspector.FeedDecrypted`. 12,300 scripted connection traces, 2,200 key-provider traces and 3,000 `feed_decrypted` traces, 0 divergences; fixed shifted-phase provenance inside decrypted plaintext. `golang.org/x/crypto` added for ChaCha20-Poly1305 only (ADR 0002). The presentation glue (`decryptor.py`, `capture.py`, `live.py`) belongs to M8. |
| Engine benchmark (M9, engine level) | measured | `bench_compare.py --iterations 200 --rounds 3` on `4111a70`: Go p50 faster by 8.0x (http_small), 36.4x (http_fragmented), 13.5x (tls_whole), 18.1x (tls_fragmented), 9.5x (http_after_identification); local CPU only, not SWG latency. Adapter-level benchmarks are not built yet. |

## Content release 2026.11.1 (2026-11-15)

| item | state | evidence |
|---|---|---|
| Server-name catalog | implemented | 115 more services on operator-owned domains (169 entries, 271 catalog applications): streaming, gaming, social, messaging, storage, business, developer, identity, generative AI, remote access, VPN, encrypted-DNS resolvers, platform bases, search and commerce. Remote-access and VPN apex/www names are web fronts (D03). `content.select("2026.11.0")` reproduces the previous host-catalog digest. Self-reviewed against the rule only; independent review pending. |
| Release 2026.11.2 | implemented | 262 more services (431 entries, 533 catalog applications): media, social, messaging, mail, storage and backup, business, management and endpoint security, developer, identity, generative AI, remote access and RMM, VPN and circumvention, cloud proxies, resolvers, commerce, news, education, advertising and measurement. `content.select("2026.11.1")` reproduces that release's host-catalog digest. 734 host-catalog session cases, 7,318 cases in total; Python and Go match on all. Self-reviewed against the rule only. |
| Parity cases | implemented | `cases.py host_catalog_session_cases()`: every entry as a TLS SNI under its first and last domain, every web front, HTTP Host for every tenth entry and seven names that must not map (329 session cases; 6,913 in total). Python and Go match on all of them (`make check`, `make go-check`); Go needed no change, it loads the shared pack. |

## M8 — offline analysis on the Go engine, default backend (2026-11-15)

Lee's decisions of 2026-11-15: this session also does M8 and M10, the default backend switches to Go once the
gates pass, host-named applications are added, the Python port-table cache is fixed.

| item | state | evidence |
|---|---|---|
| Go `analyze` command | implemented | `1eea0cd`: `go/internal/capture` (classic PCAP and pcapng), `go/internal/policy`, `go/internal/analyze`, `cmd/protodetect analyze` with the options of `analyze_pcap.py`. 4,000 capture files through the reader, 20,000 policy documents and 15,618 evaluations, 0 differences. |
| Byte-identical rows | implemented | `go/internal/pyjson` writes rows as `json.dumps` does (separators, ASCII escapes, float repr, dict key order incl. evidence-ordered maps, the reference's integer zero clock). 5,400 generated captures (about 76,000 rows) byte-identical in JSON and text form, with exit status and error text. |
| Default backend | switched for `analyze` | `protocol_adapters/analyze_pcap.main`: Go when its binary is installed, Python on `--backend python` / `PROTODETECT_BACKEND=python`, without a binary, and for what Go declines with exit 64 (`--content-version` rollback, signature patterns outside RE2). `--backend go` never falls back. `test_backend.py` (8 tests); the whole Python suite passes with either backend answering. |
| Gate | implemented | `make parity-analyze` (`migration/parity/analyze_diff.py`, 300 captures, byte comparison) inside `make go-check`; fuzz targets for capture, signatures and decrypt. |
| Fixes found | fixed | session tables were walked in Go map order when several states ended together (insertion order now, regression test); an identified git or TPKT route kept its internal candidate name. |
| Presentation capture analysis | switched | `protodetect present` (`go/internal/analyze/present.go`): a capture on standard input, the result of `presentation/server.py` `analyze_bytes` on standard output (bounded-prefix tracking, 256 connections and flows, fingerprints, heuristics, certificates, the frame/session/event limits, refusals as the reference's exception class and text). `analyze_bytes` selects the backend exactly as `analyze` does; `analyze_bytes_reference` is the Python path. `make parity-analyze` now also compares this result on every capture, and every third capture is built for bounded-prefix tracking (`stress_records`: streams past the 64 KiB window, segments before the origin, FIN beyond the window, expiry timing, table eviction). 2,700 captures over 5 seeds (900 of them stress captures), 0 differences; a planted `Compact: false` is caught (15 of 150). Before this, bounded-prefix tracking in Go had no differential at all. `presentation/tests/test_backend_selection.py` (8 tests). |
| Key-log decryption analysis | switched | `protodetect decrypt-capture` (`go/internal/keylogcap`): a capture and its key log on standard input (never in arguments, the environment or a file), the report of `poc_decryption.capture.analyze_capture` on standard output. Ported for it: the coordinator's retained reassembly tier with its budget (`coordinator.go`), session identity (`go/internal/sessionid`, BLAKE2s-64 checked against `hashlib`) and generations, the Decryptor's rows and bounded work (`decryptor.go`), the layered view with an inner layer and decryption state (`appid.LayeredViewWith`), a decrypted-source inspector, retained-tier streams. `analyze_capture` selects the backend as `analyze` does (`analyze_capture_reference` is the Python path); with the Go binary the decryption analysis no longer needs the `cryptography` extra. `make parity-decrypt` (`migration/parity/decrypt_diff.py`, in `make go-check`): TLS 1.3 (three suites) and TLS 1.2 streams generated in memory, OpenSSL exchanges, segment, record and key-log faults; reports equal as JSON text, refusals in class, message and code. 2,800 captures over 6 seeds, 0 differences (about 1,500 decrypted rows, every failure class); five planted regressions (evidence filter, inner-layer authentication, FIN check, generation renewal, aggregate budget) each caught. Go tests assert that no hostname, path, credential or secret appears in a report; `FuzzAnalyzeNeverPanics` runs in the gate. `presentation/tests/test_backend_selection.py` (14 tests). |
| Live capture | switched | `protodetect live` in Go (`go/internal/live`, `go/internal/telemetry`): the capture monitor (classification events, retired directions, session records stamped with capture id, session id and generation and published at most once, capture gaps that name the retracted sessions, progress and final summaries with counters, telemetry and host input quality), the run loop (tcpdump as a child process, its statistics and exit status, interrupt, duration and packet limits, bounded drain at stop, a closed output pipe) and both output forms. `protocol_adapters/live_capture.py` validates the options, lets the binary check them (`live --check`) and then replaces itself with it (`os.execv`), so the dashboard's live view, which starts that module and stops it with SIGINT, follows without a relay; the reference runs on `--backend python`, without a binary, and for what the binary declines or rejects. `make parity-live` (`migration/parity/live_diff.py`, in `make go-check`) replays generated capture streams through both with the clock taken from the stream (`--replay-clock`; the reference's `run_capture` runs unchanged on the same clock), so every event is a function of the bytes: 1,200 replays over 3 seeds, about 14,800 event lines in JSON and text form, exit status included, 0 differences; work-stage durations are compared by count only. Five planted regressions (generation renewal, a counter, idle expiry at ticks, exactly-once sessions, the progress interval) were each caught. Go tests drive the real process path with a stand-in `tcpdump` (statistics, loss, failure, option refusals) and assert that no hostname or path appears. With a real tcpdump on loopback and synthetic traffic only (the opt-in `presentation/live_smoke_check.py`), both backends classified the exchange, stopped on SIGINT and reported the same counters; a nonexistent interface produced the same events and status. `test_backend.py` (13 tests). |
| Fixed on the way | fixed | `protodetect live --stdin ...` and `protodetect live --interface ...` (the documented form) were rejected by the command parser on every supported Python: an option cannot start an `argparse.REMAINDER`. `analyze` and `live` are now delegated before the parser sees them; regression test in `test_backend.py`. |
| Live key-log decryption | switched | `protodetect live-decrypt` (`go/internal/livedecrypt`): the worker of `presentation/poc_decryption/live.py`. The live monitor carries the retained reassembly tier (`keylogcap.Tier`, shared with the offline decryption analysis: idle close at ticks, gap, end, tuple reuse), the key log is read append-only from a regular file owned by the user without following a link (rotation, truncation, an over-long or non-ASCII line and the size budget are errors), the decoder keeps the sample budgets (2 MiB, 20,000 frames, 64 connections, 64 records per connection per slice), the decryptor feeds the reference's telemetry, a CPU limit is set, and a failure is published as one of five fixed codes and sentences: never key-file contents, a path or parser input. The key-log path arrives on standard input. `live.py` replaces itself with the binary when one is installed (`PROTODETECT_BACKEND=python` keeps the reference). `make parity-live-decrypt` (`migration/parity/live_decrypt_diff.py`, in `make go-check`) drives the reference's real objects and the binary (`--replay`) with the same script of pipe reads, key-log appends, ticks and the end, each with its clock value: 1,500 scripts over 3 seeds, about 21,400 event lines, exit status included, 0 differences (decrypted, decrypting, awaiting-keys and awaiting-hello rows, every failure code, capture gaps). Five planted regressions were each caught; one of them (the per-slice work budget) only after the generator gained record runs longer than a slice. Fuzzing found that a replay operation's declared length was allocated unchecked (a 4 GiB length exhausted memory); it is bounded now and the input is a regression case. The hosted fuzz run on `9046738` then failed (ci run 402): a replay clock value of NaN was published as `"elapsed_seconds": NaN`, which is not JSON. Only the replay mode takes its clock from input (captures give finite times), so replay now ends on a clock value that is not a finite, non-negative time, and reads an operation's bytes without allocating its declared length first; unit test and fuzz seed added, 60 s of further fuzzing clean. With a real tcpdump on loopback and a synthetic TLS exchange (`presentation/live_decrypt_smoke_check.py`, opt-in), both backends decrypted it from a key log written while they ran and reported the same counters. |
| Adapter benchmark and a hot-path fix | measured, fixed | First adapter-level measurement (`analyze --json --sessions --events-only` on a generated capture of 4,000 conversations, 27,757 frames, 2.5 MB; best of five; local CPU work on this container, not production latency): the Go binary took as long as the reference (0.80 s against 0.81 s). A profile showed 62% of the time in an ordering helper added on 2026-11-15 for deterministic record order: it sorted the whole connection table for every packet. `Tracker.Expire` now orders only the states that actually expired (same states, same order; `make go-check` and 1,400 extra differential runs unchanged). After the fix: Go binary 0.20 s, Go through `protodetect.py` 0.31 s, Python 0.68 s, with byte-identical output (3.3 MB). The remaining time is spread over JSON writing and tracking; nothing else was tuned. |
| Content digest contract (Culvert #16) | defined, implemented in Go | `migration/CONTENT-DIGEST.md`: canonical encoding CJ1, the release digest (the reference's value, stated over the pack alone) and a pack digest (`SHA-256("protodetect-content-pack-v1\n" + CJ1(pack))`). `content.Parse` recomputes the `host_catalog`, `application_catalog` and `risks` components and the release digest and refuses a pack that states anything else; `Pack.Digests` exposes both digests. Release 2026.11.2: release digest `e0d6e39533a6ae9c` (unchanged), pack digest `0984af6e…f5aa`; vectors computed with Python's standard library and asserted in `digest_test.go`. Open: the `families` component is carried as stated, because a schema-1 pack holds no family inventory. No Python file, generator or fixture changed. |
| C16 evidence in Go (malformed input) | added, not a status change | Two fuzz targets for paths that had none: `FuzzPresentNeverPanics` (`go/internal/analyze`: capture bytes through the decoder, the tracker, every inspector with fingerprints, heuristics and certificates on, and the record builder; a result must be valid JSON) and `FuzzPolicyNeverPanics` (`go/internal/policy`: any document; a policy that parses must decide). Local runs on 2026-11-16: 240 s / 7.5 million executions and 120 s / 1.5 million executions, no finding. Their seeds run with `go test`; they are not in the Makefile's `go-check` fuzz list, and `FuzzCanonicalIsAFixedPoint` is not either. Contract C16 stays `pending`: its adapter- and HTTP-level part is not exercised by this. |
| Go acceptance evidence C13, C15-C17 | experimental, evidence recorded | C13: `make schema-go` validates every analyze row, session record and live event the Go binary writes against `schemas/*.json` with `tools/schema_check.py` (4 seeds of 250 captures: about 40,000 offline rows, 5,500 session records, 14,000 live events, 0 problems) and checks `engine_status` against `policy.ENGINE_STATUSES`. C16: all 25 Go fuzz targets run in `make go-check` (10 s each), five written on 2026-11-16 (signature documents, pack bytes, the canonical encoder, the capture-to-result path, policies) and six older ones that had run only their seeds (DTLS, HPACK, HTTP/2, HTTP continuation, X.509, QUIC); refusals already compared with the reference by the differentials. C17: `canary_test.go`. C15 (Go part): `interrupt_test.go`. Reference-side findings, not changed (Python is read-only): `engine_status` `midstream` is emitted but missing from `ENGINE_STATUSES` (a policy cannot name it); the live adapter's invalidation without events lacks `app`, so the reference's own live output fails `live-event`; analyze frame rows print the asserted server name without `--hostnames` (documented for offline rows, SR-9 covers live output and session records only). C14 and the presentation part of C15 are Python components with no Go implementation. |
| Not switched | open | Nothing on the capture, decryption or presentation paths: every runtime path has a Go implementation that is the default when its binary is installed. The live clock of the Go binary is monotonic seconds since its start plus one, not the host's monotonic clock value; only differences of those times mean anything in either backend. The installed wheel ships no Go binary, so an installed product runs the reference unless `PROTODETECT_GO_BINARY` or `protodetect-go` is provided. `--content-version` rollback and signature patterns outside RE2 are answered by the reference. |
| Reused tuples (Milestone B) | fixed in both engines (`caf964f`, then one counter per capture) | Lee's rule of 2026-11-17: adapter-level Python changes may go ahead. The coordinator (`protocol_adapters/coordinator.py`, the Go live monitor and offline decryption coordinator) dropped a second UDP flow on a 5-tuple after the first expired, a TCP connection on a tuple whose earlier connection had ended, and any flow after a gap retracted the tuple, as duplicates of an already published (session id, generation). Such flows are now published (`caf964f`). The record of what was published then still grew with the distinct tuples of a run; Lee chose (2026-11-18) one generation counter per capture: a flow draws the next value the first time it needs one (the retained tier opens it, or its session is published) and releases it when published or retracted, so (session id, generation) is unique per capture and only tuples with a flow in flight hold a value. A tuple's first session is not necessarily generation 0 (contract C18, `schemas/live-event.schema.json`, `events.py`, PROTOCOLS.md). Go: `keylogcap.Generations`, shared by the live monitor, the offline coordinator and the retained tier; the live monitor now publishes a packet's sessions before the retained tier sees the packet, as the reference's sink does (an RST would otherwise release the generation first). Evidence: `test_session_reuse.py` and `go/internal/live/reuse_test.go` (3,000 distinct tuples: 3,000 distinct generations, at most 8 held; they fail on the previous code), `parity-live`, `parity-live-decrypt`, `parity-decrypt` on seeds 1-3, 0 differences. The detection engine is unchanged. |

## M10 — CI for the Go engine (2026-11-15)

| item | state | evidence |
|---|---|---|
| Engine gate | implemented | the `go-engine` job runs `make go-check`, which now also runs the capture, signature, decryption and key-log adapter fuzz targets, `make parity-analyze` and `make parity-decrypt` (Go binary against the Python reference). The job installs the hash-pinned decryption extra for the reference side of `parity-decrypt`; its first hosted run is the one on the commit that adds it. |
| Vulnerability scan | implemented in CI; first hosted run passed (`34ea6b0`, ci run 397) | `toolchain-audit` runs the pinned govulncheck in source mode over `go/` (`go.mod`/`go.sum` as committed). The workflow lock was regenerated in the same change (rule 14). It could not be run in this session (blocked by the session's permission policy), so the first result is the hosted run on this commit. |

## Performance budgets aligned with Culvert (2026-11-16)

Lee, 2026-11-16: the detector will merge into Culvert, so its release thresholds follow Culvert's rather than
a target of this repository's own. Sources: Culvert's benchgate convention (`//go:build benchgate` tests run as
`go test -tags benchgate -run 'TestBenchGate_' -count=1 -p 1`, gating only deterministic quantities, timing
judged by interleaved `benchstat` and never hard-gated on shared runners) and the per-flow engine budgets of the
integration plan §9 (`docs/integration/PROTODETECT-CULVERT-WORKING-PLAN.md` on `claude/culvert-integration-prep`):
at most 64 allocations per flow, at most 4 KiB retained after the observation, CPU p99 at most 50 µs (stated
there as a hypothesis to measure), 16 KiB observed and 16 feed calls per direction.

| item | state | evidence |
|---|---|---|
| Gate | implemented | `make bench-gate` (`go/internal/bench/benchgate_test.go`, in `make go-check`): on the shared workloads (`migration/benchmarks/workloads.json`) plus an SSH banner + KEXINIT flow and an unidentified 16 × 1 KiB flow, each through `engine.New`, its feeds and `End`. Correctness is asserted first. Gated: allocations per flow (`testing.Benchmark`) against the 64 budget and, per workload, a regression ceiling of the count measured on go1.27.4 plus 4 (the headroom Culvert's own allocation gates leave); retained heap per finished flow over 2,000 kept inspectors against 4 KiB. Reported only: p50/p99 per flow over 20,000 samples. |
| Allocations per flow | within budget | http_small 26, http_fragmented 38, tls_whole 33, tls_fragmented 37, http_after_identification 26, ssh_banner_kexinit 34, unknown_16x1KiB 10. The gate found the SSH flow at 90: the KEXINIT posture built a set per name-list. It now scans the validated lists (`c63ca05`), proven equal to the previous code by an oracle test (20,000 generated cases) and a fuzz target in `go-check`; parity unchanged. |
| Retained per finished flow | within budget | 631–1,406 bytes. |
| p99 definition | decided (Lee, 2026-11-17) | The 50 µs p99 is measured per flow with garbage-collection pauses included, since that is what Culvert would experience; it stays reported, not a hard gate on shared runners, as in Culvert's benchgate. By that definition tls_fragmented, ssh_banner_kexinit and http_fragmented are over it (below). |
| CPU p99 per flow (report only) | measured, three workloads over the hypothesis | One 4 vCPU container, garbage collector on, local CPU work only, not SWG latency: http_small 35.5 µs, tls_whole 49.2 µs, http_after_identification 33.9 µs, unknown 7.7 µs within 50 µs; tls_fragmented 55.6 µs, ssh_banner_kexinit 75.1 µs, http_fragmented 219 µs over it. With `GOGC=off` the first two fall to 35.6 µs and 38.0 µs, so their tail is collection pauses landing in a sample, not the parse; p50 is 3.8 µs and 6.6 µs. http_fragmented feeds 6,050 bytes in 190 calls, far past the plan's 16 feed calls per direction, so it is outside the facade's envelope; it is kept as a stress workload. Not gated, by Culvert's convention. |

## M8 — the live control plane and the dashboard service in Go (2026-11-17)

Contracts C14 and C15. Lee assigned M8 (frontend, API) to this session on 2026-11-15; the page itself (`web/`,
`store.js`) is JavaScript and is served unchanged.

| item | state | evidence |
|---|---|---|
| JSON as the reference writes and reads it | implemented | `go/internal/ojson`: objects in insertion order, integers with exact digits, `json.loads` (CPython's `_json` scanner on decoded characters: its error text with line, column and position; `detect_encoding`, UTF-8 with `surrogatepass`, the BOM, the 4300-digit limit) and `json.dumps(allow_nan=False)`. 4,800 mutated documents in `parity-control`, 0 differences; a fuzz target in `go-check`. UTF-16 and UTF-32 bodies are not decoded (refused with this port's own text). |
| Event log, reducer, run state | implemented (`3488126`) | `go/internal/events` (envelope, bounded log read by cursor, retractions, the reducer and the effective layered view) and `livectl.State` (ingest, snapshot, state view, cursor reads, run-scoped reset). `make parity-control` (`migration/parity/control_diff.py`): the Go `live` and `live-decrypt` workers' lines on generated inputs plus duplicates, capture gaps naming real sessions, malformed lines, reads across the 4096-event retention edge and resets naming the current, a stale or no run: 120 runs, about 105,000 lines, 11,000 reads, 0 differences; seeds 2 and 3 likewise. Four planted regressions caught. |
| Job runner | implemented (`1d12314`) | `go/internal/jobs`: admission (2 running, 4 queued), lifetime, retention, cancel, shutdown, the reference's reasons. Workers run in their own process group, killed together on cancel or expiry, and `Wait` is bounded: a worker's child holding the output pipe cannot keep a job alive (the reference kills the worker alone and would wait). |
| Live manager | implemented (`86ef86b`) | `livectl.Manager`: `start()` with the reference's refusals in order, the worker (`protodetect live`, or `live-decrypt` with the key-log path on standard input) in its own session, the reader, the 30 s lease and the run's lifetime, stop, heartbeat and reset scoped to the run they name; cursor reads accept every integer `int()` admits. |
| Dashboard service | implemented (`2445d72`), not the launcher's default | `protodetect serve` (`go/internal/serve`): the loopback service of `presentation/server.py` with its eight handler slots and raw 503, Host and Origin checks, the token, upload limits, the live, job, analysis and decryption endpoints and the page. Requests are parsed as `BaseHTTPRequestHandler` of Python 3.13 parses them (HTTP/1.0 answers, one request per connection, the same limits and error pages, `int()` and `urlsplit()` semantics). Analysis and decryption workers are Go (`serve-worker`). `make parity-server` (`migration/parity/server_diff.py`): both services with the Go engine installed and a stand-in `tcpdump` playing a generated capture (nothing is captured), the same raw requests: 424 exchanges per run at `--count 12` (seeds 1 and 2), 400 at `--count 6` (seeds 1-3), 0 differences; planted regressions (queue size, pool size, unscoped stop, Origin check) caught. Normalized by construction: ids, monotonic times, the lease countdown, live wall-clock readings (session start and end, decision latency, telemetry), analysis time, and the health report's `python` field (`null` in the Go service). |
| Not ported | open | The demo capture (`/api/sample`, the `demo` job), the decryption showcase (`decrypt-demo`) and the catalog export (`/api/catalog`) are built by Python fixture builders and descriptor tables; `protodetect serve` runs the reference's own code for them as worker processes (`--python`), and answers 503 without an interpreter. The demo answers are random in the reference itself and are compared by shape. |
| Launcher default | switched (`24e410e`), Lee's decision of 2026-11-17 | `presentation/launch.py`, which the desktop launcher runs, starts `protodetect serve` when the Go binary is installed (the adapters' `go_binary()` lookup) and `server.py` otherwise; `--backend python` or `PROTODETECT_BACKEND=python` keeps the Python server, `--backend go` never falls back (`presentation/tests/test_launch_backend.py`, `README-HE.md`). SIGTERM, which the launcher sends on Ctrl+C, now stops a live run and the job runner before the Go service exits (`ed6b2b8`). |
| Reference findings, not changed | open | (1) A worker line whose endpoint is not an `[address, port]` pair raises `IndexError` in `LiveManager.ingest` (only `ValueError` is caught): the reader thread ends, closes the pipe and marks the run `stopped` without an error, while the worker runs on until its next write fails or the lease stops it; Go keeps the line out of the log and reads on. (2) The reference's texts are interpreter-specific: Python 3.9 writes another error page and other base64 messages; the Go service follows 3.13 (the CI interpreter). (3) A worker that leaves a child holding its output pipe keeps the reference's job (and the live reader) waiting; the Go runner kills the job's process group. |

Frozen milestone SHAs for Codex (available from Sunday): `61fd45a` (Milestone A), `fdb90e2` (Culvert-aligned
performance gates), `68fb867` (the Go live control plane and dashboard service), `58a4701` (the launcher switch
and Milestone B), `9e51389` (one generation counter per capture, family verification, container signature
descriptions, content-version rollback), `6b280a6` (the adversarial suite and the load benchmark), `024163f`
(the case generator's coverage cases for nine families: 88 of 88 parity-verified), `12e1ed0` (the CoAP
profile held to RFC 7252 in both engines, F-ADV-1), `d1b63ee` (C11: earlier content releases reproduce the
digests they were published with, both engines), `baa07b9` (content release 2026.11.3, research batch A), `aaa5a7e` (merge-readiness checklist and draft PR
description, documentation only), `93cbf2a` (Go answers signature repeat counts 1001..4096; `36e2c5e` before it
rebuilds the Go binary ahead of the presentation suite), `76e467a` and `d65d21a` (x/crypto vendored, every Go
command with `-mod=vendor`, `make go-vendor-check`), `07b216e` (parity-server canonicalizes a job id that begins
with "L-"), `6ab434d` (content 2026.11.4, research batch B), `7dcabb7` (content 2026.11.5, batch B2: the
DeepSeek, Perplexity, Mistral and xAI API hosts apart from the chat apps), `b6ed149` (content 2026.11.6,
research batch C: notebook.google.com re-sourced, Dropbox www web fronts, ngrok, Cloudflare One Client, Atlassian,
WeTransfer), `c08773f` (the prepared post-merge tests), `ee1645d` (content 2026.11.7, batch D: Defender for
Endpoint, Intune, iCloud Private Relay and vendor hosts), `253a91d` (2026.11.8, batch E: Chrome Remote Desktop,
Bitwarden), `2f6ad4d` (2026.11.9, the vendor-level `goto` id), `50ce5c0` (Hermes's 2026-11-19 decisions in
POST-MERGE-BACKLOG.md, the prepared tests adjusted to them; **the frozen review head of the Codex review packet**), and the
commit that adds `migration/review-packet/` (documentation only: 42 chunks over `dbe20f3..50ce5c0`, see its INDEX.md); after the packet: `6194fb9` (PRO-31: Go orders content release versions numerically, `CompareVersions`; Python test-only checks, with three expectedFailure tests reproducing the reference's string comparison in `content.py`, which is not changed; outside the packet's range, review as its own diff `git diff e5ae2f6 6194fb9`); `4d8aa29` (PRO-31 numbering rule, Hermes PRO-34: YYYY.MM.N with N 0..9, enforced by `TestEmbeddedReleasesFollowTheNumberingRule`; review as `git diff 4c64c75 4d8aa29`); `376a204` (PRO-31: the Python reference compares versions numerically, Lee's exception of 2026-11-20; review as its own diff `git diff 2393659 376a204` together with `6194fb9`).

Frozen-Python exceptions (Lee-approved edits to the read-only Python reference on this branch; nothing else in it
changes):

| Exception | Approval | Commits |
|---|---|---|
| Launchers start the Go service when its binary is installed (`presentation/launch.py`) and stop a live run on SIGTERM | Lee, 2026-11-17 | `24e410e`, `ed6b2b8` |
| Case generator: coverage cases for nine families (`migration/parity/cases.py`) | Lee | `024163f` |
| CoAP profile held to RFC 7252 in both engines (F-ADV-1) | Lee, 2026-11-18 | `12e1ed0` |
| C11: earlier content releases keep their published components (`protocol_engine/content.py`) | research finding, fixed in both engines | `d1b63ee` |
| PRO-31: content release versions compared numerically (`protocol_engine/content.py` `compare_versions`, the semantics of Go's `CompareVersions`) | Lee, 2026-11-20, relayed by Hermes | `376a204`, with `6194fb9` |
| Per-carrier port tables: `Application.uses_port` no longer reads a cache keyed by name across carriers (`protocol_engine/applications.py`) | Lee, 2026-11-15 ("Reference finding, fixed in Python" below) | `9cec1e6` |
| Offline analyze defaults to the Go backend; the reference runs with `--backend python` (`protocol_adapters/analyze_pcap.py`) | Lee, 2026-11-15 (M8 decisions) | `b0664ef` |
| Live capture defaults to the Go backend; the reference runs with `--backend python` (`protocol_adapters/live_capture.py`) | Lee, 2026-11-15 (M8 decisions) | `9a7ebb9` |
| Reused tuples: a flow on a reused tuple is the next generation (`protocol_adapters/coordinator.py`) | Lee's rule of 2026-11-17: adapter-level Python changes may go ahead (Milestone B row) | `caf964f` |
| One generation counter per capture (`protocol_adapters/coordinator.py`, `protocol_adapters/events.py`) | Lee, 2026-11-18 | `0d78604` |
| PRO-260: TLS post-quantum hybrid key shares (0x11EB, 0x11EC, 0x11ED) are recognised in Go only; the Python reference is unchanged and the 18 differing parity cases are pinned in `migration/parity/deltas.json` (section "PRO-260" below) | Go-only by Lee's decision, 2026-11-23 (relayed by Hermes) | `b1379a4` |
| Content releases 2026.11.1 to 2026.11.9: new versions of the reference's data (`protocol_engine/host_apps.py`, the release tables in `content.py`, `content_lock.json`), each added as a new version (AGENTS.md rule 2) to both engines' pack | content-release process; each release is recorded in this ledger, and no separate Lee approval is recorded for them | `9cec1e6`, `3b0ddf9`, `baa07b9`, `6ab434d`, `7dcabb7`, `b6ed149`, `ee1645d`, `253a91d`, `2f6ad4d` |

C11 (2026-11-18, research finding): a rollback recomputed an earlier release's digest from the current
application catalog, so every added application moved it (2026.11.1 published as `c4020c2437f3de8d`, rolled
back as `45ad7b6b...`), and a record pinned to that release no longer matched. Fixed in `d1b63ee`: each earlier
release keeps its published components (`content._RELEASED_COMPONENTS`, from its lock), its rebuilt host
catalog must reproduce the recorded host component, `check_content.py --update` refuses a new release until
the superseded one is recorded; Go's `EmbeddedRelease` verifies the same way. All four earlier releases now
roll back to their published digests (`test_content`, `history_test.go`).

Batch A (`baa07b9`): the research lane's name-based patch (claude/app-research `9c040b2`) applied as content
only, each entry checked against its spec's source; `notebook.google.com` skipped (no source that it is
NotebookLM). Release 2026.11.3, 536 applications, 434 host entries; 7,404 cases, Python and Go match all.

## Family verification (2026-11-18)

Routine technical choice under Lee's standing rule: what `parity-verified` means for a family, stated as a check
the gate computes rather than a label set by hand.

| item | state | evidence |
|---|---|---|
| Rule | implemented | `migration/parity/verify_families.py`, run by `make parity-go` (so in `make go-check`) right after the exact comparison: a family is `parity-verified` when the passing report claims it and every committed case labelled with it matched exactly (no gap, no approved delta), its cases of each transport's kind cover a positive message, a truncated prefix, a mutation and foreign bytes, and a TCP family has a matched session-level case. `--check` fails when a status in `migration/CAPABILITIES.json` differs from the computed one in either direction; `--write` records each family's case counts, classes and shortfall there. `test_verify_families.py`; planted regressions (one unmatched case, a listed gap) each fail the check. Capture-level differentials stay separate gates. |
| Result | 88 of 88 `parity-verified` | On 2026-11-18 79 qualified; the other nine lacked committed cases (http2, mongodb, mysql, resp, s7comm, websocket: no session-level case; smtp and ssh: no session-level case and no mutated stream; ipfix: no foreign-bytes datagram). Lee allowed the case generator (only) to add them: `coverage_cases()` in `migration/parity/cases.py`, 37 cases appended after every other, none changed (the regenerated `cases.json` keeps every earlier case and its order byte for byte); Python and Go match all 7,355 cases, and `verify_families.py --write` promoted the nine. The Go replay now takes the `tcp_hint`/`udp_hint` session options the hinted families need. |

## Security review finding SEC-QUIC-1 (PRO-47 and PRO-110, 2026-11-22)

**Finding (Security Reviewer):** the QUIC CRYPTO assembler (`go/internal/protocols/quicx/assembler.go`) scanned every
held connection on every QUIC datagram (`expire`) and on every flow end (`Reset`). With 1,024 connections held, an
attacker spraying QUIC datagrams paid about 24 µs of CPU per datagram; with an empty store it is about 15 ns.

**Fix (Go only).** The Python reference's `QuicAssembler` semantics are unchanged:
- an idle heap ordered by last-seen time, so expiry removes exactly the entries with `now - last > idle`, oldest
  first, even when capture time runs backwards;
- a per-scope index, so `Reset(scope)` touches only that flow's entries;
- the LRU list is unchanged, so eviction stays least-recently-used.

**Evidence:**

| Check | Result |
|---|---|
| `TestAssemblerMatchesTheScanningOracle` | The old scanning implementation, kept verbatim as the oracle, answers 40 seeded sequences of 600 random operations (adds with conflicting and over-budget fragments, conflict checks, resets, clears; time forwards, still, jumping and backwards, or absent) exactly as the new one does: statuses, bytes, counts, size and LRU order after every step. |
| Mutation check | `>=` in place of `>` in expiry fails at seed 1, step 517. A dropped LRU move fails at step 34. |
| `TestResetAndExpiryTouchOnlyTheirEntries` | Passes. |
| `BenchmarkAssemblerDatagram` | One expiry check plus one flow-end reset, 1,024 held: 23,385-26,097 ns before, 28-43 ns after, 0 allocations. |
| Parity | `make go-check` matches 7,430 of 7,430. |

## Security review finding SEC-CONTENT-1 (PRO-50 and PRO-154, 2026-11-22)

**The finding.** The Go content-pack loader decoded its tables with `json.Unmarshal`, which matches field names
case-insensitively, using Unicode simple folding. So `"Release"`, `"Risks"` or `"releaſe"` (U+017F) land in the
same field as the exact key, and a later variant overrides or merges with it. Digest verification, the content
gate and the Python reference all read exact keys only. A pack whose exact keys verified could therefore:
- load other tables from its variant keys;
- report a forged release version and digest in every record, while the verified digest differed.

The whole-pack digest still covered every key. The gap was between the tables used and the tables the release
digest pins.

**The fix** (`go/internal/content/content.go`):
- **Decoding.** The pack is decoded again from the strict tree (`parseStrict`, the tree digest verification reads).
  `exactFields` first removes every key that names a struct field only up to case, using the same folding as
  `encoding/json`. Exact keys are kept, and so are keys that name no field. The tables used are exactly the ones
  the exact keys hold, which is the Python reference's reading.
- **The `release` field** now has an explicit `json:"release"` tag. Without one, `encoding/json` matched it by
  its Go name, `Release`.
- **The reported digest** must equal the verified one, `Digests.Release`. The analyzer, analyze and live records
  now take it from `Digests.Release`.

| item | state | evidence |
|---|---|---|
| Regression test | `TestCaseVariantKeysAreIgnoredLikeTheReference` | A forged `releaſe`, a `protocol_nameſ` table and an upper-case `Risks` table on the committed pack. Before the fix, all three loaded: release `9999.12.31` with digest `0123456789abcdef` while the verified digest was `cdaa5993077d101a`, plus a merged `forged` risk and the forged protocol name. After it, the pack loads with the exact keys' tables and the verified digest. |
| Parity | unchanged | Python never loads pack files: the Go `--content` loader is the only reader. The fix aligns Go with the digest contract's exact keys, so the 7,430 parity cases are unaffected. |
| Fuzz | `FuzzParseNeverPanics`, 30 s | 2.7 M executions, no failure |

## Security review finding SEC-INSP-1 (PRO-48 and PRO-129, 2026-11-22; P0, blocks PR #40)

**The finding.** Each HTTP CONNECT in a shifted phase (trigger: `textroute/http.go` `shiftBoundary`) opened
another nested phase. A stream of CONNECT requests on one direction therefore built a chain one phase per
request, about MaxBytes/45 deep. Each segment was forwarded down the whole chain, and every level rebuilt the
evidence of the levels below it in `shiftResult`. The cost was O(d²) evidence and O(n³) work per direction.

**The fix** (`go/internal/engine/inspector.go`, Go only):
- Parser-driven shift nesting stops at `maxShiftDepth` = 2.
- Two levels keep every real case: a CONNECT tunnel, then TLS or an HTTP Upgrade inside it.
- A shift below that depth identifies the phase that saw it. Its reason gets "a further <boundary> boundary was
  not followed (shift nesting limit)", the stream turns terminal, and the rest is not inspected.
- Host-driven `OpenShift` records the depth as well.

| item | state | evidence |
|---|---|---|
| Regression test | `TestRepeatedConnectDoesNotNestWithoutBound` | 1,008 CONNECT requests, one per segment, as many as the default 64 KiB budget admits. On the old code: 2,019 evidence items and about 10 s. With the fix: 7 evidence items, exactly 2 shift markers, the limit named in the reason, and about 6 ms. |
| Parity | divergence recorded, no case changes | The Python reference nests without a bound, with the same cubic growth. Go now differs from it only at a third nested shift. No parity case nests shifts at all: 146 cases carry one shift marker and none carry two. All 7,430 still match, and `deltas.json` needs no entry. |
| Approval | approved | Lee approved the Go-only divergence on 2026-11-22 (PRO-129, relayed by Hermes: merge today with only P0 blocking). The fix is `e0aae82`, merged through PR #87 (`f209bd5`). |

## Security review finding SEC-HTTP-1 (PRO-177 and PRO-179, 2026-11-22; P1, blocks PR #40)

**The finding.** The HTTP/1 hostname came from the Host header alone, in both engines. An absolute-form request
target (`GET http://www.netflix.test/ HTTP/1.1` with `Host: www.youtube.test`) or a CONNECT target was ignored,
so a client could steer routing and policy with a Host header that names another site. RFC 9112 §3.2.2 says a
server must ignore Host for an absolute-form target. An HTTP/1.0 absolute-form request without a Host header
got no hostname at all.

**The fix** (`go/internal/protocols/textroute/http.go`, Go only, Lee's instruction on PRO-179: fix in Go and
record the divergence):
- With an absolute-form (`http://`, `https://`) or CONNECT authority-form target, the hostname is the target's
  authority. It is validated like a Host header: IP literals are never a hostname, and userinfo is dropped.
- A Host header that names another host, or an IP literal against a named target, or the reverse, adds
  `http_host_mismatch` = `present`. The disagreeing name itself is never emitted.
- The hostname evidence says `wire:http_target` when the name came from the target. When the Host header agrees,
  the output is unchanged and the source stays `wire:http_host`.
- The signature context `http-req-host-header` keeps the Host header's own value.
- HTTP/2 `:authority` handling is unchanged.

| item | state | evidence |
|---|---|---|
| Regression tests | `TestRequestTargetAuthorityIsTheHostname` (9 cases), `TestAbsoluteFormTargetIsTheObservedHostname` | Before the fix 5 of the 9 cases failed. In the absolute-form and CONNECT cases with a disagreeing Host, the Host header won; with no Host there was no hostname; and an IPv4 target took a named Host. After it all pass, and no disagreeing name appears in any evidence. |
| Parity | divergence recorded, 0 case changes | No parity case uses an absolute-form target, and every CONNECT case's Host agrees with its target. All 7,430 still match. |
| Randomized differential | approved-divergence rule | `random_diff.py` accepts a mismatch as SEC-HTTP-1 only when the request has an absolute-form or CONNECT target and every differing path is host attribution (hostname, evidence, application). Any other difference still fails; the self-test covers acceptance and both rejections. Seed 1: 1,972 matched plus 28 approved, 0 failures. Seeds 2 and 3 at 20,000 each: 265 and 225 approved, 0 failures. |

## PRO-260: TLS post-quantum hybrid key shares, Go only (Lee, 2026-11-23)

**The gap.** PR #97 (the Culvert landing) left out the preparation branch's integration work item #4: a TLS 1.3
ServerHello whose `key_share` selects a post-quantum hybrid group was `unknown` ("Server key share group outside
supported profile"), and so was a HelloRetryRequest asking for one. X25519MLKEM768 is the default of current
browsers and of Go's `crypto/tls`, so a modern HTTPS server's reply was not identified. The ClientHello side was
already identified: an offer's groups and key shares are collected, never judged.

**The fix** (`go/internal/protocols/tlsx/tls.go`, Go only by Lee's decision; the Python reference is frozen and
keeps the gap). The hybrid groups of the IANA TLS Supported Groups registry (draft-ietf-tls-ecdhe-mlkem) join the
named groups with their exact ServerHello share length: 0x11EB SecP256r1MLKEM768 (65 + 1088 bytes), 0x11EC
X25519MLKEM768 (1088 + 32) and 0x11ED SecP384r1MLKEM1024 (97 + 1568). The NIST-curve hybrids must start with an
uncompressed point (byte 4); X25519MLKEM768 starts with the ML-KEM ciphertext and has no fixed first byte.
`selected_key_exchange` is `hybrid`, which is not in the no-forward-secrecy set, so no risk follows. A share of
another length is malformed. Other groups (0x6399, the withdrawn X25519Kyber768Draft00, among them) are unchanged.
Unknown-registry handling (work item #5) is not part of this change.

| item | state | evidence |
|---|---|---|
| Regression tests | `go/internal/protocols/tlsx/hybrid_test.go` (ServerHello, HelloRetryRequest, ClientHello; whole, 1-byte and 7-byte feeds), `go/detector` `TestPostQuantumServerHello` (a real `crypto/tls` handshake with the default groups) | Before the fix `TestPostQuantumServerHello*` failed with "Server key share group outside supported profile"; after it all pass. `TestPostQuantumServerHelloGap`, which pinned the gap, is replaced by the positive test, as it said it would be. |
| Parity cases | 8 TLS hellos appended to `cases.py` (32 cases, 7,430 → 7,462) | The case generator is an approved exception (above); earlier case ids are unchanged. 14 cases match as they are: the kyber-draft group, the client offer and every truncated (`/half`) variant. |
| Parity deltas | 18 cases pinned in `migration/parity/deltas.json` | The three hybrids, the short share, the bad point and the HelloRetryRequest, each whole, bytes and sevens. Each case pins `$.events[0].observation` and `$.final` to Go's value (`go`). `compare.py` now requires that value from a Go results file, so a Go result that falls back to the reference's answer, or any other value, fails; the Python reference is still judged against its own expectation (`test_pinned_go_only_deltas_expect_exactly_the_recorded_value`). `make parity-go`: compared 7,462, matched 7,462, exempted 144. |
| The model | `migration/parity/pro260.py` (`--self-test`) | The approved divergence as code: in process, and only while its context is open, the reference's `parse_server_hello` sees a hybrid key_share as an X25519 stand-in of the same validity, and the group and `hybrid` are mapped back. Every other check runs in the reference's order with its messages. No reference file changes. Under the model the reference reproduces all 18 pinned values exactly and changes no other of the 916 TLS and DTLS cases (`test_pinned_go_values_are_the_reference_under_the_pro260_model`). |
| Capture differentials | `decrypt_diff.py` and `live_decrypt_diff.py` accept a difference only when Go equals the reference under the model | The OpenSSL-made exchanges negotiate X25519MLKEM768 by default (OpenSSL 3.5.9 here), so Go's reports gain the server's selections. Seed 1: decrypt 300 captures, 0 mismatched, 26 approved; live decrypt 300 scripts, 0 mismatched, 41 approved. Any other difference still fails (`test_pro_260_approves_only_the_reference_under_the_hybrid_model`). |
| CI finding on PR #105 (not PRO-260's) | `TestChaosAdmissionStormNeverExceedsMaxFlows` (PRO-101) fixed in the test | It failed in the CI coverage job: "no admission was refused". The storm only reached its 16-slot limit when goroutines overlapped; with one CPU they ran one after another. Reproduced on `main` `cb3ac80`: 20 of 30 runs fail at `-cpu=1`. Each goroutine now holds its first attempt until all 32 have made one, so at least 16 are refused on any scheduler: 0 of 30 failures at `-cpu=1`, 2 and 4, clean under `-race`. The assertion is unchanged. |
| Go replay test | `go/internal/replay` `TestPortedFamiliesMatchThePythonReference` honours the same pins | A pinned case's expectation at each pinned path is replaced by the recorded Go value before the exact diff (`deltas_test.go`, `TestExpectPinned`); changing one pinned value makes the test fail. |
| Family status | `tls` stays `parity-verified`, with `approved_divergences: 18` in `CAPABILITIES.json` | `verify_families.py`: a case whose deltas all pin Go's value is counted as an approved divergence, not a shortfall, and earns no class or session credit, so the family's other cases prove every class; an unpinned delta or a gap still disqualifies (`test_a_pinned_go_only_divergence_is_counted_but_earns_no_credit`). 79 of 88 families verified, unchanged. |

## Security review finding SEC-QUIC-3 (PRO-47 and PRO-123, 2026-11-23)

**The finding (Security Reviewer, PRO-47).** A decoy client Initial fixed or suppressed a QUIC flow's server name.
Both engines fed the CRYPTO data of every client Initial to the assembler whatever the datagram's size
(`go/internal/protocols/quicx/quic.go` `Validate`; Python `protocol_engine/quic.py` `quic()`, whose only size test
is the byte budget). RFC 9000 section 14.1 has a server discard a client Initial in a UDP datagram under 1200
bytes, so such a datagram never reaches the server, yet it counted as evidence:
- a 1000-byte Initial with SNI A on the real connection's DCID, then the real 1200-byte Initial with SNI B: the
  CRYPTO bytes contradict, the flow is invalidated and the real name is lost;
- the same decoy on another DCID, first: it is the flow's first identification, and the session tracker keeps the
  first identification (`go/internal/session/tracker.go` `ProcessUDP`; Python `Analyzer._udp`).

A second case needs no undersized datagram: two complete 1200-byte ClientHellos on two DCIDs of one flow that
name different servers. The assembler keeps DCIDs apart, so nothing compared them; the flow kept the first name
(Python: the session record says A while `last_classification` says B).

**The fix (Go only; Lee approved it on PRO-124, 2026-11-23, relayed by Hermes on PRO-123).** The Python reference
is unchanged and keeps both behaviours.
- `quicx.MinClientDatagram` = 1200. A long-header Initial whose payload opens with the client Initial keys is a
  client Initial; in a UDP datagram (the whole payload, so a coalesced datagram counts in full) under 1200 bytes it
  is `malformed` ("QUIC client Initial datagram below the RFC 9000 section 14.1 minimum of 1200 bytes; a server
  discards it"), and its CRYPTO data never enters the assembler. A `malformed` datagram is not an identification,
  so the flow's first identification is still open for the real Initial. A server Initial (it does not open with
  client keys) and framing-only validation (`QUICDecrypt` off, nothing asserted) are unchanged.
- `Assembler.SameServerName`: the first complete ClientHello of each flow scope records its server name (or its
  absence). A later complete ClientHello in that scope, on any DCID, that names another server (or adds or drops
  the SNI) turns its connection into the sticky conflict marker and returns the retraction the existing C5 path
  already handles, so the flow is invalidated in the tracker and stays so. The same name on a new DCID (a client's
  Initial after a Retry) agrees. The name lives as long as the flow: only `Reset(scope)` and `Clear` forget it
  (PRO-291 below; at first it was forgotten with the scope's last entry). The cost is one map lookup per complete
  ClientHello. The empty scope of a bare datagram inspector, which holds unrelated datagrams, is never compared.

| item | state | evidence |
|---|---|---|
| Regression tests | `TestUndersizedDecoyInitialDoesNotFixTheServerName`, `TestDisagreeingClientHellosOnOneFlowInvalidateIt` (`go/internal/analyzer`), `TestClientInitialDatagramMinimum`, `TestServerNameDisagreementWithinAScope` (`quicx`) | All four fail on `main` `21dd113`: the decoy on the real DCID gives `invalidated` with no name, a 1199-byte Initial is identified and stored, two names on two DCIDs stay `identified` as A. After the fix: the decoy cases give `identified` `example.com`; 1199 bytes is malformed with 0 assembler entries and 1200 identifies; a 300-byte Initial alone is malformed and coalesced into 1200 bytes opens; A then B is `invalidated` with no name; the same ClientHello on a new DCID stays `identified`; the marker is sticky, scoped and forgotten by `Reset`. |
| Parity | divergence recorded, 0 case changes | No committed case has an opened client Initial under 1200 bytes or two names on one flow. All 7,430 still match; `deltas.json` needs no entry. |
| Randomized differential | approved-divergence rule | `random_diff.py` generates a quarter of its QUIC Initials padded to 600 bytes. It accepts a mismatch as SEC-QUIC-3 only for a `quic` datagram under 1200 bytes whose Go answer is `malformed` with exactly the SEC-QUIC-3 reason and whose every differing path is in the observation; anything else still fails, and the self-test covers acceptance and four rejections. The summary line now counts each approved class. Seed 1 (2,000): 1,882 matched, 28 SEC-HTTP-1 and 90 SEC-QUIC-3 approved, 0 failures. Seeds 2 and 3 (20,000 each): 265 + 858 and 225 + 926 approved, 0 failures; the SEC-HTTP-1 counts equal the ones recorded before this change. |

### Codex finding PRO-290 P2: the first server name died with the scope's last entry (PRO-291, 2026-11-23)

**The finding** (Codex review PRO-290, `go/internal/protocols/quicx/assembler.go:123` on `d10c007`). `remove`
deleted a scope's first server name when the scope's last CRYPTO entry went, while the UDP tracker keeps the
flow's identification. With one assembler slot (an analyzer with `MaxConnections` 1) a second DCID on the same
flow evicts the first entry before `SameServerName` runs; idle expiry and an over-budget merge (`exhausted`) do the
same. A ClientHello naming another server was then taken as the first, and the earlier identification was never
retracted. Not on `main` (`21dd113`): the code came with SEC-QUIC-3, PR #107.

**The fix** (Go only, within the SEC-QUIC-3 divergence Lee approved on PRO-124). The names are a separate store
whose entries only `Reset(scope)`, `Clear` and `ForgetServerName` remove. It is an LRU bounded by `MaxNames`
(default 2 x `MaxConnections`); a dropped name is counted in `NameEvictions`, kept out of `Counts`, which mirrors
the reference's counters. The analyzer sets `MaxNames` to 2 x `MaxUDPFlows` + 2 (two direction scopes per flow,
both reset at every flow end, and the datagram being inspected) and calls `ForgetServerName` for a datagram whose
flow the full flow table turned away (`udp_flow_limit`), so orphan names cannot push out a live flow's name. CRYPTO
entries, their LRU and their counters are unchanged.

| item | state | evidence |
|---|---|---|
| Regression tests | `TestDisagreeingClientHelloAfterAssemblerEvictionInvalidatesTheFlow`, `TestRejectedUDPFlowKeepsNoServerName` (`go/internal/analyzer`), `TestServerNameOutlivesTheScopesLastEntry` (eviction, expiry, exhaustion, `Clear`), `TestServerNamesAreBounded` (`quicx`) | Before the fix the analyzer test gave `identified` `example.com` for A then B; after it, `invalidated` with no name. Each loss path now retracts B. Ten turned-away flows leave 0 name evictions. |
| Parity | 0 case changes | Only the Go-only SEC-QUIC-3 rule changes; the committed cases and the random differential classes are unaffected (numbers in the lane brief and the PR). |

### Codex findings PRO-312: two P2s on SEC-QUIC-3 (PRO-315, 2026-11-24)

**P2 1, `go/internal/protocols/quicx/assembler.go:123`** (the first SNI is removed with the scope's last
assembler entry while the UDP tracker keeps the flow's identification). Already fixed by `5b48d91` (PRO-291, PR
#108 into PR #107's branch, section above): only `Reset(scope)`, `Clear` and `ForgetServerName` forget a scope's
first name, and `TestDisagreeingClientHelloAfterAssemblerEvictionInvalidatesTheFlow` and
`TestServerNameOutlivesTheScopesLastEntry` cover eviction, expiry and exhaustion. No change.

**P2 2, `go/internal/protocols/quicx/quic.go:301`** (the sticky-conflict path returned a retraction before the
1200-byte check at line 328). Confirmed on `d950eb8`: a 1199-byte client Initial on a conflicted DCID returned
`Retracts` with `crypto_assembly=conflict` and refreshed the marker's idle time, so undersized decoys a server
discards could keep the marker alive and produce invalidation evidence. **The fix** (`653b1ca`, Go only, within the
SEC-QUIC-3 divergence Lee approved on PRO-124): `Validate` looks the marker up without refreshing it
(`Assembler.marker`), opens the packet, and returns the SEC-QUIC-3 malformed error for an opened client Initial
under 1200 bytes before the marker counts the datagram (`Assembler.refresh`). Datagrams that are not opened
(protection removal off, over the byte budget, or the client keys do not open them) are not known to be client
Initials and are still bound by the marker as before. The size check now runs right after a successful open,
before frame decoding, which also closes the related Codex P3 (`quic.go:320`: a short client Initial with a frame
outside the Initial profile was a structural QUIC match; now it is malformed).

| item | state | evidence |
|---|---|---|
| Regression tests | `TestConflictedConnectionAppliesTheClientDatagramMinimum`, `TestShortClientInitialWithUnsupportedFrameIsMalformed` (`quicx`) | Both fail on `d950eb8`: the 1199-byte Initial on a conflicted DCID gives `Retracts` (conflict), the 300-byte Initial with HANDSHAKE_DONE gives `initial_protection=unverified`. After the fix: both are malformed with the 1200-byte reason; the marker keeps its old idle time (expired at 10.5 after an undersized datagram at 8), a 1200-byte Initial still retracts and refreshes it, and a damaged 600-byte datagram the keys do not open still retracts. |
| Parity | 0 case changes | Only the Go-only SEC-QUIC-3 rule changes; numbers in the lane brief and the PR. |

## Codex finding PRO-12 P2: the unknown buffer outlived the byte budget (PRO-189, 2026-11-22)

**The finding** (Codex review PRO-12, Tier 1 window 1, `dbe20f3..50ce5c0`; `go/internal/engine/inspector.go`,
the unknown-buffering branch of `Feed`). After dispatch fails, the unknown-payload buffer collects up to
`heuristic_bytes` for the heuristics, and the stream is final once the buffer is full. When `max_bytes` is below
that limit (for example 64 against the default 512), the byte budget ran out first. The buffer then never
filled, so the stream reported `detecting` for every later byte and only `End` gave a verdict. The Python
reference behaves the same way (`protocol_engine/engine.py`, the `_unknown` branch of `feed`).

**The fix** (Go only; the Python reference is frozen). `unknownFull` is true when the buffer holds
`unknownLimit` bytes or the byte budget is spent. The stream then finalizes at the last budgeted byte, with the
verdict `End` would give for the same bytes: `unknown`, "Prefix outside supported protocol families", and the
heuristics evidence over the buffered bytes.

| item | state | evidence |
|---|---|---|
| Regression test | `TestUnknownBufferFinalizesWhenTheByteBudgetIsExhausted` (3 cases) | `max_bytes` 64, `heuristic_bytes` 512, 160 bytes no family claims: one segment past the budget, the budget spent in the buffering phase, and the budget ending exactly at a segment. Before the fix all 3 stayed `detecting` after 64 bytes. After it each is a terminal `unknown` whose reason and evidence equal `End`'s verdict on the same 64 bytes, and later bytes emit nothing. |
| Parity | divergence recorded, 0 case changes | Go now gives the verdict when the budget runs out, where Python waits for close. This only happens when `max_bytes` is below the unknown buffer's limit. All 7,430 parity cases still match. |
| Live harness | modelled-reference rule | In `live`, the stream's `unknown` verdict now arrives as an `updated` classification event, which carries risks and the policy verdict. Python reported it later, as `observation_retired`, which carries neither, and the counters follow. `migration/parity/pro189.py` reruns the frozen reference with only the budget condition added (`modelled()`, with a self-test). `live_diff.py` accepts a mismatching replay only when Go then matches it exactly. Seed 1: 297 matched, 3 approved (all with `--byte-limit 64`), 0 mismatched. |

## Codex Tier-1 P2 findings, windows 2-10 (PRO-201, 2026-11-22)

Hermes, PRO-201: the P2/P3 findings of Codex PRO-13 to PRO-21 (frozen range `dbe20f3..50ce5c0`), each checked on
`main` `e5ac90f` (the Go migration merged with PR #40), fixed with a failing-first test where the fix keeps parity,
and otherwise held with its patch in `migration/held-patches/PRO-201/` for an approved parity delta. Every finding
below was still present on `e5ac90f` unless the row says otherwise. Branch `claude/funny-cori-6znbkn`.

| Item | Present | Commit | Test (fails before, passes after) | Python reference / parity |
|---|---|---|---|---|
| PRO-13 quicx assembler: over-budget merge returned Exhausted before the contradiction check | yes | `7da811e` | `TestContradictionOutranksExhaustion` | Python checks the budget first; Go-only divergence, 0 case changes |
| PRO-13 decrypt keys: a rejected append left entries indexed without a version bump (C16) | yes | `ce8b057` | `TestRejectedAppendIndexesNothing` | Python keeps the earlier lines; Go-only, callers already stop on the error; decrypt and live-decrypt differentials 0 mismatched |
| PRO-13 decrypt connection: terminal connections kept framers, buffers and keys | yes | `60db15f` | `TestTerminalConnectionsReleaseTheirHeavyState`, `TestClosedConnectionsKeepTheirRowNotTheirInspectors` | no output change |
| PRO-14 content: case-folded struct fields | no, fixed by `bc80f45` (SEC-CONTENT-1, PR #84) | — | `exactFields` covers the host catalog | — |
| PRO-14 `check_content.py --update` skipped C11 when the prior lock was missing or malformed | yes | `4eb6d3b` | `test_content.RollbackTests.test_a_missing_or_malformed_prior_lock_refuses_the_update` | tool only |
| PRO-14 `compare.py`: a JSON boolean equalled a number | yes | `144daf5` | `test_a_boolean_never_matches_a_number` | int and float still compare by value; 7,430 of 7,430 still match |
| PRO-15 x509x four-octet DER length overflow on 32-bit | yes | `4c405d1` | `TestFourOctetLengthNeverOverflowsTheContainerGuard` (GOARCH=386) | message equals Python's `_element`; no 64-bit change |
| PRO-15 SSH KEXINIT name-list uint32→int on 32-bit | yes | `bff93e5` | `TestKexinitNameListLengthIsBoundedBeforeConversion` (GOARCH=386: panic before) | reference message; no 64-bit change |
| PRO-16 buffer replacement only delta-accounted | yes, held | — | — | **decision**: the transient peak is limit plus one old capacity; strict reservation changes ADR 0001 and its tests. `buffer.Account` has no production caller |
| PRO-16 pcapng simple packet length narrowing on 32-bit | yes | `b346b50` | `TestSimplePacketLengthIsCappedBeforeConversion` (GOARCH=386: panic before) | matches Python `min(original, snaplen)`. Left: `Record.OriginalLength` is an int, so on 386 an original length of 2^31 or more is negative (wrong value, no panic) |
| PRO-16 chunked continuation searched past its budget | yes | `ec32ac0` | `TestChunkedLineSearchStopsAtTheBudget`, `TestChunkedContinuationOutcomeAtEveryBudget` | no output change |
| PRO-16 P3 pcapng end-of-options | no change | — | — | matches the reference `_options` line for line; lenient but safe |
| PRO-17 SMB SESSION_SETUP response with an empty security buffer | yes, held | patch `pro17-smb-empty-security-buffer.patch` | `TestSMB2SessionSetupResponseWithEmptySecurityBuffer` | metrics change in 2 variants of `smb-064-smb2-session-short`; needs an approved delta |
| PRO-17 SMB NEGOTIATE response without SIGNING_ENABLED | yes, held | patch `pro17-smb-signing-enabled.patch` | `TestSMB2NegotiateResponseRequiresSigningEnabled` | `smb-034-smb2-response-required` (4 variants) goes from smb2 to malformed; needs an approved delta |
| PRO-17 P3 combined SessionFlags | yes | `9f7f304` | `TestSMB2SessionSetupResponseSessionFlagsAreExclusive` | Go-only, 0 case changes |
| PRO-17 IKEv2 responder selecting proposal 2 or later | yes | `74ee342` | `TestIKEv2ResponderMayAcceptALaterProposal` | Go-only, 0 case changes |
| PRO-17 SPNEGO NegTokenInit without mechTypes | yes, held | patch `pro17-spnego-mechtypes.patch` | `TestClassifyTokenRejects` (two rows) | `ldap-079-init-no-fields` (3 variants) goes from ldap/3 to malformed; needs an approved delta |
| PRO-18 session id: unkeyed BLAKE2s | yes, no change | — | — | **decision**: Python is identical (`events.py:46`); a keyed id changes every id in both engines. Recommendation: document it as a linkable pseudonym; add a keyed, versioned field later if unlinkability is wanted |
| PRO-18 duplicate SYN split the generation | yes, partly | `0c89721` (offline decrypt coordinator) | `TestRetransmittedSYNKeepsTheGeneration` | Go-only divergence; differentials 0 mismatched. The live pre-check (`go/internal/live/monitor.go`) is left: changing it gives parity-live 5 of 300 mismatched, and needs an approved-divergence rule |
| PRO-18 key log truncated and regrown in place | yes | `6b614c0` | `TestKeyLogRefusesATruncationThatRegrewBetweenPolls` | Python checks the size only; Go-only (a SHA-256 of the consumed prefix, never a copy) |
| PRO-18 live Feed ignored RejectedConnections | yes, held | patch `pro18-live-reject-counter.patch` | — | Python also only counts; fail-closed gives parity-live-decrypt 5 of 300 mismatched |
| PRO-18 stale cached row after a key update | yes, held | patch `pro18-stale-cached-row.patch` | `TestAReportCachedWhileAwaitingKeysSeesALaterAuthenticationFailure` | the Python reference has the same bug; the fix gives parity-live-decrypt 1 of 300 mismatched |
| PRO-18 failed decryption named an inner protocol | yes, held | patch `pro18-failed-inner-protocol.patch` | `TestAFailedDecryptionNamesNoInnerProtocol` | Python does the same; the fix gives parity-decrypt 15 of 300 and parity-live-decrypt 8 of 300 mismatched |
| PRO-18 livedecrypt child reaped twice (race) | yes | `ac8834f` | `TestRunReapsAChildThatOutlivesTheExitWaitOnce` (`-race` before) | no output change |
| PRO-19 `(?!)` gives NotPorted where Python 3.11/3.12 reject | yes, kept | `2cac79c` (pin) | `TestEmptyNegativeLookaheadIsNotPorted` | Python 3.13 accepts it as FAILURE, so the reference answer depends on the interpreter; NotPorted falls back to the reference |
| PRO-19 a signature may take a built-in application name | yes, no change | — | — | **decision**: Python is identical; decide in both engines (reject the name, or keep the built-in's metadata) |
| PRO-19 description key order keeps the digest | yes, no change | — | — | inherited; the digest must equal Python's `sort_keys` digest |
| PRO-19 FromJSON without a byte bound | yes | `3503bf2` | `TestFromJSONBoundsTheDocument` | the 4 MiB text of `from_path`; the count check keeps the reference order (`TestCountRefusalKeepsTheReferenceOrder`) |
| PRO-20 verify_families credited replays and sessions by name | yes | `098b201` | `test_a_replay_of_the_positive_message_is_not_foreign_bytes`, `test_a_session_case_counts_only_when_its_record_identifies_the_family` | **79 of 88 families stay parity-verified**: ftp, http, imap, nats, pop3, rtsp, sip, smtp and ssh had only 1- and 7-byte replays as foreign bytes and are now `experimental`. Restoring them needs real foreign cases in `cases.json` (approval) |
| PRO-20 analyze/decrypt verdicts passed empty runs | yes | `1621f61` | `AnalyzeVerdictTests`, `DecryptVerdictTests` | `--count 0` now exits 1 |
| PRO-21 control_diff ignored worker exit and stderr | yes | `0d8dc62` | `ControlWorkerTests` | 120 runs, 0 mismatched |
| PRO-21 server_diff normalized whole telemetry | yes | `d34d184` | `ServerNormalizerTests` | only wall-clock measurements normalized; 424 exchanges, 0 mismatched |
| PRO-21 server_diff timeouts and probes discarded | yes | `9b29688` | `ServerProbeTests` | 424 exchanges, 0 probes failed |
| PRO-21 schema_go ignored return codes | yes | `a56728d` | `SchemaInvocationTests` | 200 captures, 0 problems |
| PRO-21 adversarial judge order, empty record lists | yes | `5920061` | `AdversarialJudgeTests` | 4,041 cases, 1 known finding (F-ADV-1), 0 failures |

## PR #99 reconciled with main (PRO-261, 2026-11-23)

Hermes, PRO-261: PR #99 (`claude/keen-goodall-f8yhou`, head `54305c7`) fixed the same PRO-201 findings as PR #98
(merged, `b9927b7`) in 23 commits that are not patch-identical to `main`. Each #99 commit was checked against
`main` `cb3ac80` by running its regression test there (Go tests copied in; Python test files from #99 run against
`main`'s tools, API differences read by hand). Only the gaps below were ported, on `claude/engine-PRO-261-reconcile-99`.

| #99 commit | Finding | On `main` | Evidence |
|---|---|---|---|
| `f4797ef` | PRO-15 x509x four-octet length | covered, `4c405d1` | #99's `TestElementFourOctetLengthBeyondContainerIsMalformed` passes on main, amd64 and GOARCH=386 |
| `d12b794` | PRO-15 KEXINIT name-list uint32 | covered, `bff93e5` | #99's test (adapted to `newKexInit(n, nil)`) passes, amd64 and 386 |
| `a2ae04e` | PRO-13 terminal TLS connection state | covered, `60db15f` | #99's decrypt test passes on main |
| `a87d313` | PRO-13 key-log append atomic | covered, `ce8b057` | #99's `TestRejectedAppendIndexesNothing` (renamed) passes beside main's |
| `d211649` | PRO-18 capture child reaped once | covered, `ac8834f` | #99's `TestRunTimeoutReapsTheCaptureChildThroughOneWaiter` passes under `-race` |
| `cb8c634` | PRO-14 host-catalog case-variant keys | covered, `bc80f45` | main has the same test name and body |
| `bfd616b` | PRO-14 `check_content --update` fail-closed | covered, `4eb6d3b` | #99's subtests pass on main without `--bootstrap` (a #99-only option, not part of the finding) |
| `43b18bc` | PRO-14 boolean vs number in `compare.py` | covered, `144daf5` | #99's `test_migration_parity.py`: 15 of 15 pass on main |
| `8249ba6` | PRO-19 FromJSON byte bound | covered, `3503bf2` | #99's `TestFromJSONRefusesMoreThanMaxFileBytes` passes on main |
| `7aadbef` | PRO-16 buffer growth charges both arrays | **held decision on main** (ADR 0001, row above) | #99's two tests fail on main by design; not ported. `buffer.Bounded` still has no production caller (`go/detector` uses only `buffer.Account` reservations) |
| `185c7dd` | PRO-16 pcapng 32-bit lengths | **partly missing**: the slice panic is fixed (`b346b50`), `OriginalLength` still wrapped negative on 386 | ported: `capture.length` saturates; #99's test fails on main under GOARCH=386 (`OriginalLength:-1`) and passes after |
| `afd82ec` | PRO-16 chunked continuation budget | covered, `ec32ac0` | #99's guard test passes on main |
| `62a1957` | PRO-20 family evidence | covered, `098b201` | #99's stricter extras (a positive must identify the family; a foreign case must not) change no family's status on today's cases. #99's new foreign cases in `cases.json` that restore 9 families are not ported: that needs approval (row above) |
| `d519ac0` | PRO-20 analyze/decrypt empty runs | **partly missing**: a run of refused presentations, or of decryptions naming no inner application, passed | ported: `shortfall` checks both; real runs 300/300, 201 completed presentations, 147 decrypted, 9 inner applications |
| `edcc29b` | PRO-21 control worker completion | covered, `0d8dc62` | main checks the exit status the last line implies; #99 also failed on any stderr, not ported (Go `live` forwards capture stderr) |
| `2ac6b5b` | PRO-21 server telemetry normalization | **partly missing**: a null in a measurement slot was normalized away | ported: only numbers become markers |
| `a29d6ca` | PRO-21 server waits and probes | covered, `9b29688` | main's admission check is stricter (states per slot) |
| `20515ea` | PRO-21 schema_go completion | covered, `a56728d` | same rules, plus a timeout on main |
| `ef2beff` | PRO-21 adversarial judge | covered, `5920061` | same bases and empty-record rule |
| `c38fa5e`, `111a04f`, `5f9c9d1`, `54305c7` | docs, lint, backlog | superseded | #99's PM-9 to PM-14 restate decisions this file's PRO-201 table already tracks (PM-9, PM-11 a/b and the FromJSON half of PM-12 are fixed on main) |

## Randomized differential (PRO-100, 2026-11-22)

Hermes, PRO-100: differential testing with random inputs, the Python reference as the oracle.
`migration/parity/random_diff.py` draws seeded, valid-shaped client openings:
- TLS ClientHello records (GREASE, varied server names, ALPN, versions, groups, key shares, padding, unknown,
  duplicated and ECH extensions, session ids, record versions);
- HTTP/1.x request heads;
- SSH identification lines, with an optional KEXINIT;
- protected QUIC v1/v2 Initials, with reordered CRYPTO frames.

Each case is varied the way traffic arrives: random fragments, truncation with or without the capture-ended
reason, a correct or wrong hint, or a tight byte budget. The Go engine answers through `protodetect replay`, and
`compare.py` compares every event, the final observation and the metrics exactly.

| item | state | evidence |
|---|---|---|
| CI run | gate | `make parity-random` is part of `make go-check`, so the CI `go-engine` job runs it. It runs three steps: `--self-test` (allow-list rules, stale entries, determinism), `--plant` on 300 cases (the planted difference must be caught), then seed 1 at 2,000 cases, about 3 s. Seed 1: 2,000 of 2,000 matched. |
| Long run | available | `make parity-random-long SEED=n COUNT=n`. Seeds 2-11 at 20,000 cases each, plus seed 12 at 3,000: 203,000 of 203,000 matched, 0 allowed, about 21 s per 20,000. A nightly job is a CI/CD-lane workflow change (requested). |
| Allow-list | empty | `migration/parity/random_allow.json`: case id to reason. An entry that no longer mismatches on its seed fails the run. |
| Self-checks | pass, in CI | `--plant` alters one reference answer to another valid status, and the run must report exactly that case. `--self-test` checks `judge()`: an allowed mismatch passes, an unlisted one fails, and a listed case that now agrees fails. Removing the stale-entry rule makes it fail. |
| Found and fixed | 0 engine mismatches | The first trial had 8 cases Go declined ("not ported: hint http/ftp/redis"). It was a harness error: `cases.run_stream` drops a hint outside `registry.PARSERS`, so stream hints are now drawn from `PARSERS` only. |

## tshark oracle on real implementations (PRO-127, 2026-11-22)

Hermes asked for a pcap-based oracle in PRO-127 and chose its data source in PRO-186 (option A).
- Real, unmodified clients and servers talk on 127.0.0.1 through a recording relay:
  - OpenSSL 3.0.13 `s_client` and `s_server`;
  - curl 8.5.0, against `s_server` and Go `net/http`;
  - quic-go v0.65.0, QUIC v1 and v2.
- The relay writes a pcap with synthetic Ethernet, IPv4 and TCP/UDP framing into the test's temporary
  directory. Nothing is committed.
- gopacket v1.7.7 (BSD-3-Clause) reads and reassembles the pcap, independently of the engine's decoder, and
  the engine classifies each flow without a hint.
- tshark 4.2.2 (GPL-2.0, an external process only) dissects the same file.
- Compared fields: SNI, offered ALPN, the highest offered TLS version, the HTTP Host and the QUIC version.
- It is a separate test-only module, `go/oracle`: `go/go.mod` and `go/vendor` are unchanged.
- The full recipe, the tool pins and the licences are in `go/oracle/README.md`.

| item | state | evidence |
|---|---|---|
| Comparison | 26 of 26 agree | 10 scenarios: TLS 1.3 and 1.2, no SNI, a 253-byte SNI, 7-, 50-, 100- and 5-byte segments, out-of-order pairs, curl h2 and http/1.1 offers, HTTP/1.1 and 1.0 Host, QUIC v1 and v2. The allow-list is empty. |
| Self-checks | pass | Planted wrong SNI: the run fails. Listed with a reason: it passes. Listed after it agrees again: it fails (stale entry). An entry no scenario compares also fails. Tool-free unit tests cover the normalisations and the recorder/reader round trip. Five runs under `-race` all pass. |
| Finding | not an engine bug | quic-go splits and reorders its ClientHello's CRYPTO frames over two Initials. Without the host-owned cross-datagram store (`Datagram.Assembler`), Go and the Python reference both stay at "ClientHello incomplete" with the same output. With the store attached as the analyzer attaches it, the server name and ALPN agree. |
| Runs | nightly (requested) | `make pcap-oracle`. It needs the three pinned tools and module-proxy access to build, so it isn't part of `go-check`; the nightly job belongs to the CI/CD lane. |

## Mutation testing (PRO-126, 2026-11-22)

Hermes, PRO-126: mutation testing of the Go protocol parsers with gremlins (github.com/go-gremlins/gremlins
v0.6.0, Apache-2.0). It is test tooling only, pinned in its own module `migration/mutation/gremlins` (`go.sum` pins
all 22 linked modules: 13 MIT, 5 BSD-3-Clause, 4 Apache-2.0; no GPL or LGPL), installed into `build/` and never
linked into or vendored with `go/`. `migration/mutation/mutation.py` runs it on each package and compares
efficacy (killed / (killed + lived)) with `migration/mutation/baseline.json`; a package more than 5 points below its
baseline, or one with no result, fails the run. It is a nightly job, never a per-PR gate (one full run takes about
20 minutes, `framed` alone 17).

| package | killed | lived | not covered | efficacy | first run (base `752dcbd`) |
|---|---|---|---|---|---|
| tlsx | 192 | 48 | 263 | 80.00% | 99 killed, 69 lived, 58.93% |
| quicx | 192 | 25 | 6 | 88.48% | 150 killed, 67 lived, 69.12% |
| textroute | 232 | 111 | 582 | 67.64% | 7 killed, 3 lived, 914 not covered |
| x509x | 243 | 63 | 56 | 79.41% | same |
| hpack | 73 | 20 | 6 | 78.49% | same |
| fingerprint | 28 | 23 | 0 | 54.90% | same |
| framed | 718 | 507 | 3568 | 58.61% | same |
| dnsx, heuristics | 0 | 0 | 269, 72 | none covered | tested only from other packages |

The first run's survivors in TLS, QUIC and HTTP/1 sat on comparison boundaries and length arithmetic that no
package-local test hit exactly. `migration/mutation/boundaries.py` generates one `boundary_test.go` per package
(73 TLS, 48 QUIC, 105 text-route cases), each on a limit or one past it, with the expected outcome from the Python
reference, so each case checks the boundary and the parity at once; `make go-check` runs `boundaries.py --check`.
Survivors that remain are mostly in DTLS (`tlsx/dtls.go`), the QUIC assembler's idle-heap and expiry comparisons, HTTP header classification and the
non-HTTP text routes. Some are equivalent mutants (`i >= 0` read as `i > 0` before slicing to an empty prefix).
Run safeguards, each found by an end-to-end `make mutation`:
- One `hpack` mutant removes an allocation bound, and its test binary grew to 11 GB until the kernel killed it,
  taking unrelated processes with it. `mutation.py` caps every process it starts at 4 GiB of address space
  (`--memory-mb`), so such a mutant fails fast and counts as killed.
- A cached coverage run gives gremlins a near-zero reference time, and then every mutant times out (one run: 8
  killed, 0 lived, 340 timed out, efficacy "100%"). The test cache is cleared before each package, and a package
  where more than 25% of the tested mutants time out fails the run.
- A package with a baseline efficacy that comes back with nothing covered fails (it used to be skipped).
With these, a full clean run reproduced the baseline exactly in all nine packages (about 21 minutes on 4 cores).
The nightly workflow step is a CI/CD-lane change (requested).

## Property, fuzz and chaos tests for every parser (PRO-101, 2026-11-23)

Hermes, PRO-101 (Lee's addition of 2026-11-21: `pgregory.net/rapid` v1.3.0, MPL-2.0, test-only; ADR 0002). Four
properties, each checked by rapid (shrinking) and by a native `testing.F` target running the same check, so a
counterexample from either is replayed by `go test` from the target's checked-in corpus (`testdata/fuzz/<target>/`):

| test | what it covers | property |
|---|---|---|
| `TestEveryParserIsSplitInvariantAndBounded` / `FuzzEveryParserIsSplitInvariant` (`go/internal/engine/property_test.go`) | all 59 registry parsers (`factories`), one rapid subtest each, half the draws from fixtures that parser identifies (53 of 59 have one) | no panic, no over-consume or stall (`parsertest.DriveCuts`), whole = any split, the same twice, a credited parser within a 512-byte Credit (`parsertest.CheckCredit`) |
| `TestInspectorIsSplitInvariantAndBounded` / `FuzzInspectorIsSplitInvariant` | the inspector: dispatch, the chosen parser, shifts, the unknown buffer | final observation, terminal flag and boundary equal whole and split; `bytes_inspected` within `MaxBytes`, `bytes_received` exact, retained bytes bounded |
| `TestDatagramIsDeterministicOnEveryHint` / `FuzzDatagramIsDeterministic` | the datagram inspector on every UDP hint and none | no panic, the same observation twice |
| `TestFlowIsSplitInvariantAndBounded` / `FuzzFlowIsSplitInvariant` (`go/detector/property_test.go`) | the facade: both directions interleaved, a 24-call feed budget | whole = split while the split fits the feed budget, else `budget_exhausted`/`engine`; the same twice; retained within the flow allowance after every call; closed flows leave nothing retained |

Two fields are compared as the reference defines them, not as split invariant: `bytes_inspected` counts the whole
chunk in which a parser fails (`engine.py`, inspector.go `continueFeed`), and a parser's consumed count after a
fault is discarded with the parser (`Inspector.failed`). Both are checked against their budgets instead.

Finding **PRO-101 F1** (P3, metrics only, Python and Go alike): the SMB1 and SMB2 parsers watch one more frame after
NEGOTIATE. When the next frame's 8-byte header is not an SMB frame, `nextFrame` returns `start` (0 bytes of this
call), but header bytes that arrived in earlier calls were already reported consumed, so `bytes_inspected` depends
on the split by up to 7 bytes (byte by byte: 93, whole: 86, for an SMB1 NEGOTIATE followed by a misaligned copy).
The observation and the boundary are unchanged. The reference has the same code (`protocol_engine/windows.py`
`_next_frame`, `return start`), so a Go fix is a parity delta waiting for Hermes/Lee; the property relaxes only the
consumed field for `smb1` and `smb2` (`continuationConsumedVaries`), and the two shrunk seeds
(`rapid-smb1-watch-header-F1`, `rapid-smb2-watch-header-F1`) fail without that entry. Tracking issue:
[#103](https://github.com/leenadav/protocol-detector/issues/103) (opened on Hermes's request, PRO-101 review); the
decision, to accept it as reference behaviour or fix it in Go with a parity delta, is Lee's.

Chaos tests (`go/detector/chaos_test.go`, after Culvert's standard; every one runs under `go test -race`): an
admission storm (32 goroutines, 16 slots: never over the limit at any sampled instant, every attempt counted once,
all slots back), memory exhaustion (4 flow allowances, 16 concurrent admissions: 4 admitted, 12 `ErrMemory`), huge
headers (a 1 MiB header line, 65,536 small headers, a TLS record length over the profile and a 16 MiB ClientHello
claim, each whole, in 64 KiB and in 1,500-byte pieces: the pinned budget outcome, within the byte budget and the
allowance), slowloris (128 flows holding every slot, one byte per call: `budget_exhausted` at call 33 of a 32-call
budget, no change after, nothing retained, admission refused until they close), and a panic storm (one engine call
in 7 panics across 16 goroutines: no panic escapes, only the faulting flow is quarantined, `Stats.Panics` equals the
quarantined flows, the breaker refuses from `PanicLimit` on, a flow admitted before keeps working; with
`PanicLimit` 0 the breaker never opens).

The four new fuzz targets are in `GO_FUZZ_SMOKE` (per-push `go-fuzz-smoke`, 50 s together); the nightly
`extended Go fuzz (every fuzz target)` job discovers every `Fuzz*` under `go/` (`tools/go_fuzz_long.py`), so
`nightly-fuzz.yml` needs no edit to run them. Local runs: the engine properties at 20,000 rapid checks three times, the facade property at 20,000 once, and each
native target for 45 s (828,913 / 943,876 / 74,577 / 901,280 executions), with no failure other than F1.

Commit `fd46be0` (frozen for Codex). Also fixed there: `TestKexinitNameListLengthIsBoundedBeforeConversion` (`textroute/posture_test.go`) did not compile
on `main` `b9927b7` (`newKexInit` gained its Credit argument in PRO-201), so `go vet ./...` and the textroute tests
failed there.

### PRO-101 review follow-up (Hermes CHANGES, 2026-11-23)

- **Who merged PR #102.** GitHub records `merged_by: leenadav` at 13:25:46 UTC (merge `cb3ac80`). The cloud session
  that opened it (`session_01UqaXYzkPpYhwBgjiMuapJt`) did not merge it. Its transcript shows no merge call: its tool
  calls were PR reads, Bash, `ReadNotifications` and `delete_trigger`. Its last turn before the merge ended at
  13:13:19, and it woke at 13:25:58 only to read the merge notification and check that `3a25bd0` was on `main`.
  The click came from Lee's account, outside that session. No agent merges again without Lee's approval.
- **Why that branch and that base.** The PR went to `main` because PR #40 had already merged `claude/go-migration` into
  `main` (2026-11-22), and since 2026-11-23 Hermes's rule keeps that branch as frozen history ("never push to it").
  The branch was `claude/busy-ramanujan-7oczj2`, not `claude/engine-PRO-101-<slug>`, because the cloud session's
  harness assigns each session exactly one development branch and refuses pushes to any other branch without
  explicit permission. An agent cannot choose the name. This follow-up is under the same constraint
  (`claude/dazzling-franklin-1179wl`). A `claude/engine-PRO-n-<slug>` name needs the bridge to create the session with
  that branch (its `outcome_branch`).
- **Secret scan.** Pinned gitleaks 8.30.1 (`tools/scanners/go.mod` and `go.sum`, built read-only on go1.27.4, run as
  in `ci.yml`: `git --ignore-gitleaks-allow --redact`):
  `b9927b7..fd46be0`: 1 commit, about 192,455 bytes (the vendored rapid included), 0 findings.
  `fd46be0..3a25bd0`: 1 commit, about 7,411 bytes, 0 findings. Both together: 2 commits, about 199,866 bytes,
  0 findings, exit 0. Full history as CI scans it (unshallow clone, `HEAD`
  = `cb3ac80`): 653 commits, about 51.5 MB, 0 findings, exit 0; `tools/check_gitleaks_allowlist.py --bin` with that
  binary passes.
- **The relaxed fields.** F1 is tracked in [#103](https://github.com/leenadav/protocol-detector/issues/103), linked
  from `continuationConsumedVaries` and the LANE-BRIEF. The other relaxation, `bytes_inspected` not compared across
  splits in `inspectorOutcome`, is the reference contract (`engine.py` counts the whole chunk in which a parser
  fails), not a finding. The issue names both, and it stays checked against `MaxBytes`.
- **Nightly fuzz.** `nightly-fuzz.yml` was not run for PRO-101. Its `extended Go fuzz (every fuzz target)` job finds
  the new targets through `tools/go_fuzz_long.py`. Its first scheduled run on `main` after `cb3ac80` is the evidence
  to record here.

### PRO-141: livectl stop tests made deterministic (2026-11-24)

- **Failure.** `TestStopReleasesTheProcessGroupAndLeavesTheKeyLog` (`go/internal/livectl/process_test.go`) timed out
  "waiting for the stopped state" at 10.01 s on PR #65 head `6fdaa33` (pull_request run 44960532796; the push run
  44960527096 of the same SHA passed), and on PR head `8480775` (run 45230141542). Earlier, `f5353c5` failed
  `TestStopKills…` the same way (run 44986686845).
- **Root cause (PRO-140, Research Lab; confirmed here).** The test raced its stand-in worker, not `Manager.Stop`. The
  shell printed both events and only then set `trap 'exit 0' INT`; the test called `Stop` as soon as the events were
  ingested. A SIGINT in that window killed the shell (status -2), `read` recorded "Capture process exited
  unexpectedly (-2).", the phase became `failed`, and the poll for `stopped` ran out. PRO-140: 0 of 420 natural
  failures, 5 of 5 with a 0.3 s delay before the trap. Here, on `main` `21dd113` with that delay: 3 of 3 failed.
- **Fix (`aff4d13`, test only).** The trap is the worker's first command; the worker writes its child file aside and
  renames it, then writes a ready file as its last step; the three stop tests (`TestStopReleases…`,
  `TestStopKills…`, `TestLeaseExpiry…`) call `awaitReady` before they stop. No assertion changed and no product code
  changed; Python untouched.
- **Proof (go1.27.4, `-race`).** With a forced 0.3 s delay after the events in the fixed worker: 15 of 15 passed
  (`-count=5` of the three tests). `-count=200 -run '^TestStopReleasesTheProcessGroupAndLeavesTheKeyLog$'`: ok, 200 of
  200 (14.4 s); again with 8 busy loops on 4 CPUs: ok (17.7 s), and `TestStopKills…` plus `TestLeaseExpiry…`
  `-count=20` under the same load: ok (152.7 s). Gates are in the PR body.
- **Branch.** `claude/vigilant-meitner-t7kw7h`, assigned by the session's harness (see the PRO-101 follow-up above).

## Adversarial identification (2026-11-18)

Lee, 2026-11-18: a suite that tries to deceive the detector on purpose, asserting that it either stays honest
(the identification the bytes support, or an evidence-limited outcome) or is caught misidentifying.

| item | state | evidence |
|---|---|---|
| Suite | implemented | `migration/parity/adversarial.py` (`make adversarial`, in `go-check`): 41 built cases in five kinds and 4,000 seeded noise payloads. **mimic**: a request line over binary, a request line alone, an SSH banner prefix, a TLS record header over noise, a handshake type without a ClientHello, zeros, a DNS-over-TCP length over noise, an SMTP-shaped greeting over binary, a response line from the client, a PROXY v1 header before TLS, DNS and QUIC headers over noise. **prefix**: HTTP then TLS, a stray byte before TLS or HTTP, an SSH banner then HTTP, TLS then HTTP. **sni**: a known service's name over an unrelated certificate, a lookalike suffix, a trailing dot, a punycode lookalike, upper case. **port**: SSH on 443, TLS on 80, HTTP on 22, noise on 443/22/445 and UDP 53/443/5004/123, DNS on UDP 443. **fragment**: a ClientHello and a request one byte at a time, a record header split, a handshake across two records, reordered segments, overlaps that rewrite retained bytes. Each case states the outcomes an honest detector may give; a session must also keep a server name a client assertion. A misidentification must be listed as a finding (an unlisted one fails, a listed one that no longer reproduces fails). The Go backend answers every case through `protodetect replay` and must match the reference exactly: 4,041 of 4,041. A planted unlisted finding fails the suite. |
| Result | 4,037 honest, 1 finding | Every built case is honest in both engines. Where the bytes do support a family (a request line before TLS, an SSH banner before HTTP, TLS on port 80), that family is reported and nothing about the later bytes is claimed, as initial-message inspection specifies; a stray byte before TLS, a PROXY header, noise on well-known ports and every overlap that rewrites retained bytes end evidence-limited; ports never establish identity. |
| F-ADV-1 | finding, reduced by a deliberate detection change in both engines (Lee, 2026-11-18) | CoAP's datagram profile accepted random datagrams without a hint: 40 of 20,000 seeded random datagrams (seed 7, lengths 4-512 cycled as in the suite; 0.200%), 4 of the suite's 2,000. (The earlier note's "about 0.17%" was measured on a different random set; on this one the rate was 0.200%.) Reproducer: the UDP payload `655085b84e0ec69b50164b0c53833c26` (code 2.16, unregistered). Lee approved tightening the profile in the Python reference and Go together: RFC 7252 codes (section 12.1.2), no reserved option number (12.2), option lengths and repeatability per table 4 plus Observe and Block-wise (PROTOCOLS.md, "CoAP message profile"). Now 6 of 20,000 (0.030%) and 1 of the suite's 2,000; the remainder conforms structurally, so F-ADV-1 stays listed in `NOISE_FINDINGS` at the lower rate. Regression tests: `test_expansion::test_coap_profile_follows_rfc7252_codes_and_option_formats` and `TestCoAPProfileFollowsRFC7252` (Go), both failing on the earlier code; 32 `datagram/coap-profile/*` parity cases (valid and invalid, unhinted and hinted). `cases.json` regenerated with the canonical generator: those 32 added, 3 malformed cases now name the precise rule in their reason (`datagram/022-ethernet-ip/mutated`, `datagram/hint-coap/text`, `datagram/coverage-ipfix/text`), nothing else changes; Python and Go match all 7,387. The behaviour diff against the parent tree lists CoAP verdicts only. The catalog profile sentence is unchanged (it is part of the content digest). |
| By design, not a finding | documented | A server name is an offer: a ClientHello naming a known service over an unrelated certificate is attributed to that service with basis `client_assertion` and activity `unobserved`, never authenticated identity (the certificate watch reads structure, not names). Lookalike and punycode names do not map. |

## Throughput under load (2026-11-18)

Lee, 2026-11-18: sustained throughput and memory with many concurrent flows, reported only (Culvert's benchgate
convention: timing is never a hard gate on shared runners). `make bench-load` (`go/internal/bench/load_test.go`,
build tag `loadbench`); not part of `go-check`.

| item | state | evidence |
|---|---|---|
| Method | implemented | N TCP flows are opened (SYN, SYN-ACK, ACK), then fed in four interleaved rounds (round k sends the k-th payload segment of every flow), so all N are in flight at once and none closes before `Finish`. The flows cycle through four synthetic kinds: an HTTP request in two segments, a TLS ClientHello with a server name in three, an SSH banner and KEXINIT in two, and 512 bytes of unidentifiable noise in four (inspected up to its byte budget). Packets are built decoded, so frame decoding is excluded; tracking, reassembly, dispatch, inspection, App-ID and the session record are included, through `analyzer.Process` with compact tracking as the live path uses it. Throughput is payload bytes and segments over the process CPU time (`getrusage`) of the feeding rounds. Memory is the Go heap in use after a collection, sampled after the flows open, after each round and after `Finish`. With 4 workers the flows are sharded over four analyzers on four goroutines (one analyzer is single-threaded, ADR 0001). |
| Results (one 4 vCPU Xeon 2.10 GHz container, go1.27.4) | measured | 10,000 flows: 17.5 MiB/s and 208k segments/s per core with one worker, 23.6 MiB/s and 279k segments/s per core with four (39 MiB/s on the wall clock); heap 33 MiB once the flows are open, 44 MiB peak (4.66 KB per concurrent flow), 2.1 MiB after `Finish`. 100,000 flows: 17.7 MiB/s and 210k segments/s per core with one worker, 19.6 MiB/s and 232k segments/s per core with four (37 MiB/s wall); heap 331 MiB open, 443 MiB peak (4.65 KB per flow), 16 MiB after `Finish` (map capacity). Memory grows linearly with concurrent flows and stays flat across rounds; throughput per core does not fall from 10k to 100k flows. Local CPU work on synthetic inputs, not SWG end-to-end latency. |
| Found by it, fixed | fixed (`b2e2280`) | The first run gave 2.6 MiB/s per core: the tracker built the per-family evidence table on every data segment although only non-compact messages print it (29% of the profile, most of the garbage). It is now built only where it is printed; no output changes. |
| Against the plan | noted | Plan §9 states 4 KiB retained per flow after the observation (gated by `bench-gate`: 0.6-1.4 KB per finished flow). A flow still in flight holds about 4.65 KB here (3.3 KB from the handshake alone, the rest reassembly and parser state); the plan states no in-flight budget. |

## Open after M7

- Default backend: Go wherever its binary is installed, on every runtime path (Lee's decisions of 2026-11-15
  and 2026-11-17; the launcher since `24e410e`); merge and deployment remain Lee's decision (AGENTS.md).
- M8 and M10 were done in this session (M8 and M10 tables above).
- Contracts C14 and C15 have Go evidence since 2026-11-17 (the live control plane above); C16 and C17 since
  2026-11-16. All four are `experimental`, not complete: their gates compare the Go service with the reference,
  and the Python reference stays the fallback.
- Reference finding, fixed in Python on 2026-11-15 (Lee's decision): `applications._PORT_TABLES` cached port
  tables by application name, so a host-named application, configured mapping or custom signature seen over
  two carriers in one process (YouTube over TLS, then over QUIC) took the first carrier's ports. The cache is
  keyed by the port list now; `test_appid.PortTablePerCarrierTests` fails without the fix. Go never had it.
- Signature documents whose description is a JSON object or list: read in Python's key order and rendered
  as its `str()` since 2026-11-18 (no longer refused).
- `--content-version` rollback in Go since 2026-11-18: `go/internal/content/history.json`
  (`migration/content_history.py`, checked by `make content-pack`) carries each earlier release's block and
  server-name catalog; `content.EmbeddedRelease` lays it over the embedded pack and validates it (all four
  releases recompute the reference's digests, `history_test.go`); `parity-analyze` and `parity-live` now draw a
  content version for about 15% of their runs, 0 differences. With an external `--content` pack the request
  is still declined (exit 64). The Python adapters' docstrings still name rollback among the requests Go
  declines; they are reference files and stay as they are.
- Still answered by the reference: signature patterns outside RE2 (Go's regular-expression engine has no
  backtracking constructs): inline flags, atomic groups, possessive repeats and a `$` before the end of the
  pattern. Repeat counts 1001..4096 (the signature rules' limit) are answered by Go since 2026-11-18: written as
  pieces of at most 1000 that denote the same language, which suffices because a signature asks only whether a
  match exists (`writeRepeat` in `go/internal/signatures/pattern.go`; `repeat_test.go` checks nine patterns at
  19 counts each against CPython's `re`).
- Reference finding, not changed (2026-11-18): a pattern with an inline `(?i)` compiles case-insensitively, but
  its literal anchor, the prefilter `Condition.evaluate` checks first, is compared case-sensitively unless the
  condition's own `case_insensitive` is set; so `(?i)hello world` never matches `HELLO WORLD`. Go refuses inline
  flags as not ported, so the reference answers such a signature and the behaviour is the same on both
  backends. Porting inline flags would have to keep this, together with CPython's flag errors and verbose mode.

## Open decisions and blockers

- Mac checkout patch set (reset, labels): needs a push or a description to reconcile with `c2b7cc3`.
- Codex round-3 result on `726007d`: pending (issue #2).
- Independent labelled corpus (D09): the dataset is decided (ISCX VPN-nonVPN 2016, internal research evaluation
  only; commercial use `UNVERIFIED`; non-commercial or academic-only datasets excluded). First measurement:
  `research/d09-iscx-vpn2016.md` on `claude/app-research` (engine `2fd9452`; 63 scorable captures, 41 correct,
  1 wrong, 14 unknown, 7 background). Findings tracked as post-merge, Go-only items PM-1..PM-7 in
  `migration/POST-MERGE-BACKLOG.md`: P1 UDP OpenVPN and CoAP over-permissiveness, P2 the TLS 1.2 ServerHello
  cipher policy (an identified TLS session must not become unknown over a posture table), P3 BitTorrent and SIP,
  P4 pre-RFC 9000 UDP/443 and one XMPP session.
- Merges (this branch, and the CI/CD lane's PR #30) wait for Codex's Sunday review; Lee then decides.
- Release thresholds: aligned with Culvert (above); allocations and retained bytes are gated, the p99 per flow
  with collection pauses (Lee, 2026-11-17) is reported.
- Dedicated migration PR: to be opened only when authorized in the working session (plan §1); the branch `claude/go-migration` exists and is pushed. Merge readiness and the draft description: `migration/MERGE-READINESS.md`, `migration/PR-DRAFT.md` (2026-11-18: 7 files conflict with `main`).
- `go/go.mod` requires `golang.org/x/crypto` (since `4111a70`) while main's Go jobs run with `GOPROXY=off`
  (`c58fe65`): vendored on Hermes's decision (`76e467a`); at merge time main's `go-check-minimum` needs
  `GOFLAGS=-mod=vendor` too, and CI a step for `make go-vendor-check` (MERGE-READINESS.md).

### SEC-SIG-2 and SEC-SIG-1: the compile and run cost of signature patterns (PRO-332, 2026-11-24)

**The findings** (security review PRO-51; measurements PRO-170). SEC-SIG-2: one 502-character pattern compiled to
450,569 RE2 instructions (about 156 MB, 245 ms), and nothing bounded a set, so a hostile document (4,096
signatures, 64 conditions each) could exhaust the engine at load time. SEC-SIG-1: an unidentified TCP direction
re-evaluates the unknown-payload signatures over its whole buffer after every update, so 1-byte updates cost
updates x buffer x program size, quadratic in `signature_bytes`.

**SEC-SIG-2 fix** (Go only, `go/internal/signatures/cost.go`). `estimateInsts` bounds the instruction count of the
program `regexp.Compile` builds, on the parsed tree, before the Go expression is written and before
`regexp.Compile` runs (no `syntax.Simplify` or `syntax.Compile`). It follows `regexp/syntax`: one instruction per
atom, an `InstAlt` per alternative, `x{n,m}` as m copies with m-n `InstAlt`s, `x{n,}` as n+1 copies and two more;
the arithmetic saturates and the walk stops just past the limit. Caps (Hermes, PRO-160): 10,000 per pattern and
100,000 per set, charged cumulatively in document order before each compile. Every reference rule is checked
first, so a pattern Python rejects keeps its error; a pattern or set over a cap is refused as not ported (the
reference answers), never a positive result. Before the caps were fixed, the estimate ran over every pattern in
the repository (the reference vectors, the repeat tests, the Python and Go test documents, `analyze_diff.py`,
`signatures-example.json`): 0 blocked; the largest is 8,202 (`begin.{0,3000}finish`-class repeats at 4096). The
content pack and the 7,462 parity cases carry no signature patterns.

**SEC-SIG-1 fix** (Go only, `go/internal/engine/inspector.go`, `signatures.Work`). Each direction has a work
budget in units of haystack bytes (every byte-valued condition) plus bytes x the instruction estimate (every
pattern search), charged before the work runs. The allowance is `max(MaxSignatureWork = 2^26,
2 x buffer x the set's units per byte)`: never less than two complete evaluations of the set over a full buffer,
so a flow that arrives in one or two segments is evaluated exactly as by the reference, and the bound does not
depend on how the peer splits its bytes. An exhausted budget ends the direction as `budget_exhausted` ("Signature
work budget exhausted") and no later byte is evaluated; it is never a match. The reference has no such bound:
this is a Go-only divergence for flows past the allowance, pending approval (Hermes/Lee, PRO-332).

| item | state | evidence |
|---|---|---|
| Upper bound | `TestEstimateBoundsTheCompiledProgram`, `FuzzEstimateBoundsProgram` (in `GO_FUZZ_SMOKE`) | the estimate is >= `len(prog.Inst)` of the real compile for every corpus pattern, with and without IGNORECASE; 257,877 fuzz executions, no counterexample |
| Caps | `TestPatternInstructionCap`, `TestSetInstructionCap`, `TestHostileDocumentLoadIsBounded` | the PRO-170 shape is refused; 12 patterns of 8,202 load, the 13th is refused; reference rule errors win over the cap |
| Flow cost | `TestUnknownPayloadSignatureWorkIsBounded`, `TestExhaustedSignatureWorkNeverMatches`, `TestSignatureWorkBelowTheBudgetKeepsTheReferenceVerdict`, `TestWorkStopsBeforeTheSearchAndNeverMatches` | PRO-170 1-byte `.{0,4096}` flow: `budget_exhausted` after 80 updates within its allowance; early matches, full single segments and the test set's 1-byte flow (2.0 M units) keep the reference verdict |
| Parity | divergence pending approval, 0 case changes | no committed case carries a signature set (gate numbers in the lane brief and the PR) |

Load times (4 vCPU Xeon 2.3 GHz; `BenchmarkHostileDocumentLoad` in `go/internal/signatures`, 10 iterations each):

| hostile document | before | after |
|---|---|---|
| PRO-170 shape, 512 x 40 patterns of ~438,000 instructions (4 MiB) | unbounded: ~245 ms and ~156 MB per pattern, x 20,480 | 28 ms, refused at the first pattern (JSON decoding of 4 MiB dominates) |
| 12 patterns of 8,202 (the set cap) | not measured (same compile work) | 20 ms, loads (600 patterns of 164: 26 ms) |
| 13+ patterns of 8,202 | grows with the count | 21 ms, refused at the 13th |
| 11,110 patterns of 9 instructions (the cheapest raw pattern) | ~124 ms (with the caps, before the faster expression writer) | 98 ms, loads: per-pattern fixed cost, not instructions (above the 50 ms target; see the lane brief) |

Flow cost of one direction (1-byte updates unless noted; `MaxUpdates` 1,000,000):

| flow | before | after |
|---|---|---|
| 1 PRO-170 signature, `signature_bytes` 2000 | 43.4 s (1,990 updates, measured) | 13 ms, `budget_exhausted` at 6.6e7 units |
| 12 PRO-170 signatures (the set cap), 2000 | ~2 min (projected: 2.0e11 units at the measured 0.65 ns per unit) | 54 ms, `budget_exhausted` at 3.9e8 units |
| 12 signatures, one 2000-byte segment | ~0.6 s | ~0.6 s, `unknown` (unchanged: within two full evaluations) |
| 12 signatures, `signature_bytes` 65536 (configured maximum) | ~38 h (projected, 2.1e14 units) | 11-34 s, `budget_exhausted` at 1.3e10 units (two full evaluations; see the lane brief) |
