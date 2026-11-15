# Protocol Detector v0.65 — Architecture and Security Review

Date: November 6, 2026. Audience: Lee and Claude, implementing the next changes.

## Authoritative implementation baseline — updated November 6, 2026

**Use v0.65.0 for new work. Start from `claude/v065-presentation`, which adds the application to the existing v0.65 engine history.**

- Repository: `leenadav/protocol-detector` (currently public; no visibility change was made).
- Upstream engine branch: `claude/engine-next`.
- Engine commit: `08274cbb5cfc8eab0abdef9a3bace027e8ef943b`.
- Engine tree: `7080bebcf29fece6920f7df1dff9b041030fc547`.
- Publication branch: `claude/v065-presentation`; retrieve its current head before editing.
- The repository root and `presentation/engine/` contain identical v0.65 engine files. `presentation/SOURCE.json` identifies the upstream engine, not the whole-application commit.
- The original local running application was not overwritten during publication. The prepared v0.65 checkout is `/Users/lee/Desktop/protocol-v059-publication` (its directory name is historical).

### Divergent v0.59 histories: do not silently drop work

The Mac's old v0.59 commit `993457ad4ee536d11c75c3946859d1e699cbd0ac` added LIFX/Tuya/TP-Link and multicast DNS repairs. The upstream v0.59 commit `a37bcd3` instead added SMB transport protection. v0.60–v0.65 descend from the latter. They are not one linear series containing the Mac additions.

The Mac source was published on `claude/v059-unknowns-catalog-keylog` at `190e01121c12551b3e62b7f1d9d6055663101075`, with **exactly the same tree** (`145de19c392e7898dcbd61436ef9827a6997c0d8`) as the original local commit. GitHub connector publication changed commit metadata, so the SHA differs. Do not require original commit `993457a` to be fetchable from GitHub.

The unchanged historical application is on `claude/v059-presentation` at `7e50aeda5076222e4dbb75511cf9f8de8fdf07c2`. That branch preserves the stale version test for historical reproduction. New work must use v0.65, while retaining these source branches. Port the smart-home/DNS additions in a separate reviewed change if they are to be combined; reconcile colliding test, benchmark and version filenames. The v0.65 presentation snapshot deliberately matches upstream v0.65 exactly and does not claim those additions are present.

v0.60–v0.65 were already published on `claude/engine-next`; their history is preserved as the parent history of the presentation branch. No changes were pushed to `main`, `claude/appid-engine`, or `claude/engine-next`.

Paths below are relative to `presentation/` unless stated otherwise. `engine/` paths also exist at the repository root. Original finding line numbers are navigation hints, not stable patch locations; resolve symbols in your current head. Preserve any commits newer than this baseline and revalidate affected findings.

## Executive recommendation

Preserve the bounded protocol-classification core. Substantially refactor the runtime and integration around it. Do not start with a complete rewrite, microservices, a native-language migration or another large protocol expansion.

The main weaknesses are duplicated connection ownership, repeated processing of previously captured data, separate representations of outer and decrypted classifications, and a release/CI boundary that does not cover the complete application being demonstrated.

The capture/decryption frontend is a useful POC, but its snapshot-based decryption is not the right foundation for a low-latency SWG. Increasing its limits would amplify the problem rather than solve it. The frontend/decryption code previously added by Codex is part of the architectural debt and must be reviewed as critically as the engine.

This assessment distinguishes three things:

1. Concrete implementation facts or observed failures.
2. Architectural risks inferred from those facts.
3. Future product capabilities that are intentionally outside the present profile.

A missing unsupported TLS feature is not automatically a correctness bug. A passing test suite is not evidence of production readiness.

## Review scope and verification

Reviewed the module layout and contracts, dispatch/registration, Inspector, App-ID, signatures, TCP/UDP ownership, capture adapters, TLS POC, HTTP management server, worker lifecycle, frontend state, packaging, tests and CI definitions. This is a high-level architecture review, not a line-by-line audit of every decoder or a penetration test.

Verification for the v0.65 publication:

- Upstream root engine: **655 tests passed**, 17.292 seconds, Python 3.12.14; coverage matrix check passed.
- Presentation suite: **31 tests passed** after updating the source snapshot and replacing the stale version literal with a manifest-to-pyproject consistency assertion. The suite includes a new synthetic end-to-end adapter check for YouTube over HTTP and ChatGPT over TLS SNI, including preserved carrier and unauthenticated-name provenance.
- `SOURCE.json` blob checks cover all **340 engine files**. The root engine and the embedded snapshot match upstream v0.65; no decoder code was modified during publication.
- Five unchanged LiveDecoder snapshots still caused **five decrypt_streams calls**, using a generated in-memory OpenSSL fixture. A02 remains reproducible on v0.65.
- The original v0.59 review found 635 passing core tests and one stale-version presentation failure. That failure remains reproducible on the historical v0.59 presentation branch, but has been corrected on the v0.65 publication branch; do not claim it is still a failing v0.65 test.
- The v0.65 delta was inspected, including hostname App-ID attribution. The core reassembly, Inspector, signature evaluator and live capture modules referenced by the original architecture review are unchanged between those engine snapshots. Most broader findings below carry forward from that review; this publication was not a new exhaustive audit of every v0.65 decoder.
- No user traffic or real key logs were read. HTTP tests used ephemeral loopback and TLS tests used synthetic fixtures. Sandbox restrictions initially prevented loopback binding; the authorized rerun passed.
- No full make check, CodeQL, extended fuzzing, production load test or browser automation was completed for this publication. Passing unit/integration tests is not a full-CI or security approval.

The original SOURCE-HASHES.json and VERIFICATION.md are historical v0.59 review evidence, not v0.65 checksums. Use the new engine manifest and publication report for v0.65 provenance.

## Preserve these strengths

- The core has no network I/O and uses per-direction Inspectors with immutable configuration and explicit inspection budgets.
- Prefix dispatch selects a candidate instead of trying every protocol parser on every packet.
- Reassembly detects conflicting overlaps and invalidates affected classifications; identical retransmissions do not feed the inspector twice.
- Evidence carries provenance and strength. Offered ALPN and SNI are not automatically promoted to authenticated application identity.
- The TLS POC uses cryptography's AEAD implementations rather than new handwritten AES for record decryption.
- The engine already contains substantial synthetic, fragmentation, negative, schema, fuzz and security-requirement testing.
- The local management server uses loopback, Host/Origin checks, bounded input, and argv-based subprocess invocation. These controls should be retained and tested.

## Current processing paths

```text
Offline PCAP -> Analyzer -> SessionManager/Stream -> Inspector -> App-ID
Live tcpdump -> CaptureMonitor -> Analyzer -> the same core path

Live tcpdump + keys -> LiveDecoder --+-> CaptureMonitor/Analyzer
                                     +-> accumulated capture in memory
                                         -> analyze_capture on each snapshot
                                             -> another Stream/TLS/Inspector path
                                                 -> rewritten Observation -> App-ID

LiveManager -> separate events/sessions/decryption snapshots -> HTTP -> global JS state
```

The two branches in the live decryption path do not share one connection state machine. A connection can consequently appear as `ssl` in the session summary and `webdav` in the decrypted log. This is an integration/model issue, not merely a table-layout problem.

## Prioritized findings and implementation requirements

P1 means address before significant scale or feature expansion. P2 means address during the next stabilization stages. These priorities are engineering priorities, not CVSS vulnerability scores.

### A01 — P1: Establish one v0.65 source of truth and package the whole product

**Evidence:** `SOURCE.json`, `engine/pyproject.toml`, the duplicate engine directories and `tests/test_showcase.py` (the stale version assertion has now been corrected). The engine wheel packages only `protocol_engine`; capture scripts and the frontend sit outside that package. The historical local parent checkout left `presentation/` untracked. Publication now versions it, but does not integrate its packaging or CI coverage. Workflows nested under `presentation/engine/.github/` are not automatically workflows of the parent repository.

**Change:** Start from the v0.65 presentation branch. Bring the reviewed application additions into that source tree with explicit ownership and packaging. Keep historical snapshots outside active source. Define core and optional adapters/UI installation; cryptography can remain an optional decryption extra, preserving dependency-free core installation. Replace `sys.path.insert` and ambiguous top-level imports such as `sessions` and `packets` with package imports.

**Acceptance:** A clean clone builds and installs an artifact that runs replay, frontend and decryption without a Desktop copy or Codex runtime. CI covers the whole product. Engine, adapter, frontend and schema versions are reported together. Preserve the new manifest/source consistency test; package and test all components rather than treating that narrow fix as completion of A01.

### A02 — P1: Replace snapshot reprocessing with incremental decryption

**Evidence:** `poc_decryption/live.py:68` copies the accumulated bytes and calls `analyze_capture` again. `poc_decryption/capture.py:6` rebuilds packet decoding, flows, streams and inspectors. `KeyLog.read` seeks to zero and rereads the file. Five unchanged snapshots caused five decryption calls in the review reproduction.

**Impact:** Work increases with already-processed history. For a growing stream with periodic snapshots, cumulative prefix processing grows quadratically with the number of snapshots until the configured caps stop it. The 2 MiB cap limits exposure but does not make the implementation incremental. Snapshot processing also delays draining the capture pipe.

**Change:** Maintain a `TlsConnection` with directional record framers, sequence/epoch/key state and authenticated plaintext deltas. Make the key provider append-oriented, retaining only a partial final line and indexed secrets. Late keys should wake only dependent connections within a bounded waiting budget. Status/snapshot reads must not perform cryptography or parsing again.

**Acceptance:** Repeated status calls with unchanged input produce zero additional parser/decrypt calls. One new record is decrypted once. Test late keys, split records, key updates, log truncation/rotation and long-lived streams. Measure CPU against new bytes, not historical bytes.

### A03 — P1: Separate reassembly from inspection and give each connection one owner

**Evidence:** `engine/sessions.py:27` allocates the stream buffers, constructs an Inspector and feeds it. The decryption adapter uses that same Stream and then constructs additional Inspectors. The live POC runs CaptureMonitor alongside its independent capture-analysis path.

**Change:** Extract a transport reassembler producing ordered `StreamDelta` events without application knowledge. A single connection owner handles lifecycle and routes deltas to protocol inspection or TLS decoding. Retain outer handshake evidence separately from decrypted inner evidence.

**Acceptance:** Offline and live adapters produce identical deltas for identical packet sequences. Deliver each contiguous byte once. Identical retransmissions add no inspection work; conflicting overlap invalidates all dependent results. Remove parallel independent flow tables for the same capture within a worker.

### A04 — P1: Unify lifecycle across normal and decrypted capture

**Evidence:** `engine/live_capture.py` explicitly calls `analyzer.expire(now)` and `analyzer.finish(...)`. `poc_decryption/live.py` calls accept/summary without the corresponding expire/finish calls. The offline decryption flow dictionary persists for the capture and rejects tuple reuse.

**Risk:** A connection without FIN can miss final session emission when decrypted capture stops; idle behavior differs between capture modes. This is a confirmed control-flow difference, not a newly executed packet-level reproduction in this review.

**Change:** Introduce a shared `SessionCoordinator` with injected time and explicit tick/end/gap operations. Identity includes `capture_id` and connection generation, not just transport and endpoints. Define FIN, half-close, RST, idle timeout, eviction, tuple reuse and operator stop semantics.

**Acceptance:** A no-FIN connection is finalized once on capture end. Idle expiration happens without incoming packets. Reused tuples create new generations. Exercise the same lifecycle fixtures through every adapter.

### A05 — P1: Represent layered App-ID instead of rewriting observations to obtain a verdict

**Evidence:** `engine/protocol_engine/engine.py:440` offers `feed_decrypted` and layer merging. However, `poc_decryption/capture.py` strips encryption/application and selected evidence using `replace` before calling `session_verdict`. The frontend merges decryption rows and classification events independently.

**Change:** Define transport, outer protocol, encryption, inner protocol, application and identity basis as separate fields, with decryption status and capture quality. A common reducer derives an effective verdict without erasing provenance or outer-layer knowledge.

**Acceptance:** For one session, logs, session table, charts, details and export agree on `TLS -> HTTP -> WebDAV`. An authentication failure invalidates dependent inner evidence while retaining independently established TLS evidence. Record authentication is not represented as certificate or product identity verification.

### A06 — P1: Define versioned event, revision and retraction contracts

**Evidence:** The engine has schemas, but `LiveManager.ingest:93` accepts additional POC dictionaries outside that shared contract. Events, sessions and decrypted snapshots are separate collections. Frontend identities include endpoint-derived strings and local sequence numbers. Capture gaps clear sessions while historical events remain.

**Change:** Add an event envelope containing schema version, capture/session/generation/layer identifiers, revision, kind, source, quality, reason code and budget state. Retractions identify dependent observations. Use a bounded event sequence with cursors and a reset-required response when consumers fall behind; distinguish snapshots from new events.

**Acceptance:** Duplicate polling does not duplicate records. Older revisions cannot overwrite newer state. Loss/conflict cannot leave dependent inner results displayed as valid. Event replay reconstructs the same state as live processing.

### A07 — P1: Add aggregate resource and scheduling budgets

**Evidence:** Each Stream allocates both data and presence arrays at its configured limit. At 256 KiB per direction, a bidirectional flow can allocate about 1 MiB for those arrays alone; 64 such flows imply a theoretical 64 MiB before TLS/plaintext/Inspector overhead. This is an allocation calculation, not measured RSS. Capture copies and the parallel pipeline add overhead. Unlike offline workers, the live decryption entry point does not set the same CPU limit.

**Change:** Introduce budgets at run, connection, layer and work-quantum levels: bytes, connections, gaps, outstanding records, pending keys, depth and output. Make eviction/rejection explicit. Yield between bounded units of work so one connection cannot monopolize capture draining. A supervisor timeout is not a parser CPU budget. Apply process memory isolation appropriate to the host OS rather than assuming identical RLIMIT behavior everywhere.

**Acceptance:** SYN floods, sparse gaps, large streams and missing-key loads remain within measured aggregate limits. Rejection does not silently discard unrelated results. Emit exhaustion reasons and counters. Do not raise caps before these tests pass.

### A08 — P1: Keep the management plane responsive during work

**Evidence:** `server.py:184` uses a synchronous HTTPServer. Handlers invoke subprocess jobs with a 25-second timeout; socket read timeout is 15 seconds. `LiveManager.snapshot:169` also renews a 30-second lease.

**Risk:** File analysis or a slow request can delay status/stop operations. Merely reading status changes lifecycle. This coupling matters even for a local POC; no remote exploitation claim is required.

**Change:** Introduce bounded asynchronous jobs and admission control. Keep control requests independent from worker execution. Stop is idempotent and prioritized. Use explicit run-scoped heartbeat ownership, side-effect-free GET status, and a server-enforced maximum lifetime. Do not replace the problem with unlimited request threads.

**Acceptance:** Slow uploads and analysis do not starve status/stop beyond an agreed budget. Concurrent starts cannot create duplicate runs. Disconnect and shutdown do not orphan workers; incomplete outcomes remain explicit.

### A09 — P1: Make decryption an explicit trust boundary

**Evidence:** The POC uses established AEAD primitives but owns TLS framing, epochs, Finished handling and KeyUpdate. It intentionally does not verify the Finished transcript or certificate trust chain. Its valid claim is record authentication using supplied secrets.

**Change:** Give decryption a narrow interface that releases authenticated plaintext deltas with provenance and epoch. Use typed states/errors: awaiting keys, awaiting bytes, unsupported profile, authentication failure, gap, exhausted budget and complete. Replace the live catch-all operational error with sanitized, actionable error codes. A future host-provided plaintext adapter can implement the same interface without implementing proxy integration now.

**Acceptance:** Wrong keys, corrupt tags, missing records, invalid epochs, alerts/close-notify and malformed updates cannot publish new authenticated application evidence. Use independent fixtures for every supported suite, not just a shared encrypt/decrypt helper. Never label AEAD verification as peer trust. Unsupported HRR/0-RTT/CBC remains a documented scope boundary until explicitly implemented.

### A10 — P1: Specify key handling, privilege separation and local API security

**Evidence:** KeyLog already uses O_NOFOLLOW, regular-file/ownership checks and size limits. Secrets and plaintext still live in Python memory and are copied through worker input. Host/Origin checks and the loopback token protect some browser-origin scenarios; they do not authenticate against a malicious process already running as the same user.

**Change:** Make one key provider responsible for secret lifetime, expiry and reference release. Never emit raw secrets/plaintext in JSON, exceptions, telemetry or crash artifacts. Authorize a path/descriptor at start and define rotation/truncation behavior. Keep capture privilege in the minimal helper; parsers and HTTP stay unprivileged. Do not run the application with sudo. If later exposed as a multi-user service, introduce actual authentication/authorization rather than reusing the localhost token model.

**Acceptance:** Canary secrets and plaintext never appear in output/error/report channels. Test Host/Origin/token, symlinks, FIFOs/devices, rotation and permissions. Permission failures do not trigger automatic privilege changes. Do not promise reliable Python memory zeroization.

### A11 — P2: Scale signature evaluation with indexes and measured budgets

**Evidence:** `engine/protocol_engine/signatures.py:292` indexes by family; `match:344` linearly evaluates that family's signatures. `get:351` scans groups again. There is a 4,096-signature cap, regex restrictions and a literal prefilter. This review does not claim a proven ReDoS exploit.

**Change:** Add a name index, compilation-time context/anchor indexes and bounded candidate evaluation. Exact hostname/path matches should use exact lookup. Consider multi-pattern anchor matching only when measurements justify it. Preserve priority and first-match semantics. Load immutable, versioned rule sets and pin their version per session.

**Acceptance:** Benchmark 100/1,000/4,096 signatures, including all-in-one-family and prefilter-pass/nonmatch workloads. Report compilation and runtime costs separately, p99 and memory. Regex-engine changes require equivalence and adversarial tests.

### A12 — P2: Consolidate protocol registration contracts without generic hot-path scans

**Evidence:** registry.py, dispatch.py, datagram.py, catalog.py, applications.py and fixtures each describe parts of the same capability. The Inspector combines dispatch, continuation, unknown signatures, shifts, replay and decryption. Some parser modules contain several families.

**Change:** Define internal protocol descriptors for factory, transport, bounded candidate selection, limits, evidence schema, profile scope and direction support. Validate inventory and references at build time. Keep protocol definitions distinct from the application catalog. Split Inspector responsibilities along real lifecycle boundaries rather than mechanically splitting files. Do not load arbitrary plugin code from JSON configuration.

**Acceptance:** A new protocol has one explicit capability definition and standard test template. Duplicate definitions, missing references and ambiguous candidates fail checks or preserve explicit unknown/correlated outcomes. No fallback loops across all decoders.

### A13 — P2: Distinguish protocol families, application identity and transactions

**Evidence:** App-ID refines HTTP into labels such as WebDAV/gRPC from methods and headers. v0.65 additionally maps selected TLS/QUIC SNI and HTTP Host suffixes to application labels through `host_apps.py`; `appid.py` preserves the generic carrier and explicitly calls this a client assertion. The built-in catalog excludes outer ECH attribution and selected shared-hosting suffixes, but these checks do not authenticate a service or user. HTTP/2 inspection is bounded initial-message inspection rather than unlimited transaction analysis. RESP is a protocol label, not proof of a particular Redis product deployment.

**Change:** Distinguish protocol, application family, configured attribution and verified product identity in API/UI. For future multiplexed application detection, model transaction/HTTP2 stream identity with independent budgets instead of assigning every transaction the first connection label. Do not silently convert the initial-message Inspector into a full proxy parser.

**Acceptance:** ALPN/SNI/fingerprints remain attributed claims or derived signals. Preserve v0.65 hostname attribution provenance, configured-rule precedence, ECH exclusion and label-boundary tests. Known-name mappings must not become trusted identity or automatic policy approval; client-controlled Host/SNI can be spoofed. Different transaction evidence does not get flattened into one unjustified identity. Supported scope and ambiguity remain visible.

### A14 — P2: Replace global frontend state with a shared result model

**Evidence:** web/app.js, live.js and decrypt.js share globals, build HTML strings and synthesize demo session views independently. app.js has very long compressed lines; line count understates complexity. Escaping exists, so innerHTML alone is not proof of XSS.

**Change:** Introduce modules for API access, store/reducer, selectors and views. Vanilla JS is sufficient; React is not an architectural requirement. Track explicit demo/offline/live mode and run identity; reject stale responses. Never store keys in localStorage. Render backend result contracts instead of inventing verdict semantics in the frontend.

**Acceptance:** Late demo responses cannot overwrite a newer live run. Filters/navigation do not disturb capture. Refresh restores current run state. Row details remain stable during updates. Counts, filters and exports use the same store. UI tests cover hostile evidence strings and retractions.

### A15 — P1/P2: Measure and test the boundaries between components

**Evidence:** Core metrics and capture counters exist, but stage-level work and end-to-end classification latency do not share one model. The live POC error combines permission, format, loss and resource failures. Synthetic demonstrations are not real-world accuracy or SWG latency measurements.

**Change:** Track new/replayed/decrypted bytes, pending keys, candidate checks, auth failures, gaps, event loss, queue depth and retained bytes. Add stage and time-to-verdict histograms, sampled tracing without payloads, and an authorized labeled corpus. Report false positives/negatives by profile and input class, not a demonstration identification percentage.

**Acceptance:** Record a baseline before refactoring. Compare old/new behavior on the same corpus and explain intentional differences. Include overload/soak, late keys, disconnect, slow consumers and worker crashes. Test core, adapters, installed artifacts and frontend in canonical CI. Agree on hardware/workload/SLOs before claiming production capacity.

### A16 — P2: Identify and secure the complete build

**Evidence:** `launch.py:13` identifies a compatible running server using only the engine commit. Different frontend/decryption builds sharing that commit can be treated as the same installation. The decryption requirement pins a version but not package hashes. Engine CI controls do not automatically cover untracked application additions.

**Change:** Build manifests identify engine, adapters, schemas, UI, rules and dependencies. Health reports a complete build digest and instance identity. Include decryption extras in the SBOM, dependency review, secret scanning and artifact provenance. Install independently from the Codex environment.

**Acceptance:** The launcher does not reuse a mismatched application build. Clean builds produce verifiable artifacts. CI catches accidentally committed key logs. Preserve pinned actions and least-privilege tokens. Do not allege a dependency vulnerability without a specific advisory.

## Proposed architecture

```text
CaptureAdapter / FileReplayAdapter / FutureHostStreamAdapter
                         |
                 SessionCoordinator
          identity + lifecycle + shared budgets
                         |
                Reassembly / StreamDelta
                         |
                 Bounded Layer Stack
              +----------+-----------+
      Protocol Inspector       TLS Record Decoder <- KeyProvider
                                     |
                              authenticated delta
                                     |
                               Inner Inspector
              +----------+-----------+
                         |
                Evidence / Observations
                         |
             Application Verdict Reducer
                         |
             Versioned Events + Session View
                    +----+----+
             Policy consumer   API/UI/report consumers
```

Keep the core as a library without I/O or locks. One worker owns a session and both directions. If measurements later justify scaling, shard by flow; first measure Python scheduling, serialization and memory costs. Logical control/data separation does not require distributed services. A modular monolith with a capture helper and isolated worker is a reasonable next architecture.

Suggested layout, not mandatory names:

```text
src/protocol_detector/
  core/          contracts, observations, dispatch, parser lifecycle
  protocols/     validated profiles and registration
  applications/  catalog, signatures, layered verdicts
  sessions/      identity, lifecycle, reassembly
  decryption/    framing, TLS state, key-provider interfaces
  runtime/       budgets, scheduling, bounded events, supervisors
  adapters/      pcap, tcpdump, keylog and other external I/O
  api/           bounded jobs and versioned management API
web/             API client, store, selectors, views
tests/          unit, contracts, replay, adversarial, UI, packaging
benchmarks/      stable workloads and comparison tools
docs/adr/        decisions, constraints and evidence
```

These directories do not each need a separate distribution package. Enforce dependency direction: core must not import adapters/UI/runtime, protocols must not import capture, serializers must not own classification logic.

## Implementation sequence for Claude

| Stage | Deliverable | Dependencies | Exit criteria |
|---|---|---|---|
| 0 | Confirm canonical v0.65 head and divergent v0.59 work, inventory, baseline and reproduction tests | None | Record all versions, dirty changes and intentional differences |
| 1 | Package and CI the complete v0.65 application | 0 | Clean clone and installed artifact work without external source copies |
| 2 | Schemas, session generation, errors and event reducer | 1 | Ordering/retraction/replay tests; compatibility adapter for old API |
| 3 | Shared lifecycle and reassembly ownership | 2 | Offline/live/decrypt parity; exactly-once expiration/finalization |
| 4 | Incremental TLS and key log with aggregate budgets | 3 | No parsing on unchanged status reads; late-key and failure tests |
| 5 | Layered App-ID and one session view | 2–4 | Logs, tables, charts and export agree |
| 6 | Responsive jobs/control API and frontend store | 2,5 | Bounded concurrency, stop responsiveness, race/disconnect tests |
| 7 | Signature/registry improvements and observability | 4–6 | Measured candidate costs and explicit performance/semantic deltas |
| 8 | Security, soak and release gate | Security work throughout; final gate after 7 | Verified artifact, threat model, corpus results and documented limits |

Use small reviewable PRs. Do not mix a broad refactor, new protocols and verdict semantic changes in one patch. First move one vertical slice, such as TLS -> HTTP -> WebDAV, through the new contracts while preserving an old-API adapter. Then migrate other paths. Keep rollback possible at each stage.

## Ready-to-use implementation instructions

> Work on `claude/v065-presentation`, based on upstream v0.65 engine commit 08274cbb5cfc8eab0abdef9a3bace027e8ef943b. Preserve newer changes and the separately published v0.59 smart-home work; do not assume the latter is already included in v0.65. The old local v0.21 root is not your implementation baseline. Revalidate these findings against your actual head. Start at stage 0 and then establish the canonical packaged application. Do not implement all stages in one PR. Preserve Lee's captures and unrelated edits. Each PR must state changed contracts, tests, measurements and remaining profile limits. Remain Python 3.9-compatible and IPv4-only. Do not add proxy integration, a native rewrite or unrelated protocol expansion during this refactor. Use only synthetic local traffic for capture tests. Preserve fragmentation, overlap, invalidation and hint-provenance semantics. Never emit raw keys or plaintext through telemetry. Test the installed artifact and frontend as well as the core. Do not claim production readiness without deployment-specific SLOs, corpus and load/security evidence. Do not merge, deploy or change permissions without the relevant authorization.

## Industry reference points

This review does not claim access to the internal architectures of proprietary firewall/SWG vendors. Recommendations use observable design principles and primary documentation:

- [Zeek architecture](https://docs.zeek.org/en/current/about/architecture.html): packet/event processing separated from semantic interpretation and policy. Relevant to keeping observations independent of product decisions.
- [Suricata configuration and threading](https://docs.suricata.io/en/latest/configuration/suricata-yaml.html): explicit worker/resource configuration. Relevant to ownership and measured resource management, not copying a thread count into Python.
- [TLS 1.3 RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html), [TLS 1.2 RFC 5246](https://www.rfc-editor.org/rfc/rfc5246.html), [AES-GCM RFC 5288](https://www.rfc-editor.org/rfc/rfc5288.html): reference contracts for framing, epochs and record authentication; they do not justify claiming certificate trust when it is not checked.

A high engineering standard here means explicit state ownership, bounded incremental work, tested contracts, retractable evidence and reproducible releases. Protocol count alone does not establish those properties.
