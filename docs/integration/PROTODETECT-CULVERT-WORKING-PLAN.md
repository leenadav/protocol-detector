# Protocol Detector ↔ Culvert — integration working plan

Version 1.1 · 2026-11-14 · Owner: Lee · Status: agreed direction; detector preparation starting on `claude/culvert-integration-prep` (base `f239c65`)

This is the **single working document** for the integration. It merges:
- Claude's review of Codex's integration plan;
- the lab validation addendum (Lee and Codex);
- the corrections agreed afterwards by Claude, Codex and Lee.

Where this document and Appendix A (the original review, kept as history) disagree, this document wins. Appendix B lists every correction.

**Authority.** All Culvert work stays in local branches on the lab machine. This document authorizes no upstream push, pull request, merge, release or deployment to KidCarmi/Culvert. Detector work follows the repository's existing review loop (`AGENTS.md`).

---

## 1. Decision and scope

The direction:
- an in-process Go library behind a narrow Culvert adapter;
- observe mode first;
- Culvert owns every transport, TLS, authentication and policy decision;
- no PCAP capture, packet Analyzer or TCP reassembly in the proxy path;
- enforcement only later, as a restriction attached to the existing policy decision, in a separately gated experiment.

**First milestone:** Culvert forwards the same traffic with observation off and on; the detector produces useful, correctly scoped results; connection lifecycle and resource use stay bounded. Blocking traffic is not part of it.

Start the lab now, in parallel with the remaining Go migration. Do not wait for every protocol family, the GUI, capture adapters or TLS decryption. The next step is deliberately narrow:
1. run unmodified Culvert;
2. prove the lab scenarios repeat;
3. prepare the public library in parallel.

Only once the baseline repeats does anyone touch the forwarding path.

## 2. Baseline and evidence

| Item | Value | Status |
|---|---|---|
| Culvert | `main` `52eb9d1e4482adc9773afc4db77109acad617625` | Source read; no tests run |
| Detector (Go) | `claude/go-migration` `a2cf4e8b1a557da328f98cb62780bb522f7a1fe7` | One commit after the `a4d39c3` that Codex's plan cited; re-pin per campaign |
| Detector (Python reference) | `main` `201a552` | Read only |
| **Integration-prep branch** | `claude/culvert-integration-prep`, created 2026-11-14 from `claude/go-migration` HEAD **`f239c65572e2217554e93c70a20ed5b3b319dc37`** | Base for all detector preparation work in this plan |

Changes between `a2cf4e8` and the base `f239c65`, all made on `claude/go-migration` in response to the independent review of 2026-11-14:
- **R1:** Analyzer retention is fixed, so work item #20 is done.
- **R3:** `buffer.Account` now counts allocated capacity, but still has no parser callers.
- **R4:** `Config.Validate` uses an ordered table of ranges with upper bounds, so its error is now deterministic. Of #14, the deterministic error and the upper bounds are done; wiring the account and adding a proxy profile remain.
- **R5:** the hint set is now derived from the factory.
- Host-side shift correlation (LDAP StartTLS and HTTP CONNECT) was added.

Recorded runs. These are Claude's checks; neither the CI nor the lab has reproduced them.

| Check | Command | Result |
|---|---|---|
| Build and tests at the pinned toolchain | in `go/` at `a2cf4e8`: `go build ./... && go vet ./... && go test ./...` (go1.27.4) | Passed |
| Benchmarks | `go test -bench` | Nothing ran: no `Benchmark*` functions exist |
| Go minimum | a scratch copy of `go/` at `a2cf4e8` with `go.mod` edited to `go 1.27.0`: `GOTOOLCHAIN=go1.27.0 go vet ./... && GOTOOLCHAIN=go1.27.0 go test ./...` | `vet` and the tests passed. The race detector was not run. This supports lowering the `go` line; it does not prove every compatibility property. Repeat it, with `-race`, in the change that edits `go.mod`. |

Nothing has been run in Culvert, and no detector-in-Culvert test exists yet.

## 3. Constraints already set by Culvert

Any design must satisfy these. Each was checked in the Culvert source at `52eb9d1`.

| Constraint | Source | What it requires here |
|---|---|---|
| Package boundaries | ADR-0002, ADR-0003 | `internal/*` never imports `package main`; logging goes through the `obs` facade; dependencies are injected |
| Parse ownership | ADR-0042 (`internal/alpnpeek`) | Main owns the peek window and the fallback; a package owns only the parse. Culvert already parses the ClientHello's ALPN |
| Observability | ADR-0011, `internal/decryptobs` | Observation never changes the traffic decision. Off means a byte-identical record (`nil` and `omitempty`). Enum-only labels, with host/SNI as record fields. HMAC pseudonymization at `persistLogEntry`. No new hot-path lock. ≤ 1 allocation per session for the `dec` block |
| One evaluator | ADR-0026 | Any policy-language change goes through `evalAccessRules` |
| Learning is advisory | ADR-0025 | Shadow mode never enforces |
| Drain and shutdown | ADR-0037, `proxy_tunnel_drain.go` | Observed tunnels stay in the existing drain classes |
| Config surfaces | `config_surfaces.go` and its parity tests | A new setting is registered with an export, snapshot, API and GUI decision |
| Dependency gates | `pr-deep-gate.yml` (go-licenses), govulncheck, `go mod tidy -diff`, SBOM | The detector module must pass all of them unchanged |
| Toolchain | Culvert `go.mod` (`go 1.27.0`, `toolchain go1.27.4`, GODEBUG pins) | A dependency must not raise Culvert's `go` line |

Facts the design relies on:

- **Splice fast path.** `idleCopyCounted` (`proxy_tunnel.go:267`) calls `io.Copy`, which delegates to `ReaderFrom`/splice for TCP↔TCP. It sets **only read deadlines** (`:283`, every `armInterval` = 30 minutes). Culvert sets no write deadlines.
- **Idle clock.** The shared activity stamp updates when `io.Copy` returns with `n > 0`. Today that happens only at a read-deadline wake-up or at the end of the copy, not per chunk.
- **Panics.** Culvert already recovers in its relay goroutines (`proxy_tunnel.go:322`, `:927`, `:1163`; `proxy_tunnel_h2.go:265`; `socks5.go:210`, `:628`; `crashguard.go`). On a panic, `relayCounted` closes **both** connections. A detector panic inside the copy loop would therefore end that tunnel, not the process.
- **SOCKS5** runs no policy evaluation. It has the blocklist, `pluginDecision`, SSRF, connlimit and optional RFC 1929 auth, and writes a non-gated close record.
- **Sluice (CDR)** runs as a gRPC sidecar. This would be Culvert's first in-process third-party engine on the relay path, so it needs its own Culvert ADR before anything is proposed upstream.
- **Prebuffer.** Bytes stranded in `clientBuf.Reader` have caused three earlier bugs (`docs/ci/proxy-quality-architecture.md`). The pipelined-bytes tests are mandatory on every path the detector taps.
- **Privacy.** Culvert has no built-in privacy-category exclusion. Bypass comes from operator rules, the autoexclude cache or `inspect_unavailable`. **Observation of bypassed traffic is opt-in per rule or decryption profile.**

## 4. Detector work list

Three kinds of change:
- **Go-only additions** don't change what gets detected.
- **Detection changes** go into Python and Go together, with the fixtures regenerated so the comparison stays at zero differences (`migration/parity`).
- **Wait for Culvert** items need decisions or code on Culvert's side.

### 4.1 Before upstream proposal (does not block the lab)

| # | Change |
|---|---|
| 1 | LICENSE (Lee chooses MIT or Apache-2.0; it covers the content pack), plus contribution terms. Not a lab blocker. Required before any combined distribution or upstream PR. |
| 2 | Update `AGENTS.md` scope: it still says Go and proxy integration are out of scope. |
| 3 | Lower `go/go.mod` to `go 1.27.0` and keep `toolchain go1.27.4`. Re-run the minimum check with `-race` (section 2). Record the change in `migration/adr/0002`. |

### 4.2 Detection fixes (Python and Go together)

| # | Change | Evidence |
|---|---|---|
| 4 | Accept the post-quantum hybrid key shares in ServerHello and HelloRetryRequest. Server sizes: 0x11EC = 1120, 0x11EB = 1153, 0x11ED = 1665. | `tls_server.py:86`; `tlsx/tls.go:438`, `:583`, `:612` |
| 5 | Handle unknown registry values **by context**: per field and per extension position, decide whether an unknown value is recorded as unrecognized or rejected. Keep structural identification separate from semantic details. Add a positive and a malformed test for each change. Do not accept unknown values everywhere. | `tls_server.py:128` |
| 6 | A Content-Length that overflows int64 is malformed. Confirm Python's behaviour first. | `http.go:778` |
| 7 | Modern-client ClientHello/ServerHello fixture set, synthesized locally and refreshed quarterly. | — |

### 4.3 Public library slice (Go-only)

| # | Change |
|---|---|
| 8 | Public `go/detector` package: `New`, `NewFlow`, `Feed(dir, data)`, `EndDirection`, `Snapshot`, `Close` (idempotent). One Inspector per direction. A flow-level `Expire()` that is safe to call from any goroutine (see 5.2). |
| 9 | Typed terminal outcomes: `unknown`, `unsupported`, `outside_profile`, `budget_exhausted`, `error`. Nothing stays in `detecting` forever. None of them implies permission. |
| 10 | Panic boundary for `Feed`, `EndDirection`, `Snapshot` and `Close`. On a panic, the flow is quarantined: its parser is never re-entered, its reservations are released, and the panic is counted. Define what happens when cleanup itself fails. Fatal runtime errors are out of scope for recovery. |
| 11 | Stable reason codes and closed value sets (`All`/`Valid`/`String`), mirroring `decryptobs`. |
| 12 | Hostname evidence as a distinct type, so Culvert can pseudonymize it. |
| 13 | Profile restriction (initially HTTP/1, TLS, SSH; SMTP as a regression case). A prefix outside the profile becomes `outside_profile`, with no fall-through to other candidates. |
| 14 | Wire up `buffer.Account` per flow and per engine, with an admission refusal. Add proxy-profile limits. (Done at base `f239c65`: the deterministic config error and the Python upper bounds, review R4; capacity accounting, review R3.) |
| 15 | Read-only registries: no exported mutable maps. |
| 16 | Embedded content pack with a match test; host-supplied bytes as an alternative; a computed digest once its definition is fixed. |
| 17 | Remove `reflect.DeepEqual` from publishing; prove the event stream is identical. |
| 18 | Benchmarks with allocation limits, per-parser and public-package fuzzing, and unit tests for `tlsx` and `textroute`. |
| 19 | External consumer module test; a test that the module stays standard-library-only. |
| 20 | Analyzer retention (R1). **Done** at base `f239c65` (`6375457`). |

### 4.3a Progress on `claude/culvert-integration-prep`

Done:
- **#2** scope update.
- **#3** Go minimum, with `-race` at both toolchains.
- **#8–#13** first public slice in `go/detector`.
- **#19** external consumer module.

- **#4** post-quantum hybrid key shares, in Python and Go.

See `migration/STATUS.md`, section "Culvert integration preparation", for the evidence. Open: #5–#7, #14 (wiring), #16–#18.

### 4.4 Gate before attaching the real detector (lab phase L4)

All of the following must hold:
- the importable public package (#8, #19);
- a pinned detector commit and content digest;
- the selected profiles (#13);
- the typed outcomes (#9);
- bounded state with admission limits and reliable release (#14, 5.2);
- the panic contract (#10);
- no runtime dependency on Python, a source checkout or fixture paths.

Fix defects on the selected paths (#4–#6 for TLS/HTTP) before enabling those profiles.

## 5. Culvert-side adapter design (lab)

### 5.1 Ownership of the interface
- **Culvert owns the interface.** `internal/protodetect` defines the small interface Culvert needs (flow creation, feed, end, expire, snapshot, close).
- **A thin local adapter wraps the detector library and implements it,** with a compile-time assertion. Library API changes are then confined to that adapter.
- **The fake engine (L1) implements the same interface.** An interface alone does not stop facade changes from breaking the build; keeping the change inside the adapter does.

### 5.2 Tap design for raw-stream paths (CONNECT bypass first)
1. **Placement.** An optional observation phase runs **inside** `idleCopyCounted`'s loop, so one function still owns the read deadlines. It is not a wrapper `Reader`, and there is no second socket reader.
2. **Reads.** Use a small per-direction read buffer; start the experiment at 4 KiB. Never use the 128 KiB relay pool.
3. **Order.** Write each chunk to `dst`, then call `Feed`. Bytes **read** are observed. Bytes **successfully written** are forwarded. The two counters stay separate; a short write or write error is recorded as such.
4. **Expiry when no bytes arrive.** Two mechanisms are combined, because a read deadline cannot wake a goroutine that is blocked in `Write`:
   - **Detector state** is released by a flow-level expiry (`Expire()`), driven by a runtime timer (`time.AfterFunc`, which creates no goroutine until it fires) or by whichever direction runs next. `Expire` only takes the flow's own lock and never touches a socket. It is safe while a direction is blocked in `Write`, because that direction is not inside `Feed`.
   - **The tap buffer and the hand-off back to splice** happen when the blocked call next returns. The buffer is bounded (4 KiB per direction) but may live until then. Document that bound; don't claim the buffer is released within the observation window.
   - **Read side.** While observing, the read deadline is the earlier of the observation expiry and the next `armInterval`. When it fires because observation expired, the loop releases the observer, restores the normal deadline and continues. The connection is not closed.
5. **Idle-clock parity.** Ending observation must not reset or extend the connection's idle clock. The tap must not stamp activity more often than the current loop does, or the difference must be deliberate, documented and covered by `proxy_tunnel_idle_test.go`. Today the stamp updates only when `io.Copy` returns with `n > 0`.
6. **Hand-off.** Once the flow is terminal, the window is exhausted, it has expired or the budget is gone: take a detached snapshot, release the observer, and continue with the original `io.Copy(dst, src)` on the original connections so splice resumes. Add the byte counts to the existing total.
7. **Server-first protocols.** Both directions start immediately, and neither waits for the other's classification.
8. **Panic.** The detector boundary (#10) sits inside the tap, so a detector panic quarantines the observation without reaching `relayCounted`'s recovery, which would close the tunnel.

### 5.3 Facts-only phase (L2)
- Typed HTTP/TLS facts come from what Culvert has already parsed: the peeked prefix, both TLS connection states, and parsed HTTP requests and H2 streams. There are no new socket reads.
- Client↔proxy and proxy↔origin legs stay separate, as do offered and negotiated ALPN, and connection and stream scope.
- Results carry the provenance `culvert_facts` and are **never counted as raw-parser classifications**.
- **Parser comparison (alpnpeek vs detector TLS):** compare only the shared ALPN facts and the agreed validation obligations over a defined input domain. Record expected acceptance differences rather than weakening either parser. Routing and any future policy use one authoritative fact source.

## 6. Lab environment

### 6.1 Topology
- A Linux VM runs Culvert, so Linux TCP forwarding and splice behaviour can be tested.
- A second VM (preferred) runs the synthetic clients and origins: HTTP/HTTPS, SSH, SMTP, and scripted server-first and malformed cases.
- Network namespaces or containers are acceptable for functional tests; record host contention when interpreting performance results.
- Generated credentials, a lab-only CA, and lab-only listeners. No production secrets, customer traffic or Internet dependencies in deterministic tests.

### 6.2 Addresses and SSRF (verify in L0)
Culvert's guard (`internal/ssrf/ssrf.go:50-67`) blocks RFC 1918, CGN and `198.18.0.0/15`, but **not** the RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

- **Proposal:** put the origins on one of those ranges on an isolated VM-to-VM network, resolved through `/etc/hosts` on the Culvert VM.
- **L0 must prove it** through the real resolver and dial, with every protection on, before relying on it. Reading the list of ranges in the code is not enough.
- **If it fails:** an isolated, documented lab exception applied equally to all builds. Runs made under an exception never claim SSRF parity.
- **Also check in L0** whether Culvert restricts CONNECT destination ports (SSH on 22, SMTP on 25).

### 6.3 Source and build
- Clone both repositories locally at the pinned SHAs. Create local branches (e.g. `lab/protocol-detector`). Disable push on lab remotes.
- Connect them with **`go.work`**, which leaves Culvert's `go.mod` and `go.sum` untouched. Build baseline A with `GOWORK=off`.
- Before any packaging claim, prove a **standalone build without the workspace** against a pinned module artifact.
- **Four comparison states, all built reproducibly from recorded commits:**
  - **A:** unmodified Culvert.
  - **B:** integrated build, detector off.
  - **C:** integrated build, fake engine.
  - **D:** integrated build, real detector, observe mode.
  - A later enforcement build is a fifth state.
- **Per-campaign manifest:**
  - commits and patch hashes, and dirty-tree status;
  - content digest, Go compiler, binary hash and config hash;
  - OS/kernel, VM CPU/RAM and the runner version.
  - No secrets.
- **Backups:**
  - Git bundles and configuration templates, stored off the VM;
  - VM snapshots are for the environment only;
  - test a restore early.

### 6.4 Review of lab changes
- **Culvert lab changes:**
  - live on the separate local branch `lab/protocol-detector`;
  - get **no Codex review rounds for now** (Lee, 2026-11-14);
  - local tests and the acceptance gates in sections 7–8 still apply in full.
- **Built-in or self reviews** are never labelled as Codex reviews.
- **Detector changes** (branch `claude/culvert-integration-prep`) keep the repository's existing review process.

## 7. Lab phases

| Phase | Work | Exit evidence | Stop and redesign if |
|---|---|---|---|
| L0 | Unmodified Culvert; topology; auth, policy, TLS trust; synthetic origins | Reproducible A build; smoke scenarios repeat; baseline resource and latency report; SSRF/address proof (6.2) | The topology needs disabling protections that can't be isolated |
| L1 | Adapter plus fake engine, off by default; scripted results and failures | A/B equivalence; no observation state when off; lifecycle, panic and error tests pass | B differs from A in any forwarded byte or decision |
| L2 | Facts only on inspect paths (5.3) | Provenance, log projection, redaction, enable/disable tests; no new reads; no policy change | Redaction can't cover nested evidence |
| L3 | Raw tap on CONNECT bypass (5.2), with the fake engine | Byte transparency; server-first; fragmentation; quiet-read and blocked-write expiry bounds; release; splice restoration (8.2) | Transparency or the expiry bound fails after a bounded number of fix attempts (set in the L3 manifest) |
| L4 | Real detector behind the 4.4 gate | Expected classifications and explicit typed outcomes; resource gates with the real engine | Unexplained retained growth or disagreement |
| L5 | Inspect fallbacks and SOCKS5; H1/H2 facts; WebSocket only as a declared scope | Same matrix per path; TLS-ordering asymmetry preserved; SOCKS observation consent defined | — |
| L6 | Endurance: churn, silent peers, adverse input, recovery, packaging | Repeatable results within limits; lab report | — |
| L7 | Optional enforcement experiment (section 10) | As in section 10 | — |

L0 and the detector preparation (#2, #3, #8–#13) start now, in parallel. L1 doesn't need the real facade. A standalone VM cannot certify cluster propagation: before multi-node or shared use, complete the durable config, API/UI, RBAC and CP→DP surfaces.

## 8. Tests and measurement

### 8.1 Test matrix
Each scenario records its input or seed, expected outcome (from fixtures or protocol contracts, never from the detector's own output), observed outcome, close behaviour, forwarded-byte hashes and resources.

| Group | Scenarios | Pass condition |
|---|---|---|
| Baseline access | Allowed/denied destinations, auth success and failure, CONNECT success and failure, TLS verification | Same security decisions in A, B and D |
| Byte transparency | Header and payload in one write; empty, partial and full prebuffer; large transfers; random chunks; short writes; bytes plus EOF | No missing, duplicated, reordered or modified bytes; forwarded count = successful writes |
| Fragmentation | Whole message, 1-byte and random splits | Equivalent results within budget; explicit `budget_exhausted` beyond it |
| Bidirectional | Client-first, server-first, simultaneous, quiet direction, slow peer | No waiting deadlock; directions progress independently |
| Lifecycle | Half-close, reset, cancellation, blocked write, drain during observation, repeated Close | No leaked reservations, observer references or goroutines |
| **Deadlines and expiry** | Silent client; silent server; slow trickle; **one direction blocked in `Write`; both directions blocked in `Write`**; observation expiry before idle expiry | Detector state released within its documented bound; the tap buffer released within its separately documented bound; the connection is not closed because observation expired; **idle-timeout behaviour identical to A** |
| Detector failures | Constructor refusal, unsupported, budget denial, injected panics in Feed/End/Snapshot/Close, cleanup failure | Defined outcome; quarantined flow never re-entered; no access decision introduced |
| Protocols | HTTP/1, modern TLS hellos (including post-quantum), SSH; SMTP/STARTTLS when enabled | Expected profile outcome, provenance and bounded evidence; hints never establish identity |
| TLS/HTTP facts | Client vs upstream TLS state, offered vs negotiated ALPN, H1 keep-alive, concurrent H2 streams | No cross-leg or cross-stream attribution |
| Resource pressure | Many short flows, many quiet flows, admission exhaustion, enable/disable cycles, snapshot retention | Within limits; returns toward baseline |
| Privacy | Host/SNI evidence with redaction on; forbidden fields; label vocabularies | No escape through nested evidence; bounded cardinality |
| Recovery | Restart, config rollback, content-version change, VM restore | Reproducible; new flows use the intended version |

Don't assert identical read sizes or packet timing between runs. Assert delivered data, completion behaviour, policy outcomes and bounded timing.

### 8.2 Splice evidence
- Count `splice` syscalls on the Culvert process during a large transfer after the observation window, for example `strace -f -c -e trace=splice -p <pid>` or a bpftrace probe on `sys_enter_splice`. Compare A with D, and combine this with the unchanged concrete connection path.
- **Tracing runs are separate from performance runs,** because tracing itself adds cost.

### 8.3 Performance and capacity
- **Write the manifest before running:** concurrency, fixture sizes, warm-up, duration, repetitions and thresholds.
- **Run A and D interleaved** (A, D, A, D…) on pinned vCPUs on one host, so drift cancels out. Compare with a statistics tool (e.g. `benchstat`) and report the variability.
- **Measure:** CPU, allocations, retained heap, process memory, connections and goroutines, setup and first-byte latency, throughput, tail latency.
- **Three memory states:** off; actively observing; observation finished while the tunnel stays open. Include the quiet-flow and blocked-write cases.
- **Thresholds are not loosened after a failure.** Any deliberate revision is documented before the experiment is repeated.

### 8.4 Detection quality
- **Per profile:** positive and negative counts, false positives, false negatives, unknown, unsupported and budget-exhausted, each reported separately.
- **Fixture provenance:** record it, and keep synthetic fixtures separate from independent interoperability evidence.
- **Facts-only results** are excluded from raw-parser accuracy.
- **A small green lab corpus is not a production false-positive rate.** Before any statistical enforcement gate, define the denominator, the sampling method and the confidence interval in advance.

## 9. Budgets (hypotheses to measure)

| Budget | Starting hypothesis | Notes |
|---|---|---|
| Bytes observed per direction | 16 KiB | Post-quantum ClientHello is about 1.8–2.5 KB; SSH banner plus KEXINIT |
| Tap read buffer | 4 KiB per direction while observing | Separate from the residency ceiling; measured in the "actively observing" state |
| Retained after observation | ≤ 4 KiB per relay (benchgate culture) | Measured in the "finished, tunnel open" state |
| Feed calls per direction | 16 (experiment) | Not a protocol acceptance rule. Exhaustion is explicit and never grants permission |
| Observation time | 10 s | Detector-state bound via `Expire()`; the tap buffer has its own bound (5.2) |
| Concurrent observed flows | Admission cap derived from capacity | Refuse above it |
| Engine CPU and allocations per flow | p99 ≤ 50 µs, ≤ 64 allocations | Current Go numbers: p50 3–20 µs, 26–39 allocations |

Keep a results table: proposed value, baseline, candidate, decision.

## 10. Toward enforcement (L7, separately gated)

- **Separate branch, configuration and threat model.** An observe dashboard that looks correct is not a reason to start.
- **Written action table** for identified, incomplete, unknown, unsupported, error, budget exhaustion, retraction and shift. It states which bytes may already have been forwarded and whether the upstream was contacted before classification.
- **Restriction profiles only.**
  - The verdict is evaluated once, at the first terminal identification or when the window closes.
  - A later shift or retraction can only narrow permission.
  - Nothing converts an existing deny into an allow.
- **TLS server corroboration is extra evidence, not authentication.** A ServerHello consistent with the offer, plus well-formed early records, raises confidence. Cooperating endpoints can fake both, and the threat model states this limit.
- **Adversarial qualification before enforcement:**
  - split and fragmented handshakes;
  - a fake TLS prefix followed by another protocol;
  - SNI≠Host (domain fronting);
  - HTTP CL/TE ambiguity (checked differentially against Culvert's `net/http`);
  - prefix collisions;
  - 1-byte segment pacing against the feed budget;
  - worst-case ns/byte per parser.
  - **Exit:** every case has a recorded expected outcome, and no listed technique gets past an enforced profile without hitting its configured action.

## 11. Controls and rollback

- **Observation is opt-in for every tested path.** A TLS technical bypass is distinguished from an operator's privacy rule. SOCKS observation consent is defined explicitly.
- **Three recovery actions are always available:**
  1. stop new observations and release existing ones according to the lifecycle contract;
  2. restart the unmodified binary with the baseline configuration;
  3. restore the VM snapshot together with the source and config backup.
- **Abort an observe run on any of:**
  - byte corruption;
  - a changed access decision;
  - an uncontained failure;
  - a redaction failure;
  - unexplained retained growth;
  - an exceeded threshold.
- **Automatic admission shutdown** may be tested, with visible diagnostics. It must never silently disable a later enforcement profile.

## 12. Before anything goes upstream

None of these are needed for the lab; all are needed before proposing changes to KidCarmi/Culvert:
- **License and contribution terms** (#1).
- **A Culvert ADR** covering:
  - the in-process engine;
  - alignment with ADR-0002, 0003, 0011 and 0042;
  - the log block (`schema_version`, enum package, redaction);
  - the allocation and lock budget amendment;
  - the single authoritative TLS fact source.
- **Detector supply chain:**
  - signed `go/v0.x.y` tags;
  - govulncheck;
  - SBOM and provenance;
  - the standard-library-only test;
  - signed content with anti-rollback before any dynamic update.
- **Governance:**
  - CODEOWNERS;
  - a semver and deprecation policy for the facade;
  - a compatibility matrix (Culvert × detector × content);
  - coordinated security disclosure;
  - a release owner.
- **A Culvert `AGENTS.md` route** for `internal/protodetect`.
- **Runtime kill switch** (`ClusterSynced`, `AdminDurable`, no restart needed), node-group canary and written abort criteria.
- **Lab report deliverables:**
  - environment and topology;
  - manifests for A, B, C and D;
  - Git bundles and restore steps;
  - scenarios, seeds, expected results and commands;
  - pass/fail results with reproductions;
  - raw measurements;
  - classifications by profile, path and provenance;
  - known limits;
  - a recommendation.

Publishing or merging is a separate decision.

## 13. Open decisions

1. License: MIT or Apache-2.0 (before upstream).
2. ~~Branch for the detector work~~ Decided (Lee, 2026-11-14): `claude/culvert-integration-prep` from `f239c65`; Culvert lab work on local `lab/protocol-detector`.
3. First product goal: visibility, or restriction profiles later.
4. First profile families: HTTP/1, TLS and SSH, plus SMTP as a regression case. Confirm.
5. Starting budgets and quality targets: accept section 9 as hypotheses, or adjust.
6. ~~Lab review~~ Decided (Lee, 2026-11-14): no Codex rounds for Culvert lab changes for now; local tests and gates apply.

## 14. Immediate next work package

1. Record the two pinned revisions and the lab layout; set up `go.work`.
2. **L0:** run Culvert unchanged; prove the address/SSRF approach and the CONNECT ports; make the HTTP/HTTPS/SSH scenarios repeat; take the baseline measurements.
3. **In parallel, on the detector:** #2 and #3 (`AGENTS.md` scope; the Go minimum with `-race`), then the public slice #8–#13.
4. **L1:** the Culvert-owned interface, the fake engine and disabled equivalence.
5. **L2,** then **L3** with the expiry design in 5.2, then **L4** with the real detector.

---

## Appendix B — Corrections to the original review (Appendix A)

| Item in Appendix A | Correction | Where it is now |
|---|---|---|
| B5: "one malformed connection would drop every user's traffic" | Overstated. Culvert recovers relay panics; a detector panic in the copy loop ends that tunnel, because `relayCounted` closes both connections. The detector boundary is still required so observation failures don't end tunnels. | §3, #10, 5.2.8 |
| C2: "checked on each read … never shortens armInterval" | Wrong. That bound held state up to 30 minutes for quiet flows. Replaced by flow-level `Expire()` plus an earlier read deadline while observing. A read deadline doesn't wake a blocked `Write`, so the tap-buffer bound is documented separately. Ending observation never changes the idle clock. | 5.2 |
| C2: "stamp the shared activity clock exactly as today" | Ambiguous. Today the stamp updates only when `io.Copy` returns with `n > 0`, not per chunk. Parity or a documented difference is required. | 5.2.5 |
| C2/C7: 16 KiB buffer vs "≤ 4 KiB retained" | They conflict. Separate the read buffer, the observed-byte budget and post-observation residency; measure the three memory states. | §9, 8.3 |
| C2: "no time spent in the parser delays the write" | Partly true: parsing still delays the next read. Observed and forwarded counters are kept separate. | 5.2.3 |
| C3: server corroboration as "defence" | Extra evidence, not authentication; limits go in the threat model. | §10 |
| C7: 16 Feed calls | An experiment, not an acceptance rule. Exhaustion is explicit and never permits. | §9 |
| B2/#5: "tolerate unknown registry values" | Context-aware per field and position, with positive and malformed tests. | #5 |
| B3: differential fuzz "any disagreement is a failure" | Compare only shared facts and agreed obligations over a defined domain; record expected differences. | 5.3 |
| Section 2: "set go 1.27.0" | Now qualified evidence: vet and tests passed with go1.27.0 on a scratch copy of `a2cf4e8`; the race detector was not run. Repeat with `-race`. | §2, #3 |
| B1: license as a P0 blocker | Not a lab blocker; still required before distribution or an upstream proposal. Lee decides the license. | #1, §12 |
| Lab SSRF exception (addendum §11) | Prefer the RFC 5737 addresses, which the guard doesn't block, subject to an L0 proof through the real resolver and dial. | 6.2 |
| "Interface stops facade changes breaking the build" | Culvert defines the interface; a thin adapter wraps the library and implements it. | 5.1 |

---

# Appendix A — Original review (historical)

Kept unchanged as the record of the November 14 review. Where it conflicts with the working plan above, the plan wins; Appendix B lists the corrections.

## Protocol detector ↔ Culvert integration: plan review and detector work list

Date: 2026-11-14. Reviewer: Claude (Claude Code session). This is a review of a plan, not an integration test.

This file combines two pieces of work:
- **Sections 1–5:** a review of Codex's integration plan against the source of both repositories.
- **Section 6:** the changes we can make in the protocol detector now, before Culvert decisions are needed, so the integration goes more smoothly.

Section 7 lists smaller findings, and section 8 lists open decisions.

**Contents**
1. Blockers the plan misses (B1–B5)
2. Facts in the plan to correct or sharpen (with B6/B7)
3. Improvements to the design (C1–C9)
4. Revised phase plan
5. How the two parts fit together
6. Detector changes we can make now (#1–#20)
7. Smaller items found along the way
8. Open decisions for Lee

## What I reviewed

| Repository | Revision | Note |
|---|---|---|
| KidCarmi/Culvert | `main` `52eb9d1e4482adc9773afc4db77109acad617625` | Same commit as the plan. All of the plan's Culvert line references were checked against the source. |
| leenadav/protocol-detector | `claude/go-migration` `a2cf4e8b1a557da328f98cb62780bb522f7a1fe7` | **One commit after the plan's baseline (`a4d39c3`).** It adds Go GSS/LDAP and changes `inspector.go`, `CAPABILITIES.json` and `cases.json`. |
| protocol-detector `main` | `201a552` | Python reference, `ARCHITECTURE.md`, `AGENTS.md` |

What I ran:
- On `a2cf4e8`: `go build ./... && go vet ./... && go test ./...`, using go1.27.4. All passed.
- On `a2cf4e8`: `go test -bench`. It found nothing to run, because the repository has no `Benchmark*` functions.

What I did not do:
- I modified no product code.
- I captured no traffic.
- I ran no detector-in-Culvert test.

## Verdict

The direction is right and I would keep it:
- an in-process Go library behind a narrow Culvert adapter;
- observe mode first;
- Culvert owns every transport and policy decision;
- no PCAP, Analyzer or TCP reassembly in the proxy path;
- enforcement only as a restriction attached to the existing policy decision.

Every Culvert line reference I checked was accurate, and its warnings are correct and important:
- the splice fast path;
- the prebuffer;
- the Strip-ALPN and native-ALPN asymmetry;
- the SOCKS policy gap.

The plan is not yet ready to implement, though. It misses five things that block the work, and it ignores the Culvert ADRs that already govern this design. It also leaves budgets, quality targets and adversarial testing as open questions where it should state them as targets. Details follow, most important first.

---

## 1. Blockers the plan misses

### B1. The detector repository has no license (legal blocker)
- No `LICENSE` or `COPYING` file exists at the repository root or under `go/`.
- `pyproject.toml` and the README name no license.

Public code with no license is "all rights reserved". Culvert is MIT. Two consequences:
- Culvert's PR deep gate runs `go-licenses --disallowed_types=forbidden,restricted` when dependencies change (`.github/workflows/pr-deep-gate.yml:429-447`).
- Nobody can legally redistribute a Culvert binary that contains the code.

The plan files this under "verify licensing before distribution". It should be a P0 exit criterion:
- Lee chooses a license that is compatible with MIT. MIT or Apache-2.0 would do; Apache-2.0 adds a patent grant.
- Add `LICENSE`, plus `NOTICE` if Apache.
- Record contribution terms, because two owners and outside friends will contribute.
- Confirm the content pack (`content.json`) is covered by the same license.

### B2. The TLS parser treats modern post-quantum handshakes as "unknown"
`go/internal/protocols/tlsx/tls.go:438` holds the accepted key-share groups:

```go
var keySizes = map[int]int{23: 65, 24: 97, 25: 133, 29: 32, 30: 56, 256: 256, ...}
```

At lines 612-614 a ServerHello whose group is not in that map returns `Unsupported("Server key share group outside supported profile")`. Lines 583-584 do the same for HelloRetryRequest.

- X25519MLKEM768 (0x11EC) is not in the map. It is the default in current Chrome, Edge and Firefox, at Cloudflare, Google and AWS, and in Go's own `crypto/tls`.
- In bypass mode, the server direction of most modern HTTPS would therefore be classified `unknown`.

The plan's quality measurement would read this as a quality problem. It is really a parser defect. Required changes:
- Fix the parser, with fixtures for 0x11EC, 0x11EB and 0x11ED.
- Audit **every field whose values come from an IANA registry** (named groups, cipher suites, extensions, signature schemes, ALPN IDs). A value the parser doesn't recognise should be recorded as such, not make the whole message unsupported. Structural malformation is a different case and should still fail.
- Add a "modern client matrix" fixture set (current Chrome, Firefox, Safari, curl, Go and Java ClientHello/ServerHello pairs). Refresh it every quarter. Major vendors keep exactly this kind of corpus.

### B3. Culvert already has a ClientHello parser, so there would be two
`internal/alpnpeek` (ADR-0042) parses the offered ALPN, and `peekClientALPN` (`proxy_tunnel_h2.go:314`) uses it to choose between H2 and H1 inspection. The plan never mentions it.

If the detector parses the same bytes independently, the two parsers can disagree: routing follows one and policy or logs follow the other. That is a classic evasion route (parser differential). Required:
- **One parse per decision.** In inspect paths, either the detector consumes Culvert's already-parsed facts, or both run under a differential fuzz harness (`alpnpeek.Parse` vs detector `tlsx`) in Culvert's fuzz-nightly matrix. Any disagreement on ALPN or acceptance is a failure.
- In enforce mode, routing and policy must use the same facts.
- The longer-term choice of a single owner (alpnpeek or the detector) is recorded in the Culvert ADR.

### B4. Culvert's ADR-0011 already sets the rules for this log block, and the plan ignores them
ADR-0011 (Decryption Observability) and `internal/decryptobs` set the house pattern for an optional, categorical, SIEM-exported block on `logstore.Entry`. Hard rules from ADR-0011 §4:
- "Observability must never block or change the traffic decision."
- "≤ 1 heap allocation per decrypted/decisioned session", "**no new lock** on the proxy hot path".
- When the feature is off, the wire is byte-identical: a `nil` pointer and an `omitempty` block.
- "no new buffer" (reuse the reqlog ring).
- Labels are enums only; host, SNI and identity are record fields, never labels. There is a 200-label cap and a required 10k-distinct-value cardinality test.
- Hostnames go through the single `persistLogEntry` HMAC pseudonymizer (`decryption_redact_hosts`).

Where the detector stands against those rules today:
- **Allocations:** its own benchmark records 26–39 allocations per flow (`migration/benchmarks/engine-go-vs-python-1113a91.json`).
- **Locks:** `buffer.Account` is mutex-guarded.
- **Hostnames:** it emits SNI and Host hostnames as evidence (`textroute/http.go:255`, `tlsx/tls.go:220-256`).

Required changes to the plan:
1. Model the new block on `dec`:
   - a nested `pd` (or `app`) block with its own `schema_version`;
   - an `internal/protodetect` enum vocabulary with exhaustive `All`/`Valid`/`String` tests, the same discipline as `decryptobs`;
   - projection to every surface (ring, JSONL, SSE, SIEM, API) from one value.
2. **Redaction:** any hostname inside the block must go through the same `persistLogEntry` pseudonymizer. Otherwise the new block leaks plaintext destinations whenever `decryption_redact_hosts` is on, which is a privacy regression.
3. **"Encrypted" and "bypassed" states:** derive them from `decryptobs.Outcome` and `DecisionSource`. Do not invent a second vocabulary.
4. **Budget:** write an explicit amendment for observed flows (CPU, allocations, retained bytes). Allocations and locks are not covered by ADR-0011's numbers, so they need their own figures. Keep zero added allocations for flows that are not observed, enforced by a benchgate in the style of `proxy_tunnel_relaybuf_benchgate_test.go`.

### B5. Panic containment must be required, not optional
- The engine has no `recover()`.
- In Go, a panic in a relay goroutine terminates the whole process, so one malformed connection would drop every user's traffic.

The plan says "contained panic if recovery is chosen". It has to be a requirement:
- **Per-call recovery.** The adapter recovers around every Feed, EndDirection and Close call. Culvert's `internal/plugin` already does panic-safe dispatch on the hot path, which is the precedent.
- **On panic:**
  - the flow is marked `error`;
  - the forwarded bytes are untouched;
  - the panic is counted and an alert fires.
- **Circuit breaker.** A process-wide breaker stops new observations after N panics in a time window.
- **Unrecoverable failures.** Fatal runtime errors such as concurrent map writes or running out of memory cannot be recovered. That makes the race detector, the "no shared mutable state" rule and hard memory budgets mandatory gates.
- **Global maps.** Mutable package-level maps exist today: `engine.Ported` and `engine.Families` are exported (`inspector.go:15,26`), and `DatagramValidators` is filled in `init()`. The public facade must expose only immutable copies.

---

## 2. Facts in the plan to correct or sharpen

| Plan statement | What the source shows | Effect |
|---|---|---|
| Detector head `a4d39c3` | The head is `a2cf4e8` (adds LDAP/GSS; changes `inspector.go` and the capability manifest) | Re-pin the baseline. Update the plan's table rather than citing a moving branch. |
| SOCKS5 "does not execute the same `PolicyStore.Evaluate` path" | SOCKS5 runs **no policy evaluation at all**. It has blocklist, `pluginDecision`, SSRF, connlimit and optional RFC 1929 auth. The close record is the non-gated `recordTunnelClose` (no match, no LogTraffic, no `dec`). The CONNECT-only rejection is at `socks5.go:496`. | There is no `LogTraffic=false` rule to honour on SOCKS. Observation needs its own logging-consent decision, and the log record there differs. |
| An in-process engine has precedent | Sluice (CDR) is a **gRPC sidecar**, not an in-process library. No in-process third-party detection engine sits on the relay path today. | The integration needs its own Culvert ADR under `docs/adr/`, following ADR-0002 (dependency direction), ADR-0003 (obs facade) and the ADR-0042 pattern ("main owns the peek window and fallback, the package owns only the parse"). |
| Open decision 4 (privacy bypass) | Culvert has no built-in privacy-category exclusion. Bypass comes from operator rules (which can match `DestCategory`), the autoexclude cache (technical reasons only) or `inspect_unavailable`. | Make observation **opt-in per rule or decryption profile**, not opt-out. A rule an operator wrote to avoid inspecting health or banking sites must not silently gain metadata inspection. |
| "Every Go status pending" (from older status text) | 80 families are "experimental", 8 are pending, 0 are parity-verified. The last parity run was 4733/4733. HTTP/2, SMB, RDP, QUIC, DTLS and IKEv2 are not ported. TLS fingerprints, certificates and continuation are `NotPorted`. | HTTP/2 prior-knowledge (h2c) through a bypass tunnel would sit silently at `detecting`; see B7. Inner H2 classification must come from Culvert's parsed facts. |
| Splice fast path | Confirmed. `idleCopyCounted` (`proxy_tunnel.go:267`) uses `io.Copy`, which delegates to `ReaderFrom`/splice for TCP↔TCP. It owns `SetReadDeadline` on every loop through `armInterval = tunnelIdleTimeout/2` and a shared monotonic activity stamp. | See C2 for a concrete tap design. |
| Prebuffer risk | Real and **historically costly**. `docs/ci/proxy-quality-architecture.md` records three bugs in this family: bytes stranded in `clientBuf.Reader` in `handleTunnelBypass`, `handleWebSocket` and the `handleTunnelInspect` peek. | Cite this history in the ADR. Make the pipelined-bytes tests (`TestProxyE2E_WebSocket_PipelinedClientBytes` style) a required gate on every tapped path. |
| `dec.sni` exists | `DecryptionOutcome.SNI` is **never assigned** in production; it is only projected (`decryption_observability.go:135`). | This is a small existing Culvert bug. Fill it from `tls.ClientHelloInfo`, not from the detector. Don't let the integration become the accidental fix. |
| Toolchain "may raise Culvert's module requirement" | The detector's `go 1.27.4` **will** force Culvert's `go` line from 1.27.0 to 1.27.4. Culvert's `go.mod` says the `go` line "is not raised to match". | Set the detector's `go` line to the real minimum (`go 1.27.0` or lower) and keep 1.27.4 as a `toolchain` line. This is a one-line fix in P1. |

### B6 and B7. Detector API gaps the plan names correctly but understates
- **B6, resource accounting:** `buffer.Account` has **no caller outside its own tests**. Parsers bound their state with local caps but don't charge any account.
- **B6, configuration bounds:** `Config.Validate` checks only that values are positive and has no upper bounds (`contracts.go:217`). It iterates a map, so with several bad fields the error names a random one. The default `MaxBytes` of 65536 is far too large for a proxy.
- **B7, unsupported families:** when the selected family is not ported, `Feed` returns `nil` and leaves the observation at `detecting`. The only signal is the side field `Inspector.NotPorted`. The facade must turn this into a typed terminal state.
- **Hot path:** `reflect.DeepEqual` runs on every published event (`inspector.go:243`). It is allocation-heavy and unnecessary; replace it with a revision or dirty flag. Mark this as a P2 performance item that must keep current behaviour.
- **Testing gaps:**
  - `tlsx` and `textroute` have **no Go test files**; they are covered only through parity cases.
  - The Inspector fuzz target has one committed seed.
  - No `testing.B` benchmarks exist.

---

## 3. Improvements to the design

### C1. Reorder phases: start with facts, tap the relay later
In the plan, the first traffic-touching phase (P4) changes the riskiest code: the bypass relay with splice. I recommend this order instead:

- **P4a, facts only, no new byte reads.**
  - On the inspect paths, Culvert already holds the client prefix (the peek), both TLS connection states (client↔proxy and proxy↔origin) and parsed HTTP requests.
  - Feed these as typed facts and emit the new log block on `TUNNEL_CLOSED` and request entries.
  - This exercises the whole product surface without touching transport: schema, enum package, redaction, config surface, CP→DP snapshot, GUI and API, metrics, the quality pipeline, rollback.
- **P4b, bypass-relay observation.** Uses the tap in C2, so it starts from a proven log, config and quality pipeline.
- **P5,** then the strip-path non-TLS fallback, the native-path plaintext fallback and SOCKS5.

### C2. A concrete tap design that keeps splice
**Who owns the tap.** Add an optional, bounded "observe prefix" phase inside the existing `idleCopyCounted` loop. It must not be a wrapper `Reader`, so that one function stays the only owner of deadlines.

1. While observation is active, read into a **small** pooled buffer, 16 KiB at most. Do not use the 128 KiB `relayBufPool`, because it would break the benchgate residency ceiling of 4096 B per relay.
2. Write each chunk to `dst` immediately; nothing is ever held back in observe mode.
3. Then call `Feed(dir, chunk[:n])`. That way no time spent in the parser delays the write.
4. Stamp the shared activity clock exactly as today.
5. When the flow is terminal, the window is exhausted, the observation time has passed or the global budget is gone:
   - release the buffer;
   - take a detached snapshot;
   - fall through to the existing `io.Copy(dst, src)` on the original conns, so `ReaderFrom`/splice resumes for the rest of the connection.
6. Add the counts to the existing total.

**Wall-clock limit.** The observation time budget is checked against the monotonic clock on each read. It never shortens `armInterval`. A quiet direction simply stays in the tap until idle timeout, exactly as today, because the tap is the same loop.

**Server-first protocols.** Both directions start at once, which handles server-first protocols. The flow object synchronises the two directions; each direction has its own Inspector.

**Tests:**
- Extend `proxy_tunnel_relaybuf_benchgate_test.go`:
  - off: zero added allocations and the same held heap;
  - on: the buffer is released after the window;
  - a test that splice/`ReaderFrom` is actually used after hand-off, verified on Linux TCP loopback (for example by counting `ReadFrom` calls on a wrapped `*net.TCPConn`).
- Add a **transparency invariant** as a property test: for random payloads, split points and close orders, the bytes delivered and the close semantics with observe on must equal those with observe off.

### C3. An adversarial and evasion programme before any enforcement
Major vendors gate App-ID enforcement on red-team results, not on parity. Add a P6.5 phase "adversarial qualification" with a written threat model of the detector inside the proxy (attacker-controlled bytes in a shared process). It should cover at least:
- **TLS framing:** a ClientHello split across records and across reads, fragmented handshake messages, oversize extensions.
- **Fake TLS prefix:** a valid TLS ClientHello followed by a non-TLS protocol. This is how many tunnelling tools get past SNI filters. Defence: in enforce mode, require **server corroboration**. The ServerHello must be consistent with what was offered (version, cipher and group drawn from the offered sets), followed by a short record-layer continuity check (the next N records are well-formed TLS records with plausible lengths). The Go TLS parser already reads ServerHello, so this is cheap.
- **Domain fronting:** SNI ≠ inner Host in inspect mode. Report it; never let a Host header widen what the SNI allowed.
- **HTTP ambiguity:** CL/TE ambiguity, duplicate Host, obs-fold and similar. The detector rejects several of these already (`http.go:715-782`). Culvert's `net/http` must reject the same set; check this differentially.
  - Small detector bug to fix: `strconv.ParseInt` errors are discarded for 20-digit Content-Length values (`http.go:778`).
- **Prefix collisions:** `PRI` and other extension methods, an SSH banner after HTTP, ECH outer SNI being treated as identity.
- **Algorithmic complexity:** a worst-case ns-per-byte assertion per parser under adversarial input. Linear-time RE2 is necessary but not sufficient, because per-line regex use (`http.go:30-41`) and per-event `DeepEqual` add constant-factor costs.

Exit criteria: every case has a recorded expected outcome; no enforced profile can be bypassed by a listed technique without the flow ending in its configured `unknown` or `error` action.

### C4. Fuzzing and tests at Culvert's level
**Detector side:**
- structure-aware fuzz targets per parser (TLS, HTTP, SSH, SMTP, and any family that enters a profile), seeded from `cases.json`;
- a facade-level fuzz target that checks invariants (never panics, revisions only increase, retained bytes ≤ budget, `Close` releases everything);
- `testing.B` benchmarks with allocation ceilings.

**Culvert side:**
- add the targets to `fuzz-nightly.yml`. ADR-0042 notes that this matrix is maintained by hand and already missed one target.
- give `internal/protodetect` a boundary test like `TestAlpnpeekBoundary_*`: no imports except the detector facade and approved stdlib.

### C5. Supply chain and content trust
Culvert already runs govulncheck, go-licenses, cosign-signed CycloneDX SBOMs per module, trivy and dependabot. The plan should state that the detector module meets the same bar:
- signed release tags (`go/v0.x.y`);
- `govulncheck` in the detector's CI;
- SBOM and provenance;
- a test that the module stays standard-library-only, so `go.mod` has no `require` lines without an ADR.

Content pack:
- Ship it inside the module with `go:embed`.
- Compute its digest in Go over a canonical encoding. Today the code only checks that the digest field is non-empty (`content.go:144`).
- Before any dynamic update, sign packs within Culvert's existing sigstore and release-catalog trust chain, with **anti-rollback** (a monotonic version) and per-flow pinning, as the plan already says.

### C6. Quality targets the plan should state explicitly
"Measure false positives" is not an acceptance criterion. Proposed, to be agreed in P0:
- **Precision and recall** per enforced family on an independent labelled corpus, reported with a 95% confidence interval. Example gate: for an enforced profile, the upper bound of the false-positive rate is ≤ 0.1%. Culvert's `edge-case-lab/` and the detector's synthetic corpus are starting points, not ground truth.
- **Shadow comparison** against the old `detectProtocolName` label and against Culvert's own facts (offered ALPN from alpnpeek, negotiated state, SNI), with a disagreement dashboard.
- **Unknown-rate budget** per path. Track B2-type causes (registry values the parser doesn't recognise) separately from real unknowns.

### C7. Proposed starting budgets
These are defaults the harness can test against, not production claims. Culvert's own `roadmap/PALO-ALTO-ARCHITECTURE-COMPARISON.md` cites App-ID's bounded identification window of about 4 packets / about 2 KB.

| Budget | Proposed default | Rationale |
|---|---|---|
| Bytes observed per direction | 16 KiB | Covers a post-quantum ClientHello (about 1.8–2.5 KB), the ServerHello plus the first records, and an SSH banner plus KEXINIT |
| Reads (Feed calls) per direction | 16 | Limits per-call overhead when bytes arrive in many tiny reads |
| Observation time | 10 s | Releases detector state; it does not change the connection's idle timeout |
| Retained bytes per flow | ≤ 4 KiB after the TLS/HTTP identification | Matches the relay residency culture |
| Concurrent observed flows | A fraction of `activeConns` capacity; refuse admission above it | Cheap global gate |
| Engine work per observed flow | p99 ≤ 50 µs CPU, ≤ 64 allocations | Current Go measurements are p50 3–20 µs and 26–39 allocations per flow |

### C8. Policy semantics: say how classification changes are handled
Culvert's PAN-OS comparison names the gap exactly: "verdict latched at CONNECT; no continuous re-classification". Keep Codex's restriction-profile approach and add:
- **Decision point:** the verdict is evaluated once, at the first terminal identification or when the window closes.
- **Later changes can only narrow.** A shift or retraction can terminate the flow or log it; it can never widen permission.
- **Shadow mode** follows ADR-0025 (learning is advisory, never enforcement).
- **Policy language changes** go through `evalAccessRules` (ADR-0026), as the plan says.

### C9. Operations, governance and rollout
- **Runtime kill switch.** It is a config-surface row with `ClusterSynced` and `AdminDurable`, takes effect without a restart, and is covered by the existing config-surface parity tests.
- **Automatic disable.** Turn observation off when CPU, allocation or panic thresholds are crossed. Report the state to the operator.
- **Canary.** Roll out by node group (`internal/nodegroup`), with written abort criteria for each rollout step.
- **Cross-repository governance:**
  - CODEOWNERS on both sides;
  - a semver and deprecation policy for the facade;
  - a compatibility matrix of Culvert version × detector module version × content version;
  - coordinated security disclosure (detector `SECURITY.md` to Culvert);
  - a named release owner.
- **Agent scope documents.** Update the detector's `AGENTS.md` (it still says "no native rewrite … or proxy integration in scope") and add a Culvert `AGENTS.md` route for `internal/protodetect` in the same P0 change.

---

## 4. Revised phase plan (summary)

| Phase | Change from the Codex plan |
|---|---|
| P0 | Add: license (B1); Culvert-side ADR (ADR-0002/0003/0011/0042 alignment); agreed budgets (C7) and quality targets (C6); re-pin to `a2cf4e8` or later; threat model draft |
| P1 | Add: B2 post-quantum and registry-value fix with the modern-client matrix; `go` line set to the real minimum; typed terminal state for not-ported families (B7); immutable public registries; per-parser fuzzing and benchmarks |
| P2 | As planned, plus: wire `buffer.Account`; Config upper bounds with a deterministic error; remove `DeepEqual` from the hot path; embedded content with a computed digest |
| P3 | Add: panic boundary and circuit breaker (B5); enum vocabulary package; redaction through `persistLogEntry`; boundary test |
| **P4a (new)** | Facts-only observation on the inspect paths (C1); differential fuzzing of alpnpeek and the detector (B3) |
| P4b | Bypass tap per C2, with a transparency property test and a splice-restoration test |
| P5 | Fallback paths and SOCKS5, observing only on opt-in rules or profiles |
| P6 | As planned |
| **P6.5 (new)** | Adversarial qualification (C3) and corpus quality gates (C6) |
| P7–P8 | As planned, plus server corroboration for TLS-based enforcement and the narrow-only rule for classification changes (C8) |

## 5. How the two parts fit together

Most of the review's detector-side items (B1, B2, B5–B7, parts of B4, C4 and C5) can be done in the detector now, without waiting for Culvert. Section 6 turns them into concrete changes. Together they cover phases P0–P2 and part of P3 in the revised plan.

| Review item | Detector change in section 6 |
|---|---|
| B1 license | #1 |
| P0 agent scope documents (C9) | #2 |
| Toolchain `go` line (section 2) | #3 |
| B2 post-quantum and registry values | #4, #5, #7 |
| C3 HTTP ambiguity (Content-Length) | #6 |
| D1 public API, B7 typed unsupported | #8, #9, #19 |
| B5 panic containment | #10 (library side; Culvert adds its own boundary too) |
| B4 enum vocabulary and redaction | #11, #12 |
| Allowlisted profiles (plan P4) | #13 |
| B6 budgets and configuration | #14 |
| B5 global mutable maps | #15 |
| C5 content packaging | #16 |
| B4 allocation budget | #17, #18 |
| C4 fuzzing and benchmarks | #18 |
| R1 Analyzer retention | #20 |

---

## 6. Detector changes we can make now

The constraint to keep in mind: the Python code is the reference implementation, and the Go port is gated by a case-by-case comparison against it (4733/4733 cases matching at `a2cf4e8`, recorded in `migration/STATUS.md`). That gives three kinds of change:
- **Go-only additions** that don't change what gets detected. These are safe at any time.
- **Detection changes.** These go into Python and Go in the same change, with the fixtures regenerated (`migration/parity/cases.py`) and the comparison kept at zero differences. A Go-only difference must be justified in `migration/parity/deltas.json`.
- **Waiting on Culvert:** items that need decisions or code on Culvert's side first.

Every step goes through the repository's Codex review loop (`AGENTS.md`).

### 6.1 Do first (small, unblocks everything)

| # | Change | Why it helps integration |
|---|---|---|
| 1 | **Add a LICENSE** (MIT or Apache-2.0; Lee chooses) at the repository root. State that it covers the content pack too. | Without it Culvert's `go-licenses` gate fails, and the code can't legally be combined or redistributed (B1). |
| 2 | **Update the scope in `AGENTS.md`.** It still says "no native rewrite … or proxy integration is in scope". | Otherwise every Codex review round flags the integration work as out of scope. |
| 3 | **Change `go/go.mod` from `go 1.27.4` to `go 1.27.0`,** keeping `toolchain go1.27.4`, and record the change in `migration/adr/0002-toolchain-layout-dependencies.md`. | Importing the module would otherwise force Culvert's `go` line from 1.27.0 to 1.27.4, which Culvert's `go.mod` policy forbids. |

### 6.2 Detection fixes (Python and Go together)

| # | Change | Evidence |
|---|---|---|
| 4 | **Accept post-quantum key shares** in ServerHello and HelloRetryRequest. Server-side sizes: X25519MLKEM768 (0x11EC) = 1120 bytes, SecP256r1MLKEM768 (0x11EB) = 1153, SecP384r1MLKEM1024 (0x11ED) = 1665. | Python has the same gap (`protocol_engine/tls_server.py:86`), as does Go (`go/internal/protocols/tlsx/tls.go:438`, `:583`, `:612`). Today most modern HTTPS server replies come back "unknown" (B2). |
| 5 | **Tolerate unknown values in IANA-registry fields** (named groups, extensions, cipher suites, signature schemes): record them as "unrecognized" instead of making the whole message unsupported. Structural errors still fail. | `tls_server.py:128` rejects any unknown TLS 1.2 ServerHello extension. Each new browser feature would otherwise break detection. |
| 6 | **Content-Length overflow:** a value that doesn't fit in int64 is malformed. Check what Python does first, then align both. | Go discards the `strconv.ParseInt` error (`go/internal/protocols/textroute/http.go:778`); the regex allows 20 digits. |
| 7 | **Modern-client fixture set:** current Chrome, Firefox, Safari, curl, Go and Java ClientHello/ServerHello pairs, synthesized locally per the repository rules, as regression cases. Refresh quarterly. | It would have caught #4, and it guards against the next change of this kind. |

### 6.3 Go-only additions (no detection change, can start now)

| # | Change | Why |
|---|---|---|
| 8 | **Public `go/detector` package:** `New(config, pack)`, `NewFlow(meta)`, `Feed(dir, data)`, `EndDirection(dir, reason)`, `Snapshot()`, `Close()` (idempotent), built on the existing Inspector, with one Inspector per direction. | Everything is under `internal/` today, so Culvert can't import it (D1). |
| 9 | **Typed "unsupported" result.** Today `Feed` returns nothing, the result stays at "detecting", and the only signal is the side field `Inspector.NotPorted`. The public package turns it into a terminal state with a stable reason. | An unsupported protocol (for example HTTP/2 prior knowledge) would otherwise look like detection still in progress (B7). |
| 10 | **Panic recovery inside `Flow.Feed`, `EndDirection` and `Close`.** On a panic the flow is marked failed, its state is released and the panic is counted. | One malformed connection must not take down the proxy (B5). Culvert adds its own recovery boundary as a second layer. |
| 11 | **Stable reason codes and closed value sets** with `All`/`Valid`/`String` and exhaustive tests, mirroring Culvert's `decryptobs`. Keep the English sentences for display only. | Culvert's ADR-0011 rules require a fixed vocabulary for labels and SIEM fields. |
| 12 | **Hostname evidence as a distinct type** (SNI, Host, other server names). | Culvert can then pseudonymize every hostname at one point (`persistLogEntry`) and not leak destinations (B4). |
| 13 | **Profile restriction:** the flow allows only selected families (for example HTTP/TLS/SSH). A match outside the profile is reported as "outside profile" instead of falling through to other candidates. | Needed for the first narrow integration slice. It keeps the prefix-dispatch semantics unchanged. |
| 14 | **Wire up the memory budget** (`buffer.Account`) per flow and per engine, and refuse a new flow when the budget is exhausted. Add Go-side upper limits for a "proxy profile", and make the config error deterministic (`go/internal/contracts/contracts.go:218` iterates a map). | The budget has no caller outside its own tests, and the default of 64 KiB per direction is too large for a proxy (B6). |
| 15 | **Read-only registries:** stop exporting the mutable `engine.Ported` and `engine.Families` maps (`inspector.go:15,26`) and expose accessors that return copies. | Another package could otherwise modify shared state at runtime, which in Go can crash the whole process (B5). |
| 16 | **Embed the content pack** in the module (`go:embed`), with a test that it matches `migration/fixtures/content.json`. Accept validated bytes from the host as an alternative. Compute the digest once its definition is fixed (M6). | Today the pack lives outside the module and loads from a file path, and the digest is only checked for being non-empty (`content.go:144`). |
| 17 | **Remove `reflect.DeepEqual` from every published event** (`inspector.go:243`) and use a change flag, with a test that the event stream is identical. | Fewer allocations, which matters for Culvert's allocation budget. |
| 18 | **Benchmarks with allocation limits** (`testing.B` for TLS, HTTP and SSH flows), structure-aware fuzzing per parser seeded from `cases.json`, invariant fuzzing at the public package level, and unit tests for `tlsx` and `textroute`. | There are no `Benchmark*` functions in the repo, `tlsx` and `textroute` have no test files, and the Inspector fuzz target has a single seed input. |
| 19 | **Separate consumer test module** (its own `go.mod`) that imports `go/detector` without any repository fixture paths. Also test that the module stays standard-library-only. | Proves Culvert can actually consume the package. |
| 20 | **Fix the packet analyzer's retention:** prune finished `sinks` and bound `Records` (`go/internal/analyzer/analyzer.go:92,113,130`). | This is the earlier review's R1. It isn't on the proxy path, but the CLI and PCAP tools are affected. |

### 6.4 Wait for Culvert

These need decisions or code on Culvert's side first:
- exact budget numbers (section 3, C7, has proposals);
- the log block layout and schema version (B4);
- the types for HTTP/TLS facts passed in from Culvert's own parsing (P4a, which requires provenance separation D4);
- enforcement behaviour (C8);
- the TLS "check the server's reply" logic (C3). It can be prototyped in the detector early, but it belongs with the enforcement phase.

### 6.5 Suggested order

1. #1–#3 in one small change, once Lee has chosen the license.
2. #4–#7 as one detection change in both Python and Go.
3. #8–#13 as the first version of the public package.
4. #14–#20.

Each step is a separate Codex review round on the agreed branch.

---

## 7. Smaller items found along the way (not blockers)

Detector items already in section 6:
- Analyzer retention (R1) is #20.
- The random `Config.Validate` error field is part of #14.
- The Content-Length overflow is #6.

Culvert items, for the Culvert team:
- The `cdr.go` header refers to a Sluice `replace` directive that no longer exists in `go.mod`.
- `dec.sni` (`DecryptionOutcome.SNI`) is never assigned in production; it is only projected at `decryption_observability.go:135`. Fill it from `tls.ClientHelloInfo` as its own fix, not as a side effect of the integration.

## 8. Open decisions for Lee

1. **License:** MIT or Apache-2.0 (#1, B1).
2. **Branch:** `claude/go-migration`, or a new integration branch, for the section 6 work.
3. **First product goal:** visibility only, or the restriction profiles (Codex's open decision 1).
4. **Families in the first profile:** recommended HTTP/1, TLS and SSH, with SMTP as a regression case.
5. **Observing bypassed traffic:** opt-in per rule or decryption profile (recommended), agreed with the Culvert team.
6. **Budgets and quality targets:** accept the C6/C7 proposals as starting points, or set others with the Culvert team.
