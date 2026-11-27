# ADR-DRAFT: An in-process protocol detector observes raw relays through internal/protodetect

> **Local draft in leenadav/protocol-detector, not a Culvert document.** It is written in Culvert's ADR format
> (modelled on ADR-0006, ADR-0042 and ADR-0051 at Culvert `main` `ef9431189490f7f85bb32d6fe7e7b6b8be5b0844`, read
> from a read-only clone with push disabled) so that it can be proposed as written once Lee decides to. Nothing here
> has been sent to, pushed to or proposed for KidCarmi/Culvert. Working plan section 12
> (`docs/integration/PROTODETECT-CULVERT-WORKING-PLAN.md`) requires this ADR before anything goes upstream. Task
> PRO-496, 2026-11-27.

- Status: Draft (protocol-detector Culvert Integration lane, 2026-11-27). Not proposed. No Culvert code exists
  outside the local lab branch `lab/protocol-detector-ef94311` (patch `lab/culvert/culvert-lab-ef94311.patch`).
- Numbering: none taken. ADR-0055 is the highest in `docs/adr/` at `ef94311`; the number is chosen when the PR is
  opened, against the open-PR file inventories, as ADR-0042 and ADR-0051 did.
- Relates to: ADR-0006 (engine injected behind a consumer-owned interface), ADR-0051 (admission gate owned by a
  package, gauge injected), ADR-0002 (`internal/` decomposition), ADR-0003 (`obs` seam), ADR-0011 (decryption
  observability), ADR-0042 (`internal/alpnpeek`), ADR-0038 (instance-owned state), ADR-0044 (destination
  pseudonymizer), ADR-0037 (shutdown and drain), ADR-0025 (advisory, never enforcing), ADR-0013 (scope note below).
- Product scope: **visibility only** (Lee, 2026-11-17, working plan decision 3). The detector identifies and the
  proxy logs; nothing blocks, restricts or reroutes traffic. First profile TLS, HTTP/1, SSH and SMTP with
  evidence; every other recognised family named only, as unvalidated (decision 4, 2026-11-18).

## Context

CONNECT tunnels that Culvert does not decrypt (`handleTunnelBypass`, `proxy_tunnel.go`) are relayed as raw bytes
by `bidiRelayCounted` → `relayCounted` → `idleCopyCounted`, which hands the copy to `io.Copy` and so to splice for
TCP↔TCP. For that traffic Culvert records the destination and the byte counts and nothing about what the tunnel
carries. A tunnel to port 443 may carry TLS, SSH, plain HTTP or anything else, and the `dec` block of ADR-0011
says only `not_decrypted` / `manual_ssl_bypass`.

Culvert already runs in-process engines. `internal/yara`, `internal/clamav` and `internal/scanner` are leaves
that `internal/secscan` orchestrates through interfaces the orchestrator owns (ADR-0006), and the scan sidecar's
admission is a package-owned gate with a gauge the composition root injects (ADR-0051). This ADR applies the same
two patterns to a protocol detector, with three differences that make it a new decision rather than another
extraction:

1. **The engine is an external module.** `github.com/leenadav/protocol-detector/go`, package `detector`
   (Apache-2.0). Every earlier engine was Culvert code moved under `internal/`. Sluice (CDR) is external but runs as
   a gRPC sidecar.
2. **It sits on the raw relay path.** The scan engines see buffered bodies on the inspect path; this one sees the
   first bytes of a bypassed tunnel inside the copy loop, where a stall or a panic would affect the tunnel itself.
3. **It parses untrusted bytes Culvert did not choose to parse.** The bytes are attacker-controlled in both
   directions, so the engine's byte, feed, memory and flow budgets are part of Culvert's safety case, not tuning.

ADR-0013 (no local analyzer framework) does not apply: it scopes the support subsystem's diagnosis of the
appliance. The detector classifies traffic, keeps no knowledge base and runs no model. It does carry a content pack
(server-name catalog), so the dynamic-update question is listed under open items.

Evidence that the design works is local only: a lab build of Culvert `ef94311` plus the four-commit lab patch,
74 of 74 observation checks, Culvert's tunnel, relay and drain tests plus the lab tests (198 under `-race`), and
two load-test runs (section 4 below). The lab wires everything by environment variable and package globals on
purpose; the decision below states what the product shape changes.

## Decision

### 1. `internal/protodetect` owns the interface; the detector is injected (ADR-0006)

- **Culvert owns the contract.** `internal/protodetect` defines `Observer` (`Begin`, `Stats`, `Name`) and `Flow`
  (`Observe`, `End`, `Expire`, `Finish`) next to its consumer, the relay, as ADR-0006 put `clamScanner` and
  `yaraMatcher` next to the orchestrator. The detector library exports no interface for Culvert.
  Lab: `internal/protodetect/protodetect.go` (interface, `Record`, `Stats`, the scripted `Fake`).
- **One adapter file holds the library.** `real.go` is the only file that imports `detector`, with a compile-time
  assertion that `*Real` implements `Observer`. A library API change stays inside that file. Lab:
  `internal/protodetect/real.go` (`NewReal`, `realFlow`; the nine library calls listed in PRO-107).
- **Three engines, one interface.** Off is a nil `Observer`: the relay calls the unmodified
  `bidiRelayCounted`, byte for byte. `Fake` scripts identification and injected panics for lifecycle tests. `Real`
  wraps the library.
- **Constructor injection, instance-owned (ADR-0006 Slice 2, ADR-0038).** The composition root builds one
  `Observer` from the configuration and passes it to the tunnel handler. The lab's package variables
  (`labObserver`, `labWindow`, `labHandoffs` and the `sync.Once` in `protodetect_lab.go:37-77`) and its
  environment variables are lab scaffolding and are replaced, not carried over.
- **The package decides nothing.** It never touches a socket and never makes, changes or delays an access
  decision. Every result is an observation (ADR-0025: advisory, never enforcing).

### 2. Admission is a package-owned gate with an injected gauge (ADR-0051)

- `Begin` either admits a flow or refuses it at once. **It never waits**: unlike the scan sidecar's 5 s bounded
  wait (ADR-0051 `QueueWait`), a relay must not stall on observation, so a refused tunnel relays unobserved on the
  unmodified path.
- The cap is the detector's `Config.MaxFlows` plus its memory allowance (`MaxRetainedTotal`, default MaxFlows ×
  32 KiB). A refusal on either is counted (`refused`, `refused_memory`, `refused_limit` in `detector.Engine`'s
  atomics, `go/detector/detector.go:87-93`).
- The in-flight gauge that `/metrics` reads is a `*atomic.Int64` passed in by main, as ADR-0051's
  `Options.Inflight`, so the gate stays its only writer and the reader needs no handle.
- **A refusal is still logged** (lab SEC-CULV-1 fix, `protodetect_lab.go:242-247`): the record says
  `"admission":"refused"` with reason `admission_refused`, so a saturated cap is visible, never silent.
- **The slot is held for the observation window only, never for the tunnel's life** (SEC-CULV-1): the flow is
  finished at window end or when both directions have handed off, whichever is first
  (`TestLabWindowEndReleasesAdmissionWhileTunnelsStayOpen`, `TestLabHandoffReleasesAdmissionBeforeTheWindowEnds`).

### 3. The tap is a phase of `idleCopyCounted`, then splice resumes

- One function keeps owning the read deadlines: the observed copy runs inside the relay's loop with a 4 KiB
  per-direction read buffer (never the 128 KiB relay pool), **writes each chunk to `dst` first, then feeds the
  engine**, and once the direction is done, expired or out of budget it calls the original
  `idleCopyCounted(dst, src, …)` so splice carries the rest. Lab: `labBidiRelay`, `labRelayCounted`,
  `labObservedCopy` (`protodetect_lab.go:145-235`), hooked at `proxy_tunnel.go:720-743`.
- A short write is `io.ErrShortWrite` at both write sites (lab commit 3 of 4).
- `Expire` is driven by `time.AfterFunc` and touches only the flow's own state, so it is safe while a direction is
  blocked in `Write`. The tap buffer is released when that call returns (bounded at 4 KiB per direction).
- **Known lab gap, to close before the PR:** the tap stamps the shared idle clock per read, the unmodified loop
  when its copy returns (Codex advisory point 4). The product tap must match the unmodified stamping or change it
  deliberately with `proxy_tunnel_idle_test.go` coverage.
- **Panic containment sits inside the tap.** The library quarantines a flow on an engine panic
  (`ErrQuarantined`, `go/detector/detector.go:22`); the adapter also recovers, so a detector panic ends the
  observation, never the tunnel (it must not reach `relayCounted`'s recovery, which closes both connections).
- Observed tunnels stay in the existing drain classes (ADR-0037); observation adds no goroutine to drain.

### 4. Alignment with existing ADRs

| ADR | How this complies | Where (lab patch at `ef94311`) |
|---|---|---|
| ADR-0002 | `internal/protodetect` never imports `package main`; the relay hook and the record projection stay in main as composition. The one new import outside Culvert is the detector module, whose `detector` package imports only the standard library, checked by `TestDetectorImportsStandardLibraryOnly` on linux/amd64, linux/arm64, darwin/arm64 and windows/amd64 (protocol-detector `go/detector`). This is the "fresh recorded design" ADR-0002 requires for new extractions. | `internal/protodetect/protodetect.go` imports only `sync`, `sync/atomic`; `real.go` imports `detector` |
| ADR-0003 | No logging inside `internal/protodetect` or the library; the composition root logs through `obs`/`logger`. Hostnames are not logged as free text. | `protodetect_lab.go:69-75` (start-up line in main); the library has no logger |
| ADR-0011 | Observation never changes the traffic decision; off is byte-identical (`nil` block, block-level `omitempty`); closed vocabularies only as labels, host and SNI as record fields; HMAC pseudonymization at `persistLogEntry`; no new hot-path lock; the allocation budget is amended in section 4 of this decision, not ignored. | `labFinishObservation` (`protodetect_lab.go:237-277`); the `pd` block shape from the first lab (`culvert-lab-52eb9d1.patch`, `ProtoDetectBlock` on `Entry`) |
| ADR-0042 | `alpnpeek` keeps the ALPN parse that routing uses, and main keeps the peek window and the `["http/1.1"]` fallback. The detector's TLS parse never feeds routing (section 5). | the lab reads the relay's bytes only; `peekClientALPN` is untouched |

### 5. The log block: `pd` on `TUNNEL_CLOSED`

- **Shape.** `Entry.PD *ProtoDetectBlock` with `json:"pd,omitempty"`, riding the same structured carrier as
  `Dec` (`store.go:349`). Absent when the tunnel was not observed, so the wire stays byte-identical with
  observation off. The first lab built exactly this (`culvert-lab-52eb9d1.patch`: `internal/logstore`,
  `store.go`, `persistLogEntry`); the current `ef94311` lab writes a separate `PROTODETECT` log line instead
  (`protodetect_lab.go:264-275`), which the product does not keep.
- **`schema_version`** (int, non-`omitempty`): independent of `dec_schema_version`, starting at 1. A field change
  bumps it.
- **Fields, per direction (`client`, `server`):** `outcome`, `reason`, `family`, `protocol`, `encryption`,
  `hostname`, `offered_alpn` (at most 16, with `offered_alpn_truncated`), `evidence` (field, value, source,
  strength, class; unclassified values withheld by the library), `detail` (bounded sentence, record only),
  `observed_bytes`. **Per tunnel:** `engine`, `admission` (`admitted` | `refused`), `quarantined`, `signals`
  (`nonstandard_port`, `host_mismatch`, `server_unresolved`: advisory, not verdicts), `forwarded_bytes` stays
  the entry's existing counters.
- **Enum package.** The closed values live in a small `internal/pdobs`, modelled on `internal/decryptobs`:
  `Outcome` (the library's ten: `detecting`, `identified`, `unknown`, `malformed`, `incomplete`,
  `budget_exhausted`, `invalidated`, `unsupported`, `outside_profile`, `failed`, plus Culvert's `unobserved`),
  `Reason` (the library's nine plus `admission_refused`), `Admission`, `Signal`; each with `All…`, `String`,
  `Valid` and an exhaustiveness test against `detector.AllOutcomes()` / `AllReasons()`
  (`go/detector/vocab.go:63-103`), so a library vocabulary change fails Culvert's build, not its dashboards.
  A value outside the set is projected as `other`, never passed through.
- **Labels.** Only `outcome`, `reason`, `admission`, `signal` and `family` (bounded registry) may be metric
  labels. `hostname`, `detail`, `evidence` and ALPN values are record fields only.
- **Redaction and HMAC.** `hostname` and every evidence value of class `hostname` are pseudonymized with the keyed
  HMAC of ADR-0044 (`redactDestinationHost` / `pseudonymizeHost`) under the same `decryption_redact_hosts`
  posture, applied at the `persistLogEntry` chokepoint so the top-level `host`, `dec.host` and `pd.*.hostname`
  carry the identical token, and fail-closed to the `redacted` sentinel when the key is missing. `host_mismatch`
  is computed on the unredacted values before redaction (SEC-CULV-2,
  `TestLabHostMismatchIsComputedBeforeRedaction`) and logged as a signal that carries no host. All strings pass
  `sanitizeLog`/`auditSafe` before any log, audit or alert projection.
- **Rules that do not log traffic log no observation** (`ruleLogsTraffic`, `protodetect_lab.go:250-252`).
- **Application naming.** The detector supplies the protocol family. If an application name is ever carried, one
  source is authoritative per field (proposed: Culvert's SaaS feed for the application, the detector for the
  protocol; Culvert team request item 4). See the forward-compatible note in section 7.

### 6. Allocation and lock budget amendment to ADR-0011 §4

ADR-0011 §4 sets **≤ 1 heap allocation per session and no new hot-path lock** for the `dec` block. That budget
cannot hold for a parser of untrusted bytes, so this ADR amends it for the `pd` path only, with numbers measured in
the lab. All figures are local CPU work on a shared 4-vCPU container (Go 1.27.4), not production latency.

**Off (observation disabled): unchanged.** Zero added allocations and no lock: a nil `Observer` takes the
unmodified relay. Measured: lab build B against unmodified A, HTTPS p50 −59 to +4 µs and CPU −0.06 to
+0.09 CPU-s per 1,000 flows (`docs/integration/LOAD-TEST.md`, commit `e91e1b5`, PR #118); p50 −0.04 to
+0.01 ms at 200 and 500/s (`docs/integration/LOAD-TEST-SPLIT.md`, commit `1f3e94f`, PR #120). A benchgate for
"CONNECT bypass, observation off" pins this.

**On (observe mode), proposed ceilings:**

| Budget | Proposed | Measured | Source (commit) |
|---|---|---|---|
| Allocations per observed flow, whole flow through the library | ≤ 110 TLS, ≤ 95 HTTP, ≤ 65 SSH, ≤ 15 unknown (the library's own gate, `TestFlowAllocationBudget`) | TLS 89 (~13.9 KB), HTTP 76, SSH 53, unknown 11 | `go/detector` `BenchmarkFlow`, PRO-148 commit `2fdc5e9`; `docs/integration/ENGINE-DRIFT-2026-11-21.md` |
| Engine core per flow (benchgate workloads) | ≤ 64 (working plan section 9) | 10 to 38 | engine `0081f6f`, `TestBenchGate_AllocationsPerFlow`, PRO-82 |
| `pd` record projection | ≤ 2 more than `dec`'s (1, or 2 when pseudonymized) | not yet measured as a Culvert benchgate | to add with the PR |
| For comparison: Culvert, one whole proxied HTTP request | — | 82 (gate 85) at `ef94311` | `TestBenchGate_HTTPForwardAllocs` |
| Proxy CPU per 1,000 HTTPS flows | report, no gate yet | +0.15 to +0.22 CPU-s (100/300/600 req/s); +105 to +277 ms (200/500 req/s, about 15 to 26 %), split about half lab observation path (fake engine, C − B: +59 to +71 ms) and half engine (D − C: +67 to +100 ms) at 500 and 1,000/s | `LOAD-TEST.md` (`e91e1b5`); `LOAD-TEST-SPLIT.md` §3.3 (`1f3e94f`); raw data `lab/culvert/results-loadtest/`, `results-load/`, `results-load-split/` |
| Added latency, HTTPS through a CONNECT bypass | report, no gate | p50 +5 to +113 µs, p95 +84 to +424 µs, p99 within noise (100 to 600 req/s); p50 +0.07 to +0.11 ms at 200 and 500/s | same two runs |
| GC cycles per 1,000 flows | report | +2.5 to +3 (B 1.73, C 2.87, D 4.67 at 500/s) | `LOAD-TEST-SPLIT.md` §3.3 (`1f3e94f`) |
| Tap read buffer while observing | 4 KiB per direction | 4 KiB (`labTapBufSize`) | lab `protodetect_lab.go:31` |
| Retained per tunnel after the window | ≤ 4 KiB (working plan section 9) | +3.9 KiB per tunnel over B, 1,000 held tunnels (RSS upper bound) | `LOAD-TEST-SPLIT.md` §3.4, `lab/culvert/results-load-hold/hold.json` (`1f3e94f`) |
| Library retained bytes per flow | ≤ the 32 KiB flow allowance, zero after `Finish` | peak 4,112 B across the fixtures | `docs/integration/CULVERT-TEAM-REQUEST.md`, "Allocation budget gap" |
| Observed bytes / feeds per direction, window, concurrent flows | 16 KiB / 16 / 10 s / 4,096 (starting hypotheses) | used in both runs (window 3 s for the rate runs of the second) | `LOAD-TEST-SPLIT.md` §4 |

Measurement context: Culvert `ef9431189490f7f85bb32d6fe7e7b6b8be5b0844` plus `lab/culvert/culvert-lab-ef94311.patch`;
detector `go/` at protocol-detector `main` `593f6a467199d15fcdb9d441d4cadff8aa78d417` through `go.work`; vegeta
v12.12.0, one connection per request. 1,000 req/s saturates that harness with or without the detector, so no
figure at that rate is a detector cost.

**Locks.** No process-wide lock is added. Each observed flow has one `sync.Mutex`
(`go/detector/detector.go:248`) taken by `Observe`, `End`, `Expire` and `Finish` of **that flow only**: it is
contended by at most the flow's two relay directions and its window timer. Engine counters and the admission
gauge are atomics. The unobserved relay and every other tunnel take no new lock. The amendment therefore reads:
"no new process-wide lock on the hot path; one uncontended-by-design per-flow lock while a tunnel is observed".

**Not measured yet, required before acceptance:** 1,000 concurrent flows each holding their full 16 KiB prefix,
the blocked-write case, and a Culvert benchgate for "CONNECT bypass, observation on" (the comparable whole-tunnel
figure neither side gates today).

### 7. One authoritative TLS fact source

- **Routing has one source: `alpnpeek`.** The h2 / http/1.1 decision (`peekClientALPN`, ADR-0042) and every
  existing TLS fact Culvert reads (`tls.ConnectionState` on the inspect path, the `dec` block) stay as they are.
  The detector's TLS parse is never read by routing, decryption, the autoexclude classifier or policy.
- **The detector's facts are observation only**, labelled with their provenance and never presented as Culvert's
  own facts. Where both parse the same ClientHello, a differential test compares only the shared ALPN facts over
  a defined input domain and records expected acceptance differences instead of weakening either parser
  (working plan 5.3).
- **A later facts-only phase** (Culvert passes the facts it already parsed; provenance `culvert_facts`, never
  counted as a raw-parser classification) needs Culvert's answer to team request item 1 and is not part of this
  decision.
- Related Culvert finding, its own change: `DecryptionOutcome.SNI` is declared and redacted but never assigned in
  production (`decryption_observability.go:43`, `:135`); the `pd` block does not depend on it.

### 8. Kill switch, canary and abort criteria (working plan section 12)

- **Kill switch.** One setting, `protodetect_observe` (off by default), registered in `config_surfaces.go` with
  `AdminDurable: true` and `ClusterSynced: true` and the export, snapshot, API and GUI decisions that file
  requires. It takes effect without a restart: new tunnels are not observed, and existing observations are
  released by their own window (at most 10 s) without closing any tunnel. Bypassed traffic is observed only where
  a rule or decryption profile opts in (working plan section 11).
- **Canary.** Enabled first on one node group (`internal/nodegroup`), with the off group as the live control;
  widened only after a clean canary period with the abort criteria checked.
- **Abort criteria** (any one stops the run and turns the switch off): byte corruption; a changed access
  decision; an uncontained failure (a detector panic reaching the relay, a tunnel closed by observation); a
  redaction failure (a plaintext destination in any sink while redaction is on); unexplained retained growth;
  an exceeded threshold from section 6.
- **Automatic admission shutdown** (a breaker on panics or refusals) may switch observation off with visible
  diagnostics. Because this phase is visibility only, it never affects traffic.
- **Recovery** is always available without the detector: switch off; restart the binary with the baseline
  configuration.

### 9. Forward-compatible field note: parent and child applications (PRO-492)

The engine lane is adding an enterprise App-ID model with child applications per function (for example
`gmail-uploading`, `whatsapp-file-transfer`; Engine PRO-492, fed by App Research PRO-495). This ADR does not add
those fields. It reserves their shape so that adding them is a `schema_version` bump, not a redesign:

- per direction, optional `app` (parent application id) and `app_child` (child id), both from the content pack's
  closed id set, `omitempty`, record fields, never labels until their cardinality is bounded;
- each carries its content release (`content_release`) so a record names the pack it was matched against;
- a child is only reported when its documented signals were observed; on the raw bypass path, where no HTTP
  method or path is visible inside TLS, only host-based parents are possible, and child functions need the inspect
  path (a separate decision).

## Open items

1. **Licence (decision 1, Lee's).** The detector repository is Apache-2.0 (Lee, 2026-11-17; commit `74638c4`,
   `LICENSE` and `NOTICE` at the root and in `go/`); Culvert is MIT. Whether Culvert accepts an Apache-2.0
   in-process dependency, with its NOTICE obligation in Culvert's distribution, and on what contribution terms, is
   Lee's decision with the Culvert maintainers. Culvert's `go-licenses --disallowed_types=forbidden,restricted`
   gate (`pr-deep-gate.yml`) does not refuse Apache-2.0.
2. **Unsigned tags.** No `go/v0.x.y` tag exists (procedure adopted 2026-11-18, `docs/governance/RELEASE-TAGS.md`;
   none created). Culvert would pin a pseudo-version of an untagged commit, which its dependency review should not
   accept. A signed tag, govulncheck, SBOM and provenance come first (working plan section 12).
3. **Content-pack updates.** The pack is embedded in the module. Any dynamic update needs signed content with
   anti-rollback first (working plan section 12); until then a pack change is a module version bump.
4. **Budgets.** Culvert's acceptance of the section 6 numbers (team request item 3), and the three measurements
   listed there as not yet taken.
5. **Idle-clock parity** of the tap (section 3), and a Culvert `AGENTS.md` route for `internal/protodetect`.

## Tests (to come with the implementation PR)

From the lab, kept with their names: `TestLabWindowEndReleasesAdmissionWhileTunnelsStayOpen`,
`TestLabHandoffReleasesAdmissionBeforeTheWindowEnds`, `TestLabRefusedAdmissionIsLogged`,
`TestLabHostMismatchIsComputedBeforeRedaction`, `TestLabSignalsCompareHostsPortNormalised`,
`TestLabHoldNeverExceedsItsBudget` (first lab). New: off-path byte identity of the `Entry` JSON; the `pd` block's
redaction across every sink with the key present and missing; `internal/pdobs` exhaustiveness against the library;
a package boundary test (no `package main` import, no `init`, no I/O or logging imports in
`internal/protodetect`) with negative controls; the pipelined-bytes tests on every tapped path; the injected-panic
matrix of the fake engine; `proxy_tunnel_idle_test.go` parity; and the benchgates of section 6.

## Consequences

- Bypassed tunnels gain a bounded, redacted protocol record with no change to forwarding, splice, policy or
  drain, and with observation off the binary behaves and logs exactly as today.
- Culvert takes its first external in-process module on the relay path. Its supply chain (licence, signed tags,
  govulncheck, SBOM) becomes part of Culvert's review, and a library vocabulary change is caught by the
  exhaustiveness tests at build time.
- The ADR-0011 budget gets a documented exception for the `pd` path, with ceilings and the measurements behind
  them, instead of an unrecorded one.

## Alternatives considered

- **A sidecar, like Sluice.** Rejected for this use: the observation needs the first bytes of every bypassed
  tunnel inside the copy loop; a network hop per tunnel would cost more than the engine and add a failure mode to
  the relay.
- **A wrapper `Reader` around the connection.** Rejected: a second reader breaks splice and splits deadline
  ownership away from `idleCopyCounted`.
- **Reuse `alpnpeek` and grow it into a classifier.** Rejected: it is an import-free ALPN leaf by design
  (ADR-0042); protocol classification across families is a different engine with its own budgets.
- **Log a separate line (the current lab).** Rejected: it escapes the one-schema-all-surfaces rule of ADR-0011
  and the `persistLogEntry` redaction chokepoint.
