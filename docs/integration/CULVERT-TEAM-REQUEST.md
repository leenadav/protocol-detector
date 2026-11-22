# What the detector side needs from the Culvert team

Written 2026-11-17 for the Culvert team, from the protocol-detector side of the working plan
(`docs/integration/PROTODETECT-CULVERT-WORKING-PLAN.md`, section 6.4 "Wait for Culvert"). It has not been sent:
Lee decides how it reaches the Culvert team. Nothing in this repository has been proposed to, or pushed to,
KidCarmi/Culvert.

**Scope, decided by Lee on 2026-11-17: visibility only.** The detector identifies and Culvert logs; nothing
blocks or restricts traffic. Enforcement (plan section 10, phase L7) is out of scope, so this request asks
nothing about actions, verdicts or TLS server corroboration.

Each item says what we need, why, the form of answer we can use directly, and what stands in for it meanwhile.
None of the stand-ins invents a Culvert number or a Culvert type.

**Revision of 2026-11-21 (PRO-81):** the anchors below were checked at Culvert `main`
`ef9431189490f7f85bb32d6fe7e7b6b8be5b0844`, a descendant of the lab's first base `52eb9d1` (101 first-parent commits, mostly pull-request merges, later). The local
lab was moved to that commit. New sections: "Culvert anchors at `ef94311`", "Found while moving the lab to
`ef94311`" and "Allocation budget gap".

## Culvert anchors at `ef94311`

| What | Where |
|---|---|
| CONNECT-bypass handler, where the raw-stream tap sits | `proxy_tunnel.go:668` `handleTunnelBypass` |
| Bytes the HTTP server already buffered (the prebuffer the tap must show the engine) | `proxy_tunnel.go:724` |
| The relay the tap replaces for its window | `proxy_tunnel.go:736` `bidiRelayCounted(destConn, clientConn, clientConn, destConn)` |
| The copy loop the tap hands back to (splice path) | `proxy_tunnel.go:407` `idleCopyCounted`, unchanged since `52eb9d1` |
| Relay panic recovery | `proxy_tunnel.go:460` `relayCounted`, unchanged since `52eb9d1` |
| Shutdown drain registration, new since `52eb9d1` (CHAOS-57) | `proxy_tunnel.go:716` `registerDrainableTunnel(tunnelClassConnectBypass, ...)` |
| The `TUNNEL_CLOSED` record of a bypass tunnel | `proxy_tunnel.go:742` `recordTunnelCloseGatedDec` |
| Upstream TLS state on inspect paths (facts, item 1) | `proxy_tunnel.go:1106` `upstreamTLS.ConnectionState()` |
| Culvert's ClientHello ALPN parser (facts and comparison, item 1) | `internal/alpnpeek/alpn.go:21` `Parse` |
| Decryption record and its host/SNI redaction (log block, item 2) | `decryption_observability.go:43` (`SNI` field), `:135` (projection), `:489` `redactHost`; ADR-0011 |
| Destination pseudonymizer | ADR-0044 |
| SaaS feed categories (taxonomy, item 4) | `internal/saasfeed/saasfeed.go:52` `Category{Name, Hosts}` |
| SOCKS5 scope | `socks5.go:57`: CONNECT only, UDP ASSOCIATE unsupported |

## 1. Facts on the inspect paths (plan 5.3, phase L2)

**What.** For each place Culvert already parses traffic, which facts it can hand to the detector, and at which
hook:
- TLS, per leg (client to proxy, proxy to origin): the SNI as sent; the client's ALPN offer in order, from
  `alpnpeek` or the ClientHello Culvert read; the negotiated version, cipher suite and ALPN from
  `tls.ConnectionState`, once the handshake completed.
- HTTP: for HTTP/1, the request's method and Host, and whether the connection is kept alive; for HTTP/2, the
  stream id with `:method` and `:authority`.
- For each fact: whether "absent" means "not sent" or "not read". These differ, and the detector keeps them
  apart.

**Why.** The plan requires one parse per decision: in inspect paths the detector either uses Culvert's facts or
both parsers run under a differential harness (B3, 5.3). Without the list, the detector cannot fix its facts
input.

**Answer we can use.** A table of hook, fact, Go type and the meaning of "absent", or comments on our strawman:
`go/internal/facts` (internal, so it binds no one). It fixes only what the plan already requires: provenance
`culvert_facts`, which never counts as a raw-parser classification; the two legs kept apart; offered and
negotiated values in separate fields; every value bounded and validated, and nothing the caller passed
retained.

**Also needed for the comparison (5.3).** The input domain on which `alpnpeek` and the detector's TLS parser
should agree, and the acceptance differences Culvert already knows of, so they are recorded rather than "fixed"
in either parser.

**Meanwhile.** Raw-stream observation on the CONNECT bypass path (phase L1 to L4) works without facts; the lab
covers it.

## 2. The log block (B4, ADR-0011)

**What.**
- The block's name and its `schema_version` scheme.
- Which Culvert entries carry it: `TUNNEL_CLOSED`, request entries, or others.
- Where its closed vocabularies live (the enum package).
- The redaction rule for hostname-class values.

**Why.** ADR-0011 already governs this block; the detector side must produce exactly what it allows and nothing
more.

**Answer we can use.** The ADR section or a field list with types.

**Meanwhile.** What the detector can supply is fixed by the public package, so it needs no Culvert input. The
inventory below gives each field's class, so the block can be laid out against it. The lab's `pd` block
(`lab/culvert/README.md`) is one possible layout, for illustration only.

| Field (`detector.Snapshot`, per direction) | Class |
|---|---|
| `Outcome`, `Reason`, `Direction` | closed vocabulary: safe as a metric label |
| `Family`, `ApplicationProtocol`, `Encryption`, `Scope` | bounded registry names: record field, low cardinality |
| `Hostname` (TLS SNI, HTTP Host, SMTP client identity) | hostname class: pseudonymize before logging (ADR-0044) |
| `OfferedALPN` (at most 16), `OfferedALPNTruncated` | bounded list from the client's offer: record field |
| `Evidence` (field, value, source, strength, class) | bounded; values of unclassified fields are withheld by the package |
| `Detail` | bounded engine sentence: record only, never a label |
| `Revision`, `BytesFed`, `BytesInspected`, `Done` | counters and flags |
| `Snapshot.Quarantined`, `Snapshot.RetainedBytes` | flow health |

## 3. Budget numbers (plan section 9, C7)

**What.** The values Culvert accepts for:
- observed bytes per direction;
- feed calls per direction;
- the observation window;
- concurrent observed flows (the admission cap);
- retained bytes per flow and in total;
- CPU and allocations per flow;
- the allocation and lock budget amendment the plan expects in a Culvert ADR (section 12).

**Why.** The detector's defaults are the plan's starting hypotheses: 16 KiB, 16 feeds and a 32 KiB flow
allowance by default (`detector.DefaultConfig`). They are not Culvert's numbers.

**Answer we can use.** One number per budget, or a range, plus the measurement Culvert wants before accepting
it.

**Meanwhile.** Every budget is a `detector.Config` field the adapter sets. No detector change is needed to apply
Culvert's numbers, and the detector does not guess them.

## 4. Families and the application taxonomy

**What.** Agreement with the first visibility profile, which Lee approved on 2026-11-18 (working plan section 13):
TLS, HTTP/1, SSH and SMTP identified with evidence, and every other recognised family named without evidence.
Also which taxonomy names the application. Culvert's SaaS feed gives host-list categories
(`internal/saasfeed/saasfeed.go:52`, `Category{Name, Hosts}`). The detector gives the protocol family, plus an
application from its own content pack. Two application labels on one record would conflict, so one must be
authoritative; we propose the SaaS feed for the application and the detector for the protocol.

**Why.** What Culvert logs, and how it presents names that are not validated.

## Found while moving the lab to `ef94311`

- **`DecryptionOutcome.SNI` is never assigned in production.** The field is declared at
  `decryption_observability.go:43` and projected, with redaction, at `:135`. None of the eight constructors sets
  it: `decryption_observability.go:179`, `:211`, `:233`, `:311`, `:348` and `:437`, and `proxy_tunnel.go:626` and
  `:971`. The `dec.sni` field is therefore always empty in the record, while the redaction posture
  (`decryption_redaction.go:218`) lists it in scope. This was first seen at `52eb9d1` and is unchanged. It is
  Culvert's to fix, as its own change: fill it from `tls.ClientHelloInfo` where the handshake is read. The
  detector does not depend on it.
- **The tap point keeps its shape.** `idleCopyCounted` and `relayCounted` are unchanged, so the lab's observed copy
  still mirrors Culvert's deadline and idle-stamp mechanics. The new shutdown drain (`proxy_tunnel.go:716`)
  closes both connections on its deadline. The tap's window then ends with the relay; the detector's `Expire`
  touches no socket. The lab's three hook commits re-applied with no conflict.
- **No UDP path.** SOCKS5 still offers CONNECT only (`socks5.go:57`), and nothing carries QUIC. HTTP/3 traffic is
  therefore outside what Culvert can observe or the detector can see. Item 6 below asks how Culvert wants that
  stated.

## Allocation budget gap

Measured 2026-11-21 on the cloud container (4 vCPU, shared, Go 1.27.4). These are local CPU figures, not production
latency. **Corrected 2026-11-21 (PRO-91):** the detector has two figures, and the earlier text gave only the first.
They measure different things; `docs/integration/ENGINE-DRIFT-2026-11-21.md` has both tables with their commands.

| Cost | Allocations | Bytes | Source |
|---|---|---|---|
| Detector engine core, one flow, benchgate workloads | tls_whole **33**, tls_fragmented 37, http_small 26, http_fragmented 38, ssh_banner_kexinit 34, unknown_16x1KiB 10 | 1,032 to 34,210 B on the trial merge (not reported at `0081f6f`) | engine `claude/go-migration` `0081f6f`, `go test -tags benchgate -run TestBenchGate_AllocationsPerFlow ./internal/bench`; Research Lab, PRO-82, median of 5 |
| Detector through the public package, one whole TLS flow (`NewFlow`, client and server flights, `Close`) | **89** (191 before PRO-148) | about 13,900 B | lane, PRO-148 commit; `go/detector` `BenchmarkFlow/tls`; gate `TestFlowAllocationBudget` ceiling 110 |
| Detector through the public package, HTTP / SSH / unknown flow | 76 / 53 / 11 (before: 128 / 89 / 15) | about 7,800 / 6,150 / 2,288 B | same benchmark |
| Culvert, one proxied HTTP request (whole forward) | **82** (gate 85) | 10,729 B | `TestBenchGate_HTTPForwardAllocs` |
| Culvert, policy evaluation at 10 to 10,000 rules | 0 (gate 4) | — | `TestBenchGate_PolicyEvalAllocs` |
| Culvert, decryption record | 1, or 2 when pseudonymized (gates 1, 2) | 320 to 336 B | `TestBenchGate_DecryptionProjectionAllocs` |
| Culvert, bypass relay residency per direction | — | 611.5 B (ceiling 4,096) | `TestBenchGate_RelayBufferResidency` |
| Culvert, inspected tunnel read buffers | — | 65,747 B (ceiling 81,920) | `TestBenchGate_InspectReadBufResidency` |

Culvert's gates run with `go test -tags benchgate` (`pr-fast-gate.yml`, job `benchgate`), outside the default test
build.

What the gap means:
- **The engine core fits the working plan's hypothesis of at most 64 allocations per flow (section 9):** 10 to 38 on
  the benchgate workloads. The engine lane gates it at 64 (PRO-80).
- **The public package is closer now.** A whole TLS flow through it costs 89 allocations, down from 191 (PRO-148:
  closed-vocabulary and engine-composed strings are no longer copied, and unchanged values are no longer copied
  again on every revision). That is about 1.1 times Culvert's whole proxied HTTP request, and it covers two
  directions of engine work. Further work waits for Culvert's budget.
- **Residency is not the gap.** The detector's retained bytes peak at 4,112 per flow across the fixtures, inside its
  32 KiB allowance, and drop to zero at `Close`. After the window, the tunnel is back on `idleCopyCounted`, whose
  611.5 B/direction is unchanged. During the window, the lab's tap buffer is 4 KiB per direction, the size of
  Culvert's relay ceiling.
- **Neither side gates the observed tunnel as a whole yet.** A Culvert benchgate for "CONNECT bypass with
  observation on" would be the comparable figure.

What we need from the Culvert team (item 3):
- the per-flow allocation and CPU budget they will accept for an observed tunnel;
- whether it is measured on the whole tunnel or on the detector call alone;
- whether the gate joins `benchgate`.

The detector will not tune toward a number Culvert has not set.

## 5. Process

- **Interface ownership (5.1).** Confirm that Culvert keeps `internal/protodetect` as its own interface, with a
  thin adapter over `go/detector`.
- **Fuzzing (C4).** Who adds the detector's fuzz targets to Culvert's nightly fuzz matrix, and when.
- **Contact.** Who on the Culvert team answers questions on these items.

## 6. UDP and HTTP/3

**What.** Whether Culvert wants the visibility phase to state HTTP/3 (QUIC) as out of view, or to steer clients to
TCP, for example by refusing QUIC at the network edge.

**Why.** The detector observes only what Culvert relays, and Culvert relays no UDP (`socks5.go:57`). A dashboard that
shows protocol mix without saying so would overstate coverage.
