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
| `Hostname` (TLS SNI, HTTP Host, SMTP client identity) | hostname class: pseudonymize before logging |
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

## 4. Which families Culvert wants in the first visibility profile

**What.** Agreement or changes to the proposal in the working plan (section 13, "Proposal: first profile
families for visibility only"): TLS, HTTP/1, SSH and SMTP identified with evidence, and every other recognised
family named without evidence. That proposal is still awaiting Lee's decision.

**Why.** What Culvert logs, and how it presents names that are not validated.

## 5. Process

- **Interface ownership (5.1).** Confirm that Culvert keeps `internal/protodetect` as its own interface, with a
  thin adapter over `go/detector`.
- **Fuzzing (C4).** Who adds the detector's fuzz targets to Culvert's nightly fuzz matrix, and when.
- **Contact.** Who on the Culvert team answers questions on these items.
