# ENGINE-FIELD spec: UDP flow decisions on long flows (CoAP and OpenVPN false positives)

- Kind: **ENGINE-FIELD** (analyzer behaviour, no new parser). Post-merge, Go only
- Status: **READY** for an Engine decision among the options in section 4
- Origin: D09 measurement (`research/d09-iscx-vpn2016.md` 4.4): 13 `openvpn` and 15 `coap` identifications in
  Skype and VoipBuster captures, which carry no such protocol
- Evidence base: the engine's own code on `claude/go-migration` `bc65e50`, plus a random-input measurement in
  scratch; RFC 7252 for CoAP

## 1. Mechanism (from the code)

`protocol_adapters/analyze_pcap.py` `_udp`: every datagram of a UDP flow is passed to `DatagramInspector.inspect`,
and the flow keeps "the first identification" ("Keep the first identification; otherwise the latest outcome
describes the flow"). One chance match in a long flow therefore labels the whole flow, and the label is sticky.

## 2. Measurement (scratch, 2026-11-19)

200,000 uniform random datagrams, seed `20261119`, lengths drawn from {24, 48, 64, 100, 160, 200, 400, 800, 1200}.
This models encrypted proprietary payloads (Skype, VoipBuster), not the real captures. Fed to
`DatagramInspector().inspect(data)` with no hint:

| Identified as | count | per-datagram rate |
|---|---|---|
| `coap` | 27 | 1.35 × 10^-4 |
| `openvpn` (tls-auth hard-reset layout) | 19 | 0.95 × 10^-4 |
| anything else | 0 | |

Per-flow false-positive probability when every datagram is inspected: 1 − (1 − p)^k:

| datagrams in flow (k) | CoAP | OpenVPN | either |
|---|---|---|---|
| 100 | 1.3 % | 0.9 % | 2.3 % |
| 1,000 | 12.6 % | 9.1 % | 20.5 % |
| 10,000 | 74 % | 61 % | 90 % |

VoIP and file-transfer flows run to thousands of datagrams, which matches D09: the identifications concentrate
in long Skype flows, and in 10 Skype captures the falsely labelled flow was the largest.

## 3. Why the validators alone cannot fix it

The CoAP validator already enforces RFC 7252: version 1 ("Implementations of this specification MUST set this
field to 1"), TKL 0 to 8 ("Lengths 9-15 are reserved ... MUST be processed as a message format error"), registered
codes only (section 12.1), reserved option numbers, option length ranges and the payload marker rules. Structural
checks bound p, but no structural check makes p zero for a short binary header on any UDP port. The fix belongs in
how often a flow is allowed to be decided.

## 4. Options (Engine lane decides; the lane's recommendation is A + C)

| Option | Rule | Effect on the measured FP | Cost |
|---|---|---|---|
| **A. Decide on the first datagram per direction** | inspect datagram 1 of each direction; later datagrams only refine an already-identified family | per-flow FP = p (about 1 in 10,000), independent of flow length | a protocol whose first datagram is unrecognisable but whose later ones are (rare for initial-message profiles) is no longer found |
| B. Bounded window | inspect the first N datagrams (for example N = 8) | per-flow FP ≈ N·p | N is a tunable budget, consistent with C8 |
| **C. Weak-family agreement** | for weak families (CoAP, OpenVPN tls-auth, and any family whose random-input rate is above 10^-5), require the same family on 2 consecutive datagrams of the flow before identifying | about p² per window | adds one datagram of latency for those families |
| D. Port gating for CoAP | require 5683/5684 or a hint | removes most CoAP FPs | violates "detection never uses ports" (v0.65); **not recommended** |

## 5. Test vectors

| # | Input | Expected (A + C) |
|---|---|---|
| V1 | a flow of 10,000 random datagrams (seeded) | not identified as `coap` or `openvpn` |
| V2 | the existing CoAP fixtures (`migration/fixtures/cases.json` `datagram/coap*`), as the first datagram | identified, unchanged |
| V3 | a valid OpenVPN client hard reset followed by the server reset (existing fixtures) | identified, unchanged |
| V4 | 500 random datagrams, then a valid CoAP request | not identified under A (first datagram decides); document the trade-off |
| V5 | two consecutive valid CoAP requests in a new flow | identified under C |

The random-input rate table above is the regression metric: rerun it with the same seed after the change.

## 6. Note on Python parity

This changes analyzer behaviour, so the Python reference frozen at merge would differ. By the post-merge policy it
is a Go-only change with its own vectors, and the parity deltas must be recorded (`migration/parity/deltas.json`).
