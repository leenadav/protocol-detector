# Input normalization and quality contracts (D06)

Three adapters feed the engine. Each states what it does with input it cannot or will not normalize, and
every session record carries the consequences (`input_quality`, `layers.capture_quality`, and the policy
predicate `capture_quality`), so a flow that lost or rejected bytes never reads as fully inspected.

| input | recorded (PCAP/pcapng, `analyze_pcap`) | host (live tcpdump, `live_capture`) | reassembled (retained tier, TLS decoder) |
|---|---|---|---|
| truncated capture record (snaplen) | counted; a capture gap ends every active observation; a tracked TCP flow named by the record ends with "Capture record truncated; stream bytes missing" | counted; every active observation is retracted (the flow cannot be known safely) | n/a (records never reach it) |
| IPv4 fragment | rejected (`fragment`); the first fragment names its flow, which is marked | same | n/a |
| IP/TCP/UDP length inconsistent | rejected (`length`); the flow is marked when the ports were readable | same | gaps and overlaps are typed reason codes (`gap`, conflict, `budget_exhausted`) |
| IPv6, non-IPv4 link types, other transports | rejected (`network`, `link`, `transport`), counted | same | n/a |
| checksums | policy `--checksums ignore` (default), `audit`, `verify` | same | n/a |

**Checksum policy and offload.** A host capture taken on the sending machine sees transmitted packets
before the NIC computes their checksums, so most of them fail verification although they are correct on the
wire. That is why the default is `ignore` (never computed). `audit` computes IPv4, TCP and UDP checksums,
counts failures (`input_quality.rejected.checksum`), marks the flows, and still inspects the packets: run it
once at a new capture point to learn whether offload is in play. `verify` skips failing packets and marks
their flows; use it only for recorded captures from a tap or SPAN where checksums are known to be final.
An all-zero UDP checksum is "absent", not a failure.

**What a marked flow means.** `input_quality` on a session record counts the rejected or suspect packets by
kind for that flow. Its layered view reports `capture_quality: degraded`, and the policy predicate
`capture_quality` sees `degraded`, so a rule can refuse to allow on partial input. The identification itself
is still whatever the inspected bytes supported (a flow whose first fragment was lost may still be identified
from a later complete segment), which is exactly why the record says the input was not complete.

**Unsupported, explicitly.** IPv4 fragment reassembly, IPv6 and non-IPv4 link types are out of scope; the
counters and the `unsupported` list in every summary's `input_quality` say so rather than inspecting part of
a datagram.
