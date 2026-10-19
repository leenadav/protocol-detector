# Review scope: protocol detector v0.18

Python 3.9-compatible IPv4-only bounded protocol classification: 38 families,
34 automatic, narrow profiles documented in PROTOCOLS.md. Review protocol_engine/,
sessions.py and both capture adapters for correctness and CPU/memory bounds.

New focus: DCE/RPC connection-oriented 5.0 unauthenticated Bind. Both byte orders,
nonempty bounded presentation contexts, unique context IDs, zero reserved fields,
exact NDR 2.0/NDR64 1.0 wire identifiers/versions and complete-frame checks.
Transfer syntaxes are only offers; no interface/product identity or endpoint
negotiation claim. Unknown syntaxes, bind-time feature negotiation, authentication
verifiers, responses and stub decoding remain excluded. Check two-byte SOCKS/RPC
dispatch, explicit hints, length/count bounds and partial-prefix behavior.

GIOP 1.2 KeyAddr Request/LocateRequest and native Git framing remain in review.
Earlier fixes validate leading overlaps, preserve PCAP truncation with retractions,
reject reserved IPv4 flags and emit directional control invalidation. FIN/payload
ends share coordinates. No multiple-epoch or endpoint receive-window validation.

270 installed tests pass, including independent endian fixtures, all cuts/bytewise,
1,600 DCE/RPC mutation fragmentation comparisons, negatives, budgets and SOCKS5
compatibility. Actual local synthetic IPv4 capture:155 packets,18 identifications,
16 families,zero reported kernel drops. BENCHMARK-V018.md and JSON report paired
CPU costs; existing-case p50 changes range -1.0% to +1.4% in this run. DCE/RPC is
new validation work versus baseline malformed SOCKS5. No production latency,
throughput or accuracy claim, or external RPC/ORB interoperability claim.

Only synthetic fixtures uploaded. Backups, development notes, credentials, old
source copies and replay logs excluded. Provide concrete reproductions.
