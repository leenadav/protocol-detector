# Review scope: protocol detector v0.23

Python3.9-compatible IPv4 passive classification: 40 families, 36 automatic.
PROTOCOLS.md defines exact initial-message profiles and exclusions. APPID.md
defines the new verdict vocabulary and the application catalog.

New focus (v0.23): custom signatures (protocol_engine/signatures.py), context
retention in parsers.py/extended.py/binary.py/wire.py, the unknown-payload
buffering state in engine.py and unknown-udp evaluation in datagram.py. Trace:
pattern safety (nested quantifiers, backreferences, lookaround, repeat counts,
Latin-1, anchor length), prefilter correctness with case_insensitive, absent
contexts under negate, buffer accounting against max_bytes/signature_bytes,
eager evaluation vs. negated unknown-payload conditions, EOF evaluation of an
unresolved prefix, hint isolation, retention off by default and never emitted,
signature precedence over RuleIndex, verdict metadata via SignatureSet.
339 tests pass. Benchmarks: BENCHMARK-V023.md.

Previous focus (v0.22): the App-ID verdict layer (protocol_engine/appid.py, applications.py)
and the session ledger in analyze_pcap.Analyzer. Trace: verdict precedence
(identified > unknown/malformed/budget > invalidated > insufficient-data >
incomplete), client preference and server disagreement reporting, custom
mappings inheriting their carrier, port_usage with ranges/dynamic/secure ports,
per-direction byte accounting including retransmissions, SYN-only sessions,
record emission ordering relative to retirement/retraction events, UDP flow
table bounds and expiry, capture-gap clearing, hostname opt-in. Catalog risk
and characteristics are editorial defaults; review them as policy metadata,
not as detection claims. 324 tests pass. Benchmarks: BENCHMARK-V022.md.


Python3.9-compatible IPv4 passive classification:40 families,36 automatic.
PROTOCOLS.md defines exact initial-message profiles and exclusions.

New focus: IKEv2 IKE_SA_INIT initiator requests. Trace fixed native/non-ESP header
positions, complete payload chaining, bounded proposals/transforms, AES attributes,
CBC/AEAD integrity rules and KE/nonce consistency with offered algorithms. All
payload/proposal/transform work shares one128-capped budget. No crypto, peer
identity, successful negotiation or established IPsec tunnel is claimed.

An arbitrary IKE initiator SPI can collide with another UDP profile. One fixed
IKE probe adds a candidate to existing routes, never steals the first match.
Maximum three validators. Actual dual CoAP/IKE and DHCP/IKE messages must return
unknown; a competing exhausted budget blocks identification. No registry scan.

Delayed review4319051025 fromv0.19 was independently reproduced onv0.20 and fixed:
TLS1.2 RSA-only cipher0x002f now rejects EC point-format extension11. Every TCP
and TLS-record split rejects; all supported ECC suites still accept the extension.
Thev0.20 review reported no major issues; this older finding is explicitly retained.

309 installed tests pass. IKE includes all supported algorithm combinations,
truncations, count/length/attribute/marker/cookie negatives,3,000 mutations and
three-candidate tests. Independent tcpdump dissection agrees on both synthetic
IKE fixtures, but no real IKE peer handshake was tested. LibreSSL TLS1.2 MemoryBIO
still passes. Synthetic actual IPv4 loopback capture:186 packets,24 identifications,
18 families,zero reported kernel drops.

BENCHMARK-V021.md: five paired subprocess rounds; new IKE p50 about15us including
packet decode/events. Existing UDP differences -0.7%..+1.4% and TCP -1.7%..+2.2%
include host noise. Different semantics are reported separately. No production
latency or detection-accuracy guarantee. Prior feature/fix history stays in scope.

No proxy integration, IPv6, native rewrite or external/user traffic. Only source,
synthetic fixtures and verification reports uploaded; backups/development notes,
credentials, old source copies and replay logs excluded. Existing sample-expanded
PCAP preserved; generator can produce a new fixture with current coverage.
