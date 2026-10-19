# Review scope: protocol detector v0.21

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
