# Review scope: protocol detector v0.20

Python3.9-compatible IPv4-only bounded classification:39 families,35 automatic.
Exact profiles and exclusions are in PROTOCOLS.md; no full-session claim.

New focus: DTLS1.2 ClientHello in exactly one epoch-zero record per UDP datagram.
Review length/count bounds, fragment/coalescing rejection, cookie framing and
DTLS/DNS/STUN/DHCP dispatch disjointness. Typed UDP results distinguish encryption
from inner application protocol; SNI/ALPN/version are unauthenticated assertions.
No cookie validation, replay protection, negotiated version, decryption or app
identity. The UDP inspector retains no input between messages. The bounded TLS
field decoder is reused only after the DTLS-specific framing/count checks.

TLS server hello/retry, DCE/RPC Bind, GIOP and native Git remain included. Earlier
review fixes cover leading overlaps, capture truncation/retraction, reserved IPv4
flags, control invalidation events and leading FIN/payload coordinates. No proxy
integration, IPv6, native rewrite or endpoint receive-window/sequence-epoch model.

294 installed tests pass, including every DTLS truncation/fragment split, maximum
record/byte/count bounds,2,500 mutations and metadata/ambiguity checks. Actual
LibreSSL3.3.6 ClientHello and cookie retry pass against a synthetic IPv4 loopback
responder; no completed/authenticated handshake. Synthetic real capture:186
packets,22 identifications,17 families,zero reported kernel drops.

BENCHMARK-V020.md reports five paired subprocess rounds: DTLS changes unknown to
identified (12.875us p50); existing UDP p50 differences -0.5%..+2.3% include host
noise. Measurements exclude capture/output and are not SWG latency guarantees.
Prior TLS MemoryBIO and other reports remain available for their version hashes.
The bundled sample-expanded.pcap is preserved; make_sample_pcap.py --expanded
can create a new synthetic fixture with all current automatic examples.

Only source, synthetic fixtures and verification reports are included. Backups,
development notes, credentials, old source copies and replay logs are excluded.
