# Review scope: protocol detector v0.19

Python3.9-compatible IPv4-only bounded classification:38 families,34 automatic.
Profiles and exclusions are documented in PROTOCOLS.md. Review concrete parser,
reassembly/lifecycle and CPU/memory failures; do not infer full-session validation.

New focus: TLS ServerHello for1.2/1.3 and HelloRetryRequest. Shared bounded record
assembly distinguishes handshake types; server extension processing is capped.
Check nested vectors, record boundaries, extension dependencies/context, exact
supported cipher/group shapes and retry semantics. TLS1.2 ALPN is an asserted
server selection; TLS1.3 ALPN stays encrypted. Neither becomes inner protocol,
client offered_alpn, hostname or product identity. No cryptographic validation,
Finished/certificate checks, client-offer correlation or hybrid/PQ groups.

DCE/RPC Bind, GIOP and native Git remain in scope. Earlier fixes handle leading
TCP overlap conflicts, PCAP truncation/retractions, reserved IPv4 flags, control
invalidation events and consistent FIN/payload coordinates. No multiple sequence
epochs or endpoint receive-window emulation. Legacy detectors.py is educational
ClientHello-only; production-style capture uses protocol_engine.

283 installed tests pass, including every TCP/TLS-record split, bytewise feeds,
2,000 mutations, malformed lengths, extension contexts, budgets and metadata.
Canonical MemoryBIO output from LibreSSL2.8.3 and OpenSSL3.5.8 was validated by
Python3.9.6; secp256r1 explicitly configured. No network or persistent private keys.
Synthetic actual local IPv4 capture:185 packets,21 identifications,16 families,
zero reported kernel drops; two server hello and one retry scopes verified.
BENCHMARK-V019.md reports final paired CPU costs and observed run-to-run noise;
ClientHello p50 +0.3% in final run. No production latency/accuracy guarantee.

Only synthetic fixtures and verification reports uploaded. Backups, development
notes, credentials, old source copies and replay logs excluded.
