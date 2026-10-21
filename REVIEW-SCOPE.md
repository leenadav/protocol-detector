# Review scope: protocol detector v0.28

Python3.9-compatible IPv4 passive classification: 66 families, 60 automatic.
PROTOCOLS.md defines exact initial-message profiles and exclusions. APPID.md
defines the verdict vocabulary and the application catalog.

New focus (v0.28): the application-shift state machine in engine.py
(`_begin_shift`, `_forward`, `_shift_result`, `_merge_shift`, `_continue`) and
the boundary detection in parsers.py (`_shift_boundary`), extended.py
(`_consume_smtp`, IMAP/POP3/FTP shifts), binary.py, database.py, remote.py
(RDP confirm), ics.py (TPKT route) and upgrade.py (WebSocket). Trace: byte
accounting across both phases against max_bytes (inner budget = remaining,
< 64 ends the shift), update budget, parser_calls; publish-before-shift
ordering and the "shifted" event kind; carrier evidence kept in a merged
observation (hostname/application only when the inner has none) and never a
downgrade of the carrier; the LineParser continuation returning at the
identifying line so a same-chunk STARTTLS error cannot make EHLO malformed;
SMTP watch bounds (512-byte lines, known verbs, NOOP count); CONNECT
authority-form regex and the no-shift fallback; Upgrade/Connection/Sec-WebSocket
header rules, body exclusion, 101 handling, h2c server frames excluded;
WebSocket frame-header bounds (RSV, opcodes, minimal lengths, control frames);
MySQL SSLRequest capability/reserved checks within the hint-only family; RDP CC
DST-REF/class/selected-protocol checks and failure codes; `shifted_from`
derivation in appid (http-connect -> http-proxy), implicitly_uses and carrier
port acceptance; invalidate/end/feed_decrypted interplay with a pending shift.
391 tests pass. BENCHMARK-V028.md.

Previous focus (v0.27): 23 decoders in protocol_engine/session_text.py, windows.py,
vpn.py, telemetry.py, ics.py, datainfra.py, their dispatch routes
(dispatch.py 0x00/0x01, 0x03 TPKT, 0x04/0x63.., 0x68, 0xff blocks) and UDP
candidate probes (datagram.py). Trace: every length/count field against the
frame or datagram before body access; min(max_headers, N) bounds on dialects,
padata, AVPs, flowsets, sets, samples; DNP3 CRC coverage and the 255-byte
frame bound; Kerberos BER definite-length handling and field ordering; TPKT
child selection (RDP cookie / negotiation / bare request vs. COTP); Kafka
8-byte selection and fragmentation equivalence; Telnet byte-at-a-time state
and the 64-byte bound; the `AmbiguousPrefix` route (shared 220/USER/PASS/QUIT
lines, `* OK` without capabilities) producing terminal `unknown` with
`ambiguous_candidates` context only, and `session_verdict` correlation
requiring both directions with an intersection of exactly one family (never a
hint or port); WireGuard/OpenVPN reported as encryption without tunnel claims;
no emission of dialects, NetBIOS names, principals, realms, host/vendor names,
client ids, LOCATION/USN strings. 381 tests pass. BENCHMARK-V027.md.

Previous focus (v0.25): QUIC (protocol_engine/quic.py, aes.py). Trace: long-header
bounds (CID lengths, token, Length varint vs datagram, coalesced trailing bytes),
probe placement ahead of DTLS and IKE competition, key derivation against the
RFC 9001/9369 vectors, header protection sample offset and reserved-bit check,
GCM tag failure and frame-type violations mapping to unverified (never
malformed/unknown), frame budgets, CRYPTO assembly (gaps, overlaps, offset
budget), QuicAssembler LRU and per-entry bounds, capture-gap clearing, no
connection-ID or token emission, signature contexts under the tls family,
CPU cost per Initial and the host's rate-limiting responsibility.
359 tests pass. BENCHMARK-V025.md.

Previous focus (v0.24): fingerprints (protocol_engine/fingerprints.py) and the
post-identification continuation in engine.py. Trace: GREASE filtering and
JA4 field rules (version from supported_versions, SNI flag, counts capped at
99, ALPN two-character code including non-alphanumeric cases, sorted vs
original order, SNI/ALPN exclusion in JA4_c, signature-algorithm suffix),
JA4S example vector, JA3/JA3S/HASSH definitions, DTLS version, HTTP/2
SETTINGS order; continuation accounting of consumed bytes, failure/budget/EOF
behaviour never downgrading an identification, KexInit bounds (35000, padding,
name-list ASCII and size, trailer), parser release after refinement, event
kinds updated/refined and live counters. 349 tests pass. BENCHMARK-V024.md.

Previous focus (v0.23): custom signatures (protocol_engine/signatures.py), context
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
