# v0.25 QUIC Initial recognition and protection removal: CPU cost

Python 3.13.16 on Linux-6.18.44-fc-v139-x86_64-with-glibc2.39 (shared cloud container, 4 vCPU).
`benchmark_ab.py` (both trees byte-compiled, 3 alternations, minimum of 7 x 400
flows, constructor subtracted), microseconds per flow/datagram:

| Case | v0.24 | v0.25 | v0.25 fingerprints on |
|---|---:|---:|---:|
| http_flow | 99.5 | 102.8 | 102.6 |
| tls_flow | 122.2 | 122.1 | 172.0 |
| tls_server13 | 96.7 | 99.9 | 111.6 |
| ssh_flow | 81.8 | 76.0 | 81.8 |
| dns_datagram | 33.2 | 38.5 | 38.3 |
| dtls_datagram | 39.3 | 40.3 | 54.5 |
| udp_unknown | 16.9 | 18.5 | 18.8 |
| quic_initial | n/a | 2034.9 | 2203.1 |

- Existing paths are unchanged within noise (the QUIC probe is one byte test
  plus a four-byte version compare ahead of the DTLS prefix test).
- A 1200-byte client Initial costs about **2.0 ms**: HKDF-SHA256 key derivation
  (3 x 2 HMACs), the AES-128 key schedule, one AES block for header protection,
  the per-key GHASH table (about 0.5 ms), 75 AES-CTR blocks (about 0.9 ms) and
  75 GHASH blocks, then ClientHello parsing. With fingerprints the JA4 digest
  adds about 0.17 ms. This is three orders of magnitude above a plaintext
  datagram and is the price of a pure-Python AEAD.
- Mitigations available today: only Initial-type long headers with a supported
  version are opened; `Config.quic_decrypt=False` keeps structural recognition
  (microseconds); the datagram is bounded by `max_bytes`. A flood of Initials
  is therefore a CPU budget the host must rate-limit (THREAT-MODEL T14). A C
  AEAD or caching the GHASH table per Destination Connection ID across the two
  Initials of one connection would roughly halve the cost; neither is in scope
  for a dependency-free Python engine.

## Verification

359 tests pass, 10 new in test_quic.py: the RFC 9001 Appendix A client Initial
decrypts to the published ClientHello (SNI example.com, ALPN "alpn", JA4 q13d0211an_...),
the test helper reproduces the protected RFC 9001 packet byte for byte and the
RFC 9369 v2 vector's first 32 bytes and keys; truncations at every structural
boundary, bad versions, oversized connection IDs, coalesced trailing bytes,
Version Negotiation and its budget, damaged tags, wrong DCID, reserved bits,
decryption disabled, byte budget, allowed and forbidden frame types, frame and
ACK-range budgets, invalid inner hello, reordered and cross-datagram CRYPTO
assembly with assembler bounds and LRU eviction, verdicts (`quic`, standard port
443), tls-family signatures on QUIC contexts, Analyzer flows, and 250 seeded
mutations/noise datagrams within documented statuses and time.
