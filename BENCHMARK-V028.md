# v0.28 application shift: CPU cost

Python 3.13 on Linux-6.18.44-fc-v139-x86_64 (shared cloud container, 4 vCPU).
`benchmark_ab.py --baseline <v0.27 worktree at 51c6b91>` (both trees
byte-compiled, 3 alternations, minimum of 7 x 400 flows, constructor
subtracted), microseconds per flow/datagram. Two runs are shown because the
host was noisy: the first ran concurrently with the per-boundary measurement
below, the second on an idle container.

| Case | v0.27 run 1 | v0.28 run 1 | v0.27 run 2 | v0.28 run 2 |
|---|---:|---:|---:|---:|
| http_flow | 136.0 | 135.1 | 136.3 | 131.2 |
| tls_flow | 158.7 | 156.4 | 161.6 | 160.9 |
| tls_server13 | 126.8 | 121.8 | 121.1 | 123.7 |
| ssh_flow | 95.9 | 96.2 | 95.3 | 97.6 |
| dns_datagram | 42.0 | 43.4 | 42.7 | 43.7 |
| dtls_datagram | 41.5 | 47.6 | 46.8 | 46.7 |
| udp_unknown | 22.4 | 22.6 | 14.9 | 22.4 |
| quic_initial | 2784.4 | 2640.9 | 2587.2 | 2554.2 |

- No existing path changed by more than the run-to-run noise: the HTTP header
  block gained four header-name comparisons and one `_shift_boundary` call per
  message; nothing in the UDP path was touched (the +14.7% DTLS and the
  -33% udp_unknown baseline readings each appear in only one run and are host
  noise, see BENCHMARK-V023.md on this harness's limits).
- Streams that do not shift pay nothing after identification except the SMTP
  EHLO case, which now watches the next command line (one extra parser call,
  about 11 µs when the next line arrives).

## Per-boundary cost (in-process, minimum of 5 x 1500, constructor subtracted)

| Stream | bytes | µs |
|---|---:|---:|
| plain GET (reference) | 37 | 38.4 |
| CONNECT alone (shift pending) | 89 | 58.5 |
| CONNECT + ClientHello | 606 | 144.9 |
| ClientHello alone (reference) | 517 | 60.3 |
| WebSocket upgrade + frame | 165 | 106.6 |
| 101 + server frame | 136 | 80.1 |
| h2c upgrade + preface | 163 | 100.8 |
| EHLO alone (reference) | 21 | 26.4 |
| EHLO + MAIL (watch ends) | 38 | 37.3 |
| EHLO + STARTTLS + ClientHello | 548 | 140.1 |
| IMAP STARTTLS + ClientHello | 532 | 123.1 |
| PostgreSQL SSLRequest + ClientHello | 525 | 104.6 |
| MySQL SSLRequest + ClientHello (hint) | 553 | 105.5 |
| RDP request + ClientHello | 536 | 114.9 |
| RDP confirm + ClientHello | 536 | 119.3 |

- A shift costs about 25 µs on top of the two phases: constructing the inner
  Inspector (`replace(config)` plus Metrics/Observation), publishing two events
  instead of one, and the merge (`_shift_result`) that rebuilds the evidence
  tuple. The inner phase itself costs what the same bytes cost on a fresh
  stream (ClientHello about 60 µs).
- The pending state (CONNECT alone) keeps one extra Inspector object per
  direction until the connection ends; its memory is the ordinary per-direction
  state, bounded by the connection limit as before.

## Verification

391 tests pass, 11 new in test_shift.py: every boundary with every split
point and 3-byte fragmentation, 60 seeded mutations per boundary, failed/
missing/malformed shifted phases keeping the carrier, byte and update budgets
across both phases, invalidate and feed_decrypted after a shift, CONNECT
authority form and the http-proxy verdict, WebSocket header rules (RSV,
opcodes, minimal lengths, control frames, masking) and upgrade header rules,
the SMTP watch bounds, PostgreSQL GSSENC/MySQL SSLRequest/MariaDB variants,
RDP confirm success/failure/invalid cases, session verdicts with
`shifted_from` and carrier ports, and an offline PCAP run producing the
`shifted` event and session record. Existing tests were adjusted where a
fixture now shifts (RDP request offering TLS, PostgreSQL SSLRequest) or
continues (SMTP EHLO).
