# Benchmark v0.56: authentication mechanism evidence

Local CPU work, not production SWG latency. Baseline is the v0.55 final tree
(e757e03) in a worktree; `benchmark_ab.py --baseline` (3 alternations x 7
repeats, 400 flows). Host noise is about +-10%. The only hot path that changed
is the HTTP/1 header loop, which gained two `elif` branches (authorization and
www-authenticate names) that the benchmark request never takes; the SMB, LDAP
and HTTP/2 changes run on their own messages.

| Flow | v0.55 (us) | v0.56 (us) | Note |
|---|---|---|---|
| http_flow | 165.5 | 165.9 | two header-name comparisons per header: within noise |
| tls_flow | 180.2 | 175.8 | noise (no change on this path) |
| tls_server13 | 146.5 | 149.2 | noise |
| ssh_flow | 127.5 | 129.6 | noise |
| dns_datagram | 58.2 | 57.9 | unchanged |
| dtls_datagram | 53.8 | 54.1 | unchanged |
| udp_unknown | 24.0 | 24.4 | unchanged |
| quic_initial | 2553.9 | 2563.4 | noise (no change on this path) |

The new work on its own messages (best of five runs of 5000 iterations of a
fresh Inspector, constructor included): SMB2 NEGOTIATE plus a SESSION_SETUP
request with an SPNEGO/NTLMSSP token about 57 us for the two frames (the
NEGOTIATE alone was about 30 us), an HTTP/1 request with an Authorization
header about 60 us. The token classifier is a fixed-depth DER walk bounded by
4096 bytes and 8 mechTypes; every bound raises `ParseError`/`BudgetError` and
ends the one-frame watch while the carrier identification stands.

Review round 1 repairs (baseline 9b163c9, same harness): every flow within
noise (http_flow 167.2 -> 170.1, tls_flow 180.6 -> 183.3, dns_datagram
56.4 -> 59.7, quic_initial 2902.3 -> 2820.1 us). The repaired paths run only on
authentication headers and SESSION_SETUP frames: a 401 response with two
challenge headers about 81 us for a fresh Inspector. The challenge splitter is
two compiled regular expressions, linear in the header value (about 40 ns per
byte on hostile 8 KiB quoted or comma-heavy values) and stops after 32 list
elements per header.

Review round 2 repairs: the Kerberos envelope walk runs only on Kerberos GSS
tokens (one linear pass over at most the 4096-byte token, fields bounded by
their message definitions and 8 principal components); the SMB2 flag rule is
two comparisons. The A/B flows do not reach either path. With a real AP-REQ
envelope, an SMB2 NEGOTIATE plus Kerberos SESSION_SETUP takes about 88 us for
a fresh Inspector, of which the 251-byte SPNEGO token walk is about 32 us.
