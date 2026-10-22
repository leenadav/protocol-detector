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
