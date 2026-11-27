# Benchmark v0.51: HTTP/1 header classes and four new families

Local CPU work, not production SWG latency. Baseline is the v0.50 tree
(6192083) in a worktree; `benchmark_ab.py --baseline` (3 alternations x 7
repeats, 400 flows). Host noise is about +-10%. The HTTP/1 hot path gained
the `http_method` evidence row and two header branches (content-type,
accept); everything else is new code on new first-byte routes.

| Flow | v0.50 (us) | v0.51 (us) | Note |
|---|---|---|---|
| http_flow | 167.5 | 164.4 | method row plus header branches: within noise |
| tls_flow | 179.1 | 172.1 | noise |
| ssh_flow | 124.4 | 132.7 | noise |
| dns_datagram | 53.0 | 57.2 | one more candidate test per datagram (RPC words), within noise |
| dtls_datagram | 55.0 | 56.1 | noise |
| udp_unknown | 24.0 | 24.1 | unchanged |
| quic_initial | 2671.0 | 2847.0 | noise (no change on this path) |
