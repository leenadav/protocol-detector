# Benchmark v0.59: smart-home datagram probes and DNS RDATA names

Local CPU work, not production SWG latency. Baseline is the v0.58 tree
(b83cf60) extracted with `git archive`; `benchmark_ab.py --baseline`
(3 alternations x 7 repeats, 400 flows), Python 3.12.

| Flow | v0.58 (us) | v0.59 (us) | Note |
|---|---|---|---|
| http_flow | 68.6 | 69.1 | unchanged path: noise |
| tls_flow | 81.1 | 80.4 | unchanged path: noise |
| tls_server13 | 66.5 | 65.1 | unchanged path: noise |
| ssh_flow | 53.1 | 50.8 | unchanged path: noise |
| dns_datagram | 20.7 | 21.0 | DNS layout path; SRV/NSEC names parsed only when present |
| dtls_datagram | 20.4 | 20.4 | unchanged |
| udp_unknown | 9.7 | 9.7 | three extra constant-time probes on the fallback path |
| quic_initial | 1590.8 | 1577.9 | unchanged path: noise |

The TP-Link profile is one linear pass over the datagram (bounded by
`max_bytes`) before `json.loads`, and runs only when the first two bytes match.
