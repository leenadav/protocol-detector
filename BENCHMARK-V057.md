# Benchmark v0.57: TLS posture

Local CPU work, not production SWG latency. Baseline is the v0.56 tree
(9b163c9) in a worktree; `benchmark_ab.py --baseline` (3 alternations x 7
repeats, 400 flows), run twice. Host noise during these runs was larger than
usual: the unchanged `udp_unknown` and `quic_initial` paths moved by up to
+-30% and +-10% between runs, so single-flow differences below about 10% are
not meaningful here.

Changed hot paths: every TLS 1.2/1.3 and DTLS 1.2 ServerHello appends two
asserted rows (one set lookup for the suite); the opt-in certificate watch
interprets three extensions and tracks extension OIDs for duplicates.

| Flow | v0.56 run 1 / run 2 (us) | v0.57 run 1 / run 2 (us) | Note |
|---|---|---|---|
| http_flow | 167.5 / 175.9 | n/a / 171.7 | no change on this path; the first run's v0.57 value was cut from the captured log |
| tls_flow | 180.3 / 183.8 | 185.2 / 181.2 | client flow: no change; noise |
| tls_server13 | 151.6 / 156.4 | 154.9 / 153.4 | two extra evidence rows: within noise |
| ssh_flow | 129.4 / 133.9 | 137.6 / 125.6 | no change on this path: noise |
| dns_datagram | 61.4 / 58.5 | 59.9 / 63.0 | no change on this path: noise |
| dtls_datagram | 47.9 / 57.2 | 52.4 / 56.7 | two extra evidence rows: within noise |
| udp_unknown | 25.0 / 16.7 | 24.8 / 24.8 | no change on this path: noise |
| quic_initial | 2667.8 / 2720.0 | 2922.8 / 2838.1 | no change on this path: noise |

Certificate walk on identical bytes (best of seven runs of 5000 calls to
`leaf_profile`, each tree byte-compiled):

| Leaf | v0.56 (us) | v0.57 (us) |
|---|---|---|
| v0.56 fixture leaf (510 bytes, basicConstraints only) | 28.1 | 30.9 |
| v0.57 fixture leaf (563 bytes, plus EKU and SAN) | 35.7 | 39.4 |

About 3-4 us more per leaf for the interpreted extensions; the whole TLS 1.2
server flight with certificates measured about 107 us (v0.56 fixture) and
123 us (v0.57 fixture, 53 bytes longer) for a fresh Inspector. The walk stays
one linear pass over at most `MAX_LEAF` (16 KiB) bytes: extendedKeyUsage is
capped at 16 purposes, subjectAltName entries are framed without reading
their contents, and the duplicate check is a set of at most 64 OIDs.
