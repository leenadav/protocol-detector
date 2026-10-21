# Benchmark v0.50: HTTP/2 HEADERS continuation and HPACK

Local CPU work, not production SWG latency. Baseline is the v0.49 tree
(c3fda9d) in a worktree; `benchmark_ab.py --baseline` (3 alternations x 7
repeats, 400 flows) and an isolated timeit micro-benchmark (min of 7 x 2000
flows, `Inspector.feed` + `end`). Host noise is about +-10%.

| Flow | v0.49 (us) | v0.50 (us) | Note |
|---|---|---|---|
| http_flow | 163.7 | 153.9 | A/B set, unchanged code path |
| tls_flow | 176.6 | 181.1 | noise |
| tls_server13 | 147.5 | 137.6 | noise |
| ssh_flow | 127.9 | 131.7 | noise |
| dns_datagram | 52.2 | 54.0 | noise |
| dtls_datagram | 54.2 | 55.9 | noise |
| udp_unknown | 23.8 | 24.1 | noise |
| quic_initial | 2730.9 | 2649.2 | noise |
| http2_preface (preface + empty SETTINGS, then EOF) | 20.1 | 16.7 | `_refined` skips the observation rebuild at EOF |
| h2_request_hpack (SETTINGS + WINDOW_UPDATE + RFC 7541 C.4.1 HEADERS) | - | 89.7 | new: frame walk, HPACK, header rules, hostname |
| h2_grpc_request | - | 81.7 | new |
| h2_response (server SETTINGS + ACK + C.6.1 HEADERS) | - | 80.5 | new |

HPACK alone: decoding the C.4.1 block (Huffman authority) costs 8.5 us; an
8 KiB Huffman string costs 1.95 ms with the nibble table (8.7 ms with the
first bit-by-bit decoder, which is why it was replaced). A hostile 16 KiB
header block therefore costs about 4 ms of CPU, bounded by the block cap and
`max_bytes`. The decoder table is built once at import (8.8 ms).
