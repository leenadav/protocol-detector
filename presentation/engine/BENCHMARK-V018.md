# v0.18 capture-path CPU comparison

Python 3.9.6 on this Mac; five shuffled paired subprocess rounds, 1,000 samples per case per round after warmup. Synthetic decoded IPv4 packets to events. Monitor creation, capture and output I/O excluded. Per-flow microseconds, not production latency.

| Case | v0.17 p50 | v0.18 p50 | Change |
|---|---:|---:|---:|
| dcerpc_flow | 24.458 | 30.000 | +22.7% |
| socks_flow | 30.750 | 30.917 | +0.5% |
| giop_flow | 28.833 | 29.166 | +1.2% |
| http_giop_method | 37.167 | 37.500 | +0.9% |
| git_flow | 38.958 | 39.125 | +0.4% |
| http_git_method | 41.625 | 42.208 | +1.4% |
| tls_flow | 46.834 | 46.750 | -0.2% |
| ssh_flow | 28.375 | 28.688 | +1.1% |
| http_flow | 38.042 | 37.708 | -0.9% |
| partial_fin | 29.458 | 29.230 | -0.8% |
| dns_datagram | 8.875 | 8.917 | +0.5% |
| reordered_http | 47.166 | 46.917 | -0.5% |
| leading_duplicate | 45.709 | 45.625 | -0.2% |
| old_payload_after_fin | 52.000 | 51.459 | -1.0% |
| pre_origin_fin | 28.958 | 29.250 | +1.0% |
| control_rejection | 54.167 | 54.042 | -0.2% |
| leading_conflict | 52.542 | 52.459 | -0.2% |

DCE/RPC is new work: baseline rejects the bytes as malformed SOCKS5, current structurally validates them. Existing-case p50 changes range -1.0% to +1.4% in this run. This is not a statistical latency guarantee. Full p95/p99, statuses/event counts and source/harness fingerprints are in benchmark-capture-v018.json.

270 tests pass, including independent wire construction for both byte orders, all cuts/bytewise input, 1,600 mutation fragmentation comparisons, duplicate contexts/syntaxes, malformed lengths, strict hints, limits and SOCKS5 dispatch compatibility. Fixtures are specification-derived; no external RPC stack interoperability is claimed.

Actual synthetic IPv4 loopback capture: 155 packets, 18 identifications across 16 families, 0 reported kernel drops. See live-smoke-v018-base.json.
