# v0.17 capture-path CPU comparison

Python 3.9.6 on this Mac; five shuffled paired subprocess rounds, 1,000 samples per case per round after warmup. Synthetic decoded IPv4 packets to events. Monitor construction, capture and output I/O excluded. Values are per-flow microseconds, not per-packet or production latency.

| Case | v0.16 p50 | v0.17 p50 | Change |
|---|---:|---:|---:|
| giop_flow | 22.791 | 29.375 | +28.9% |
| http_giop_method | 36.959 | 37.250 | +0.8% |
| git_flow | 38.209 | 38.375 | +0.4% |
| http_git_method | 41.500 | 41.459 | -0.1% |
| tls_flow | 46.333 | 46.458 | +0.3% |
| ssh_flow | 28.333 | 28.875 | +1.9% |
| http_flow | 37.125 | 37.500 | +1.0% |
| partial_fin | 28.791 | 28.917 | +0.4% |
| dns_datagram | 8.875 | 8.792 | -0.9% |
| reordered_http | 47.291 | 46.625 | -1.4% |
| leading_duplicate | 46.250 | 45.791 | -1.0% |
| old_payload_after_fin | 51.958 | 52.000 | +0.1% |
| pre_origin_fin | 29.458 | 29.583 | +0.4% |
| control_rejection | 53.000 | 53.667 | +1.3% |
| leading_conflict | 51.250 | 51.834 | +1.1% |

GIOP is different work: baseline remains detecting, current structurally identifies. Ordinary existing paths range about -1.4% to +1.9% in this run; this is not a statistical latency guarantee. Raw p95/p99, status/event counts and source/harness SHA256 fingerprints are in benchmark-capture-v017.json.

261 tests pass, including independent wire construction for both byte orders, all split points/bytewise input, 1,800 seeded mutation fragmentation comparisons, malformed lengths, CDR padding, HTTP ambiguity, strict hints and resource limits. No external ORB interoperability claim: fixtures are specification-derived.

Synthetic actual loopback capture passed: 145 packets, 17 identifications across 15 families, zero reported kernel drops; 147 packets received by filter includes shutdown timing. See live-smoke-v017-base.json.
