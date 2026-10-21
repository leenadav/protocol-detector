# v0.12 review-fix validation

Python 3.9.6 on the same local host. Six synthetic packet-to-event fixtures, 500 samples x five rounds per version, randomized version order. Construction, capture syscalls and output I/O are excluded; an event collector is included in both versions. Baseline is the preserved v0.11 project. GC remains enabled. These are local CPU costs, not SWG/network latency.

| Fixture | v0.11 p50 us | v0.12 p50 us | v0.12 p99 us | Result |
|---|---:|---:|---:|---|
| http_flow | 37.833 | 38.417 | 59.791 | identified |
| partial_fin | 28.042 | 28.292 | 45.917 | incomplete |
| dns_datagram | 9.0 | 8.917 | 14.917 | identified |
| reordered_http | 45.625 | 46.334 | 70.042 | identified |
| leading_duplicate | 44.042 | 45.042 | 66.792 | identified |
| leading_conflict | 43.959 | 51.666 | 124.5 | invalidated |

The leading-conflict baseline incorrectly remained identified. The fixed version emits an invalidation and releases tracking; its extra work is necessary and the two outcomes are not semantically equivalent. Small ordinary-path differences are measurements from one host, not statistically established deployment regressions. Source and harness SHA256 fingerprints are in benchmark-capture-v012.json.

230 unit tests passed in staging. The 12 new tests reproduce all three review findings, cover both sequence-wrap and non-wrap origins, matching and conflicting leading overlaps with FIN, a seeded independent clipping oracle, atomic failure, offline/live capture-length parity in all four classic PCAP formats, capture-loss retraction/recovery, physical record truncation, and IPv4 reserved flags with TCP/UDP/VLAN.

Reference semantics: [TCP sequence space, RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html), [IPv4 flags, RFC 791](https://www.rfc-editor.org/rfc/rfc791). A retained prefix is not a complete TCP receive-window implementation.

Local synthetic IPv4 loopback capture also passed: 13 families, 15 identifications, zero reported kernel drops. Report: live-smoke-v012-base.json.
