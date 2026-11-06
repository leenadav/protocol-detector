# v0.13 control-retraction verification

Python 3.9.6; paired isolated processes, randomized version order, five rounds
of 1,000 samples per case after warmup. Times cover synthetic frames through
CaptureMonitor and an in-memory event collector; construction and output I/O
are excluded. Full p95/p99, source hashes and harness hash are in
benchmark-capture-v013.json. Baseline is v0.12.

| Case | v0.12 p50 µs | v0.13 p50 µs |
|---|---:|---:|
| http_flow | 41.167 | 41.291 |
| partial_fin | 30.333 | 30.042 |
| dns_datagram | 9.625 | 9.542 |
| reordered_http | 49.625 | 49.583 |
| leading_duplicate | 48.667 | 48.791 |
| control_rejection | 54.209 | 56.833 |
| leading_conflict | 55.0 | 55.0 |

Ordinary cases differ by about 1% or less in this run. Control rejection costs
about 4.8% more: it now constructs an Inspector retraction and updates event
counters, instead of only printing the live fallback. Baseline offline output
omitted the retraction entirely. This is a correctness cost on the rejection
path, not a regression hidden by comparing different behavior.

Single-host synthetic CPU measurements do not establish production latency,
throughput, representative accuracy or statistical significance.

All 234 unit tests passed in staging. The four new parameterized tests expose
48 failing subcases on v0.12, and cover eight control rejections in both Analyzer
modes, offline JSON with/without events-only, live output with/without all-events,
state release, event revisions, duplicate suppression and ordinary retirement.
No physical live capture was rerun: this change affects only Analyzer control
rejection; synthetic CaptureMonitor regression frames exercise the live path.
The v0.12 physical loopback report is historical evidence for that source hash.
