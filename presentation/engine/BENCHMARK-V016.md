# v0.16 Git feature verification

Python 3.9.6; five paired rounds of 1,000 samples per case in isolated processes,
randomized version order. Synthetic frames to CaptureMonitor events; monitor
construction and output I/O excluded. Full percentiles/source/harness hashes are
in benchmark-capture-v016.json. Baseline v0.15 has no native Git recognizer.

| Case | v0.15 p50 µs | v0.16 p50 µs |
|---|---:|---:|
| git_flow | 22.917 | 38.875 |
| http_git_method | 37.25 | 41.25 |
| tls_flow | 45.875 | 45.625 |
| ssh_flow | 27.875 | 27.958 |
| http_flow | 36.562 | 36.625 |
| partial_fin | 28.625 | 28.583 |
| dns_datagram | 8.916 | 8.792 |
| reordered_http | 46.916 | 46.083 |
| leading_duplicate | 46.125 | 45.291 |
| old_payload_after_fin | 52.25 | 51.042 |
| pre_origin_fin | 29.375 | 28.916 |
| control_rejection | 53.958 | 53.042 |
| leading_conflict | 52.375 | 51.666 |

HTTP GET/TLS/SSH medians remain close in this run; this is not a statistical
equivalence claim. The intentionally ambiguous HTTP method 0033git-upload-pack
costs about 10.7% more (37.25→41.25µs) for bounded structural disambiguation/replay.
Git is newly identified; baseline remains detecting, so that timing is not
equivalent work. No production latency, throughput or accuracy claim is made.

252 unit tests passed. New tests cover all request commands, optional fields,
every split, bytewise input, misleading HTTP methods, strict hints, advertised
length/budgets, negative fields, metadata minimization, mutation equivalence and
terminal buffer release. Generic fixture tests also include Git.

git-interop-v016.json records Git 2.50.1 configured for protocol versions 0/1/2 to a
synthetic IPv4 loopback server; each also identifies once through bytewise TCP
reassembly. Run git_interop.py manually to reproduce; Git configs are disabled.
live-smoke-v016-base.json records actual narrowly filtered synthetic loopback
capture: 14 families, 16 identifications, 139 packets, zero reported kernel drops.
Both are local interoperability checks, not independent proofs of profile accuracy.
