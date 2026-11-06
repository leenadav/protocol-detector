# Local microbenchmark — recorded development run

Python 3.9.6 on macOS-26.6.2-arm64-arm-64bit. 100 measured flows per case after 20 warmups.

Reproduce: `python3 -B benchmark_engine.py --iterations 100`.
Raw data: `benchmark-local.json`.

Median feed-loop time per synthetic flow, microseconds:

| Workload | Legacy POC | Incremental |
|---|---:|---:|
| http_small | 4.917 | 12.084 |
| http_fragmented | 20014.666 | 362.938 |
| tls_fragmented | 16.417 | 27.792 |
| http_after_identification | 377.75 | 25.0 |

**Initial identification is not uniformly faster.** The small HTTP and TLS cases
include additional validation, metadata extraction and immutable evidence/events.
The legacy baseline does less work. Improvements on fragmented-prefix and
post-identification workloads do not establish production readiness.

30,000 exact-host rules took 98.944 ms to build outside the data path.
Same HTTP input: median 11.75 us without rules and 12.125 us with 30,000 rules.
This is an indexed hostname attribution test, **not** 30,000 protocol parsers or
arbitrary signatures. At most one protocol parser is selected per scope.

Work counters: the 6050-byte fragmented HTTP request is inspected once (6050
bytes). After a 37-byte request plus 64 KiB of later payload, only 37 bytes are
inspected; terminal feeds bypass the parser. Full counters and p50/p95/p99 are
retained in the JSON report.

Limitations: synthetic, single-process workload on a development Mac; no CPU
pinning, concurrency, process isolation or representative production distribution.
Timings include Python call/event and benchmark-loop overhead but exclude Inspector
construction, networking, capture, TCP reassembly, TLS decryption and logging.
Rule construction is reported separately. Per-feed percentiles mix phases; consult
per-flow values too. A 100-flow p99 is noisy. These are not product SLAs or full
SWG latency measurements. Unit tests assert work bounds, not timing thresholds.
Measure representative replay under load on target hardware before deployment.
