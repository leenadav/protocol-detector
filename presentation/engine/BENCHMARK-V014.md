# v0.14 FIN-origin verification

Python 3.9.6; five paired rounds of 1,000 samples per case in isolated worker
processes with randomized version order. Synthetic frames through CaptureMonitor
and an in-memory event collector; monitor construction/output I/O excluded.
Full percentiles, source hashes and harness hash: benchmark-capture-v014.json.
Baseline is v0.13.

| Case | v0.13 p50 µs | v0.14 p50 µs |
|---|---:|---:|
| http_flow | 41.208 | 40.416 |
| partial_fin | 30.459 | 29.834 |
| dns_datagram | 9.625 | 9.5 |
| reordered_http | 48.834 | 49.333 |
| leading_duplicate | 48.208 | 48.625 |
| pre_origin_fin | 47.875 | 29.667 |
| control_rejection | 57.291 | 56.417 |
| leading_conflict | 55.125 | 54.917 |

Ordinary cases vary approximately -2% to +1% in this run; no consistent slowdown
was observed. The pre-origin FIN case is faster because the corrected path rejects
the FIN and skips subsequent data; the baseline incorrectly identifies that data.
Those two paths intentionally perform different work. Single-host synthetic CPU
results do not establish production latency, throughput or statistical significance.

239 tests passed in staging. Five new regressions cover four stream origins
including wraparound, empty/payload FINs wholly before the origin, the half-range
ambiguity boundary, a FIN ending at zero, crossing payloads, unambiguous future
FINs, late retraction, and pre-origin non-FIN payloads. The baseline fails 17
subcases. Live adapter events are tested with synthetic Ethernet frames; no new
physical capture was needed. Historical live smoke reports retain their source
fingerprints and do not claim to verify a later implementation.
