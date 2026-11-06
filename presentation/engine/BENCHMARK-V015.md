# v0.15 leading-payload coordinate verification

Python 3.9.6; five paired rounds of 1,000 samples per case in isolated worker
processes with randomized version order. Synthetic frames through CaptureMonitor
and an in-memory collector; monitor construction and output I/O excluded.
Full percentiles, source hashes and harness hash: benchmark-capture-v015.json.
Baseline is v0.14.

| Case | v0.14 p50 µs | v0.15 p50 µs |
|---|---:|---:|
| http_flow | 39.583 | 39.875 |
| partial_fin | 29.25 | 29.458 |
| dns_datagram | 9.375 | 9.292 |
| reordered_http | 47.25 | 48.542 |
| leading_duplicate | 47.333 | 47.334 |
| old_payload_after_fin | 56.125 | 53.125 |
| pre_origin_fin | 29.292 | 29.292 |
| control_rejection | 55.25 | 55.375 |
| leading_conflict | 53.833 | 53.875 |

Ordinary-path medians vary about -1% to +3% in this run; reordered HTTP is the
largest increase (~2.7%) despite not entering the changed leading-segment branch.
These figures are descriptive, not evidence of significance. The corrected
old-payload-after-FIN case avoids a false retraction and preserves classification;
its baseline and current outputs intentionally differ. Single-host synthetic CPU
results do not establish production latency or throughput.

241 tests passed in staging. Two new methods include an independent absolute
coordinate oracle over 1,680 cases (three origins, five FIN boundaries, fourteen
payload starts, four lengths, FIN/non-FIN) plus live event regression checks.
The baseline fails 61 subcases. They verify retained-byte/highest-end accounting,
state release on contradiction, preservation of benign old payload, and rejection
when crossing payload actually extends beyond FIN. No new physical capture was
needed; the live adapter is exercised with synthetic frames only. Historical
smoke reports describe their own source versions.
