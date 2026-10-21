# v0.29 heuristics and flow risks: CPU cost

Python 3.13 on Linux-6.18.44-fc-v139-x86_64 (shared cloud container, 4 vCPU).
Heuristics are off by default and cost nothing until enabled; every verdict now
computes flow risks, and TLS ClientHellos and SSH banners carry one more
evidence row each.

## A/B harness, v0.28 (c0266b0) versus v0.29, microseconds per flow/datagram

`benchmark_ab.py` (both trees byte-compiled, constructor subtracted). Three
runs: 3x7x400, 3x7x400 after the hot-path rewrite, and 5x9x400.

| Case | run 1 | run 2 | run 3 (5x9) |
|---|---:|---:|---:|
| http_flow | 137.7 → 158.2 | 137.8 → 156.2 | 137.5 → 150.1 |
| tls_flow | 162.1 → 226.4 | 160.4 → 196.4 | 160.6 → 183.3 |
| tls_server13 | 122.6 → 144.8 | 123.7 → 141.9 | 124.2 → 138.2 |
| ssh_flow | 100.0 → 127.1 | 98.7 → 125.3 | 98.8 → 118.1 |
| dns_datagram | 43.6 → 55.5 | 38.3 → 51.4 | 39.9 → 49.2 |
| dtls_datagram | 44.6 → 50.3 | 47.1 → 54.6 | 47.0 → 40.9 |
| udp_unknown | 23.1 → 22.6 | 22.6 → 22.3 | 22.5 → 22.0 |
| quic_initial | 2557 → 2640 | 2629 → 2698 | 2571 → 2738 |

Run 1 measured the first implementation (a full `ClientHelloInfo` for every
ClientHello, a function-level import and a multi-pass risk scan); runs 2 and 3
measure the shipped code. The remaining differences on identified flows
(+9..23%) exceed what the isolated costs below add up to (+3..12 µs per flow)
and are not consistent (DTLS -13% in run 3, udp_unknown unchanged in all
runs): this host shows ±10-15% process-to-process variance that the
alternating harness does not remove (BENCHMARK-V023.md). The same-interpreter
comparison below is the reliable measurement.

## Isolated costs (same interpreter, minimum of repeats)

| Operation | µs | Note |
|---|---:|---|
| `flow_risks` on an identified HTTP verdict (two risks) | 1.05 | per-application risks cached, one pass over evidence |
| `session_verdict` / `classify` | 5.8 / 6.3 (was 2.8 / 3.3) | +3 µs: risks plus `Verdict._replace` |
| TLS ClientHello inspection | 64 → 73 | `tls_offered_max_version` from a two-entry list; no `ClientHelloInfo` unless contexts or fingerprints are on |
| SSH banner inspection | +1 Evidence row (`ssh_version`) | about 1 µs |
| `payload_profile` of 512 bytes | 67.6 | heuristics on, unknown TCP prefix |
| `payload_profile` of 64 bytes | 15.8 | |
| unknown 600-byte stream, heuristics off / on | 10.0 / 89.3 | the stream also waits for 512 bytes before publishing unknown |
| unknown 200-byte datagram, off / on | 5.1 / 49.0 | |
| DNS datagram, off / on (name shape) | 11.9 / 22.4 | `dns_details` instead of `dns`, label entropy |

Stubbing `flow_risks` inside one interpreter and re-measuring the monitor path
moved the HTTP flow by 4-14 µs between repetitions of the same experiment,
which is the noise floor of this host; the isolated 3-4 µs per flow is the
defensible cost of risks.

## Verification

402 tests pass (10 new in test_risks.py): entropy and class thresholds on
known inputs, bounded profiling only when enabled, identified streams never
profiled, datagram and DNS name shape evidence (no label text emitted), every
risk rule with positive and negative fixtures, TLS version precedence and
GREASE, session records, offline analysis and live events carrying `risks`,
and the RISKS.md documentation gate (every risk name documented).
