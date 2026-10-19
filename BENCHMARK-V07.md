# Local performance measurement — v0.7

Measured 2026-10-19 on this Mac, Python 3.9.6.
500 samples per round, five shuffled-order rounds, 50 warmups per case/version.
Identical fixtures and correctness assertions against a preserved v0.6.1 engine.
Raw results and source fingerprints: [benchmark-v07.json](benchmark-v07.json).

Timing includes feed and events; excludes Inspector construction, capture, TCP,
TLS decryption, logging, contention and concurrency. These are CPU microbenchmarks,
not end-to-end SWG latency, throughput guarantees or production tail-latency bounds.

## Existing TCP paths

| Case | v0.6.1 p50 µs | v0.7 p50 µs | Change | v0.7 p99 µs |
|---|---:|---:|---:|---:|
| http_small | 23.625 | 24.02 | +1.7% | 30.875 |
| http_fragmented | 628.812 | 630.75 | +0.3% | 718.708 |
| tls_whole | 40.125 | 40.0 | -0.3% | 51.292 |
| tls_fragmented | 52.0 | 51.875 | -0.2% | 63.0 |
| http2_whole | 9.375 | 9.542 | +1.8% | 10.708 |
| http2_fragmented | 16.084 | 16.209 | +0.8% | 18.875 |
| socks5 | 20.875 | 20.917 | +0.2% | 28.417 |
| smtp | 17.209 | 17.291 | +0.5% | 25.75 |
| ssh | 10.958 | 11.125 | +1.5% | 11.875 |
| http_after_identification | 37.0 | 37.292 | +0.8% | 46.417 |
| mqtt | 15.0 | 15.125 | +0.8% | 16.125 |
| resp | 21.375 | 21.334 | -0.2% | 26.958 |
| amqp_091 | 9.083 | 9.167 | +0.9% | 14.25 |
| amqp_10 | 9.083 | 9.125 | +0.5% | 9.75 |
| mqtt5 | 16.562 | 16.791 | +1.4% | 24.458 |
| dns_tcp | 21.25 | 21.542 | +1.4% | 24.791 |
| stun_tcp | 12.75 | 12.875 | +1.0% | 14.667 |
| postgresql_startup | 20.333 | 20.25 | -0.4% | 25.458 |
| postgresql_ssl | 10.166 | 10.25 | +0.8% | 11.209 |
| rfb | 10.125 | 10.292 | +1.6% | 10.916 |
| bittorrent | 23.084 | 23.0 | -0.4% | 29.75 |
| memcached | 14.375 | 14.334 | -0.3% | 18.041 |
| ldap | 13.958 | 14.042 | +0.6% | 16.625 |
| sip_tcp | 102.375 | 102.083 | -0.3% | 124.083 |
| rtsp | 29.542 | 29.458 | -0.3% | 38.625 |
| bgp_open | 16.75 | 16.834 | +0.5% | 25.708 |
| smb2_negotiate | 37.083 | 37.375 | +0.8% | 47.0 |
| smb311_negotiate | 42.958 | 43.208 | +0.6% | 53.208 |

These differences include measurement noise; the largest observed existing-path
p50 increase in this run was 1.8%. This is not a general no-regression guarantee.
An initial run exposed a larger SSH routing cost; early prefix rejection reduced
it before this final measurement. No remaining profile-wide scans were introduced.

## Added profiles

All added inputs below are split into seven-byte chunks.

| Profile | Bytes | Feeds | p50 µs | p99 µs |
|---|---:|---:|---:|---:|
| stomp_connect | 69 | 10 | 33.917 | 43.5 |
| stomp_connected | 27 | 4 | 19.166 | 25.334 |
| nats_info | 123 | 18 | 65.25 | 77.708 |
| nats_connect | 97 | 14 | 54.667 | 66.25 |
| imap_capability | 80 | 12 | 33.833 | 42.583 |
| rdp_negotiate | 19 | 3 | 14.583 | 23.084 |

## Packet adapter

These include IPv4 decoding, reassembly, detection and event construction, but
exclude CaptureMonitor construction, capture syscalls, output and PCAP framing.

| Case | Packets | p50 µs | p99 µs |
|---|---:|---:|---:|
| tcp_http_flow | 3 | 81.542 | 157.167 |
| udp_dns | 1 | 18.042 | 28.583 |

All nine UDP profiles are also compared in the raw report. No UDP validators changed.

Reproduce the current measurements with `make benchmark`; add `--baseline` to
`benchmark_v07.py` with a preserved v0.6.1 project for side-by-side comparison.
The local development snapshot is temporary and is not a portable dependency.

Correctness checks include 147 tests, all stream split points, bytewise input,
HTTP prefix collisions, malformed fields, budgets, mutation and cleanup. Real
IPv4 loopback capture covers 11 families including server-direction handshakes.
The traffic is synthetic. Independent labeled traces and target workloads remain
necessary to measure false positives, missed profiles and production capacity.
