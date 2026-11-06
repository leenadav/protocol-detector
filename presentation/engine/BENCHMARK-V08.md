# Local performance measurement — v0.8

Measured 2026-10-19, Python 3.9.6.
500 samples per round, five shuffled-order rounds, 50 warmups per case/version.
Existing cases run against the same preserved v0.7 engine snapshot on identical inputs.
Final measurements ran after capture smoke tests completed. Host activity and timing
noise are not controlled as in a dedicated performance lab. Raw report and source
fingerprints: [benchmark-v08.json](benchmark-v08.json).

Feed-loop timing includes parsing and events; excludes Inspector construction,
capture, TCP reassembly, TLS decryption, logging and concurrency. These are not
end-to-end SWG latency or throughput guarantees. Absolute time depends on hardware.

## Existing TCP profiles

| Case | v0.7 p50 µs | v0.8 p50 µs | Change | v0.8 p99 µs |
|---|---:|---:|---:|---:|
| http_small | 24.416 | 24.334 | -0.3% | 30.0 |
| http_fragmented | 594.562 | 600.792 | +1.0% | 649.75 |
| tls_whole | 38.917 | 39.25 | +0.9% | 45.667 |
| tls_fragmented | 50.542 | 50.708 | +0.3% | 62.292 |
| http2_whole | 9.75 | 9.75 | +0.0% | 10.25 |
| http2_fragmented | 16.125 | 16.084 | -0.3% | 16.916 |
| socks5 | 20.541 | 20.417 | -0.6% | 23.708 |
| smtp | 16.917 | 16.833 | -0.5% | 17.916 |
| ssh | 11.0 | 11.0 | +0.0% | 12.625 |
| http_after_identification | 37.125 | 37.083 | -0.1% | 43.041 |
| mqtt | 15.125 | 15.166 | +0.3% | 17.625 |
| resp | 20.875 | 21.105 | +1.1% | 26.541 |
| amqp_091 | 9.125 | 9.125 | +0.0% | 9.708 |
| amqp_10 | 9.0 | 9.042 | +0.5% | 9.5 |
| mqtt5 | 16.583 | 16.625 | +0.3% | 21.0 |
| dns_tcp | 21.083 | 21.083 | +0.0% | 23.958 |
| stun_tcp | 12.875 | 12.916 | +0.3% | 16.042 |
| postgresql_startup | 20.083 | 20.042 | -0.2% | 23.166 |
| postgresql_ssl | 10.541 | 10.458 | -0.8% | 10.875 |
| rfb | 10.334 | 10.375 | +0.4% | 10.875 |
| bittorrent | 22.125 | 22.208 | +0.4% | 24.25 |
| memcached | 14.042 | 14.0 | -0.3% | 14.5 |
| ldap | 14.083 | 13.834 | -1.8% | 15.542 |
| sip_tcp | 101.167 | 101.333 | +0.2% | 111.291 |
| rtsp | 29.417 | 29.208 | -0.7% | 31.583 |
| bgp_open | 16.084 | 16.083 | -0.0% | 16.541 |
| smb2_negotiate | 35.583 | 35.666 | +0.2% | 40.166 |
| smb311_negotiate | 41.375 | 41.375 | +0.0% | 45.333 |
| stomp_connect | 33.208 | 33.167 | -0.1% | 37.708 |
| stomp_connected | 18.875 | 18.75 | -0.7% | 19.833 |
| nats_info | 63.75 | 63.792 | +0.1% | 71.042 |
| nats_connect | 52.959 | 52.895 | -0.1% | 58.917 |
| imap_capability | 33.959 | 33.792 | -0.5% | 37.417 |
| rdp_negotiate | 14.25 | 14.292 | +0.3% | 15.125 |

The largest observed existing-path p50 increase was 1.1%. These differences
include noise and do not prove the absence of regressions on other workloads.
Automatic dispatch is unchanged. A hint adds caller-context evidence only after
successful validation; it never establishes a match on its own.

## Database and checksum paths

All new cases explicitly select a candidate. Fragmented cases use seven-byte feeds.

| Case | Input bytes | Result | CRC budget | p50 µs | p99 µs |
|---|---:|---|---:|---:|---:|
| mysql_hint_whole | 83 | identified | 4096 | 13.25 | 13.792 |
| mysql_hint_fragmented | 83 | identified | 4096 | 30.5 | 34.541 |
| mongodb_hint_whole | 52 | identified | 4096 | 15.209 | 17.459 |
| mongodb_hint_fragmented | 52 | identified | 4096 | 26.375 | 32.292 |
| mongodb_crc_3k | 3138 | identified | 4096 | 253.208 | 293.542 |
| mongodb_crc_60k_default_budget | 61506 | budget_exhausted | 4096 | 6.125 | 6.458 |
| mongodb_crc_60k_raised_budget | 61506 | identified | 65536 | 4506.042 | 4717.584 |
| mongodb_binary_60k | 61502 | identified | 4096 | 24.833 | 30.417 |

The 60KiB checksummed case is refused by the default budget. This is an intentional
budget_exhausted result, **not a successful protocol detection**. The decision is
available from the first 20 bytes; the benchmark submits the whole frame in one
feed. On errors bytes_inspected conservatively charges submitted bytes, not CPU
reads. The parser does not accumulate the body before this decision.

The same case with an explicitly raised 65536-byte CRC budget takes milliseconds.
Slicing-by-eight reduces Python loop work but does not make large checksums cheap.
The 4096-byte default is a configurable work bound, not an SLA or a selected SWG
latency target. Choose lower limits where required; zero refuses checksummed input.
No checksum is silently skipped. Non-checksummed large binary values are framed
and skipped without interpreting their opaque subtype contents.

## Packet adapter

These include IPv4 packet decoding, bounded reassembly, detection and event
construction. They exclude CaptureMonitor construction, capture syscalls, output
and PCAP framing. Config is now immutable and shared between stream inspectors.

| Case | Packets | p50 µs | p99 µs |
|---|---:|---:|---:|
| tcp_http_flow | 3 | 77.958 | 190.0 |
| udp_dns | 1 | 18.0 | 64.958 |

The raw report also compares all nine existing UDP profiles. No UDP validators changed.

## Validation and reproduction

165 tests pass. Coverage includes published BSON and CRC-32C vectors, all stream
split points, bytewise input, EOF, candidate provenance, malformed structure,
budget limits, seeded mutation, state release, reassembly and both CLI paths.
Real IPv4 loopback reports cover the existing 11-family smoke plus MySQL server
handshake and MongoDB requests with and without CRC. All traffic is synthetic.
The small published vector subset is not a full independent traffic corpus.

`make benchmark` measures current code. For comparison use
`python3 -B benchmark_v08.py --baseline /path/to/v07 --iterations 500 --rounds 5`.
The report fingerprints engine, capture adapter, fixture and benchmark source.
Old reports remain historical. Target-hardware workloads and labeled production
traces are still needed to establish accuracy, tail latency and capacity.
