# Local benchmark — v0.6 versus v0.5

Identical fixtures, Python 3.9.6, macOS-26.6.2-arm64-arm-64bit.
500 samples per round, five rounds (2,500 per case/version); warm-up and shuffled version order.
GC enabled. Stream warm-up is 50 flows per case/version; UDP warm-up is 50 per round/version.
Core timing includes feed, parsing and events; excludes Inspector construction, capture,
TCP reassembly, TLS decryption, scheduling, output I/O and concurrent load. Adapter costs
are reported separately. These are CPU samples, not end-to-end SWG latency or an SLA.

Absolute times can differ across runs due to host scheduling/power state. Compare versions
in this same run, rather than comparing absolute values to older report runs.

## Existing stream profiles

| Case | v0.5 p50 µs | v0.6 p50 µs | p50 change | v0.5 p99 µs | v0.6 p99 µs |
|---|---:|---:|---:|---:|---:|
| http_small | 23.75 | 23.708 | -0.2% | 32.875 | 30.542 |
| http_fragmented | 604.084 | 609.812 | 0.9% | 702.375 | 756.458 |
| tls_whole | 38.917 | 38.958 | 0.1% | 44.833 | 43.917 |
| tls_fragmented | 50.292 | 50.458 | 0.3% | 57.75 | 56.5 |
| http2_whole | 9.25 | 9.25 | 0.0% | 10.041 | 9.834 |
| http2_fragmented | 15.875 | 15.833 | -0.3% | 16.542 | 16.375 |
| socks5 | 20.042 | 20.25 | 1.0% | 23.709 | 24.166 |
| smtp | 16.542 | 16.5 | -0.3% | 17.334 | 17.25 |
| ssh | 10.792 | 10.792 | 0.0% | 11.25 | 11.125 |
| http_after_identification | 37.02 | 36.916 | -0.3% | 43.0 | 43.042 |
| mqtt | 15.0 | 15.125 | 0.8% | 15.792 | 15.542 |
| resp | 20.958 | 20.958 | 0.0% | 24.292 | 26.042 |
| amqp_091 | 8.917 | 8.958 | 0.5% | 9.292 | 9.417 |
| amqp_10 | 8.875 | 8.917 | 0.5% | 9.25 | 9.25 |
| mqtt5 | 16.167 | 16.25 | 0.5% | 16.833 | 16.792 |
| dns_tcp | 20.708 | 20.958 | 1.2% | 23.584 | 24.75 |
| stun_tcp | 12.667 | 12.833 | 1.3% | 18.334 | 18.917 |
| postgresql_startup | 19.667 | 19.917 | 1.3% | 26.167 | 25.292 |
| postgresql_ssl | 10.042 | 10.167 | 1.2% | 10.583 | 11.084 |
| rfb | 10.25 | 10.209 | -0.4% | 10.958 | 10.708 |
| bittorrent | 22.375 | 22.416 | 0.2% | 27.833 | 25.542 |
| memcached | 13.875 | 13.917 | 0.3% | 14.458 | 14.416 |
| ldap | 13.833 | 13.916 | 0.6% | 14.5 | 14.917 |
| sip_tcp | 100.916 | 101.625 | 0.7% | 118.208 | 112.917 |
| rtsp | 29.0 | 28.958 | -0.1% | 34.416 | 34.375 |

## Added stream profiles (7-byte chunks)

| Case | p50 µs | p95 µs | p99 µs |
|---|---:|---:|---:|
| bgp_open | 16.417 | 16.75 | 17.917 |
| smb2_negotiate | 36.083 | 36.875 | 43.583 |
| smb311_negotiate | 42.041 | 43.333 | 50.542 |

## UDP messages

| Protocol | v0.5 p50 µs | v0.6 p50 µs | v0.6 p99 µs |
|---|---:|---:|---:|
| dns | 7.709 | 7.917 | 8.375 |
| stun | 4.541 | 4.541 | 4.709 |
| dhcp/4 | 5.042 | 5.042 | 5.375 |
| coap | 5.75 | 6.0 | 6.542 |
| syslog/5424 | 13.792 | 13.792 | 16.875 |
| sip/2.0 | 39.417 | 39.208 | 47.833 |
| snmp/2c | — | 12.792 | 14.0 |
| tftp | — | 8.208 | 8.709 |
| ntp/4 | — | 4.583 | 4.834 |

## Capture adapter CPU cost

Includes link/IP/TCP decoding, prefix reassembly, dispatch, validation and event dictionary.
Excludes CaptureMonitor construction, capture syscalls, PCAP pipe decoding, printing and
concurrency. TCP flow includes SYN, SYN-ACK and one complete HTTP request.

| Workload | Packets | p50 µs | p95 µs | p99 µs |
|---|---:|---:|---:|---:|
| tcp_http_flow | 3 | 80.334 | 141.583 | 154.375 |
| udp_dns | 1 | 17.791 | 18.584 | 24.417 |

## Interpretation

The stream dispatcher still selects at most one parser per initial scope. Adding these
families does not introduce a registry scan. Most existing median costs remain close;
some cases and tail percentiles worsen. UDP gains two bounded candidate probes and
can add work. There is no claim of zero overhead or universally faster performance.

The capture adapter amortizes expiry to one-second sweeps and omits legacy per-protocol
result-list construction. Live capture loss/latency under sustained real traffic has not
been characterized; the successful loopback smoke check is functional verification.

## Reproduce

```bash
python3 -B benchmark_v06.py --baseline /path/to/v05 --iterations 500 --rounds 5
```

The baseline must contain the old `protocol_engine` package. Without `--baseline`,
`make benchmark` measures the current engine only. No old package is silently invented.

Raw measurements, round medians and source hashes: [benchmark-v06.json](benchmark-v06.json).
Loopback functional evidence: [live-smoke-v06.json](live-smoke-v06.json).
