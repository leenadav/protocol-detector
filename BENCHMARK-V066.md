# Benchmark v0.66

`python3 -B benchmark_engine.py --iterations 300` on the cloud container (Python 3.13.16, Linux-6.18.44-fc-v300-x86_64-with-glibc2.39): local CPU microbenchmark including Python call overhead; not a production latency figure. v0.66 adds three UDP datagram families and DNS layout repairs; the stream hot path is unchanged from v0.65 (behaviour diff: no stream differences), so the stream cases are the regression reference for the port. The Mac v0.59 numbers in the superseded BENCHMARK-V059.md were measured on other hardware and are not comparable.

| case | flow p50 / p95 / p99 µs | feed p50 / p95 / p99 µs | parser calls | bytes inspected |
|---|---|---|---|---|
| http_small (incremental) | 25.1 / 30.7 / 45.3 | 24.7 / 30.4 / 44.9 | 1 | 37 |
| http_fragmented (incremental) | 401.9 / 437.3 / 458.1 | 0.9 / 1.3 / 12.2 | 190 | 6050 |
| tls_fragmented (incremental) | 51.4 / 67.8 / 75.6 | 1.0 / 27.9 / 29.5 | 17 | 517 |
| http_after_identification (incremental) | 39.8 / 48.2 / 60.2 | 0.1 / 0.2 / 23.8 | 1 | 37 |
| rules_30000 | 24.7 / 28.3 / 45.8 | 24.4 / 28.0 / 45.4 | 1 | 43 |
| rules_0_same_request | 24.7 / 28.8 / 44.8 | 24.4 / 28.4 / 44.5 | 1 | 43 |
| http2 | 12.1 / 13.9 / 30.3 | 1.5 / 5.1 / 6.1 | 2 | 33 |
| socks5 | 16.9 / 19.7 / 36.5 | 2.8 / 12.7 / 17.0 | 3 | 21 |
| smtp | 19.3 / 21.4 / 40.4 | 3.6 / 13.0 / 16.4 | 4 | 25 |
| mqtt | 9.0 / 10.9 / 27.6 | 2.1 / 6.1 / 9.1 | 3 | 18 |
| resp | 12.7 / 14.1 / 21.5 | 3.1 / 4.6 / 6.0 | 4 | 25 |
| amqp_091 | 6.9 / 8.4 / 14.3 | 3.7 / 4.7 / 7.6 | 2 | 8 |
| amqp_10 | 6.7 / 8.3 / 20.6 | 3.7 / 4.5 / 8.3 | 2 | 8 |

RuleIndex build: 149.5 ms for 30,000 rules.

New datagram families (one `DatagramInspector.inspect` call each, 2,000 iterations):

| datagram | p50 µs | p99 µs | result |
|---|---|---|---|
| lifx-lan GetService | 7.3 | 23.1 | identified lifx-lan |
| tuya-lan UDP_NEW | 7.0 | 22.2 | identified tuya-lan |
| tplink-smarthome sysinfo | 14.9 | 47.6 | identified tplink-smarthome |
| mdns SRV-pointer response | 16.0 | 51.4 | identified mdns |
