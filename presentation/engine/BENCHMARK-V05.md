# v0.5 versus v0.4: bounded coverage expansion

Measured 2026-10-19, Python 3.9.6.
`macOS-26.6.2-arm64-arm-64bit`.

Each TCP result pools five rounds of 500 flows after 50 warmups per case/version.
Order alternates using a seeded shuffle. Both versions receive identical bytes and
fragmentation, and each result is checked against its expected protocol. GC remains
enabled. UDP has 2,500 samples after 50 warmups; there is no UDP baseline in v0.4.

Timing includes the feed loop, validation and observation/event creation. Inspector
construction, imports, capture/reassembly, TLS decryption, network forwarding, logging
and concurrency are excluded. This is CPU processing time, not latency waiting for
a peer to send sufficient bytes, product latency, line rate or a production SLA.

## Existing stream workloads

| Fixture | v0.4 p50 µs | v0.5 p50 µs | Change | v0.5 p95 µs | v0.4 p99 µs | v0.5 p99 µs |
|---|---:|---:|---:|---:|---:|---:|
| http_small | 11.792 | 11.792 | 0.0% | 14.667 | 18.708 | 17.958 |
| http_fragmented | 320.959 | 320.833 | -0.0% | 357.375 | 375.875 | 376.75 |
| tls_whole | 19.5 | 19.458 | -0.2% | 20.792 | 24.0 | 26.125 |
| tls_fragmented | 25.084 | 25.167 | 0.3% | 27.0 | 33.458 | 32.875 |
| http2_whole | 4.625 | 4.708 | 1.8% | 5.0 | 6.292 | 6.458 |
| http2_fragmented | 7.583 | 7.75 | 2.2% | 8.209 | 12.167 | 10.375 |
| socks5 | 9.958 | 10.0 | 0.4% | 11.459 | 15.167 | 15.625 |
| smtp | 7.958 | 8.417 | 5.8% | 9.0 | 10.833 | 11.458 |
| ssh | 4.959 | 5.292 | 6.7% | 5.708 | 6.625 | 7.084 |
| http_after_identification | 18.625 | 18.708 | 0.4% | 20.041 | 24.459 | 24.625 |
| mqtt | 7.125 | 7.417 | 4.1% | 7.958 | 9.5 | 9.583 |
| resp | 10.334 | 10.459 | 1.2% | 11.209 | 14.041 | 13.917 |
| amqp_091 | 4.334 | 4.417 | 1.9% | 4.792 | 5.542 | 6.0 |
| amqp_10 | 4.333 | 4.417 | 1.9% | 4.75 | 8.583 | 6.0 |

The final run kept HTTP p50 essentially unchanged while adding 12 families and
MQTT5. Some small workloads increased: SMTP by about 0.46 µs and SSH by about
0.33 µs at p50 in this run. Tail percentiles vary in both directions; TLS whole
p99 rose from 24.0 to 26.125 µs. These costs are reported, not treated as zero overhead.
Small differences and single-host percentiles need repeated target-environment
measurements before deployment decisions.

The data path still selects one stream parsing pipeline and at most two prefiltered
UDP validators, independent of the capability catalog. Shared text uses a direct
unbound handler after family selection. A lifecycle regression test proves completed
HTTP/SIP/RTSP parsers release without waiting for cyclic GC.

## New stream profiles (seven-byte input chunks)

| Fixture | p50 µs | p95 µs | p99 µs | Bytes |
|---|---:|---:|---:|---:|
| mqtt5 | 8.125 | 8.792 | 12.5 | 19 |
| dns_tcp | 10.25 | 11.291 | 15.708 | 35 |
| stun_tcp | 6.25 | 6.75 | 9.083 | 20 |
| postgresql_startup | 9.709 | 10.667 | 15.0 | 36 |
| postgresql_ssl | 5.0 | 5.375 | 6.833 | 8 |
| rfb | 5.166 | 5.542 | 7.667 | 12 |
| bittorrent | 11.208 | 12.125 | 16.0 | 68 |
| memcached | 6.834 | 7.333 | 9.25 | 27 |
| ldap | 6.958 | 7.375 | 7.916 | 14 |
| sip_tcp | 50.958 | 55.25 | 64.291 | 247 |
| rtsp | 14.5 | 15.5 | 19.416 | 57 |

## Complete UDP messages

| Protocol | p50 µs | p95 µs | p99 µs | Bytes |
|---|---:|---:|---:|---:|
| dns | 3.833 | 4.0 | 4.208 | 33 |
| stun | 2.25 | 2.417 | 2.583 | 20 |
| dhcp/4 | 2.5 | 2.709 | 2.875 | 244 |
| coap | 2.958 | 3.167 | 3.958 | 13 |
| syslog/5424 | 6.5 | 7.166 | 9.042 | 93 |
| sip/2.0 | 20.542 | 23.0 | 27.875 | 247 |

## Reproduce

```bash
python3 -B benchmark_v05.py --baseline /path/to/v0.4 --iterations 500 --rounds 5
```

The baseline directory must contain the preserved v0.4 protocol_engine package.
Use an extracted pre-v0.5 backup or checkout. Omit --baseline to measure current
only. [benchmark-v05.json](benchmark-v05.json) records source hashes, per-round
medians, p50/p95/p99, input sizes and parser-call counters. Representative real
SWG replay, independently labeled accuracy tests, mixed loads, many concurrent
flows, memory/GC and end-to-end tail latency remain necessary. A list of 21 families
is not a benchmark of thousands of arbitrary signatures.
