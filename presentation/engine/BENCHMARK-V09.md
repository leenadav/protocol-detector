# v0.9 measured CPU regression report

Measured on 2026-10-19, Python 3.9.6 / macOS arm64. Same-run comparison to the
preserved v0.8 engine, identical fixtures and expected statuses. 500 flows per
round, five rounds, 50 warmups per case/version; randomized version order with
seed 402. GC enabled. All correctness assertions passed. Capture tests had ended
before timing. Raw samples are summarized in benchmark-v09.json, including each
round's median and source SHA256 fingerprints.

Timer includes feed calls and event construction; excludes Inspector/Config/rule
construction, imports, packet capture, reassembly, TLS decryption, output I/O and
concurrency. A separate adapter measurement includes packet decoding/reassembly
but still excludes capture syscalls and output. Values are microseconds per whole
fixture flow, not per packet, throughput, end-to-end SWG latency or a guarantee.
There is no user-specified latency target or independently labeled traffic corpus.

## Existing paths: v0.8 versus v0.9

42 TCP cases were compared. Largest median increase was 2.1% (fragmented HTTP),
including measurement noise; this is an observation from this run, not a
statistical bound. New dispatch work is limited to the existing 0/1 branch and
a static @ table entry. No registry scan or added body work on HTTP/TLS paths.

| Fixture | v0.8 p50 | v0.9 p50 | v0.9 p95 | v0.9 p99 | p50 change |
|---|---:|---:|---:|---:|---:|
| http_small | 24.708 | 24.625 | 26.166 | 29.792 | -0.3% |
| http_fragmented | 603.958 | 616.48 | 666.792 | 693.375 | +2.1% |
| tls_whole | 39.333 | 39.291 | 40.375 | 43.791 | -0.1% |
| tls_fragmented | 50.542 | 50.709 | 52.375 | 57.125 | +0.3% |
| http2_whole | 9.583 | 9.583 | 10.0 | 10.25 | +0.0% |
| http2_fragmented | 16.125 | 16.083 | 16.375 | 16.708 | -0.3% |
| socks5 | 20.75 | 20.75 | 21.416 | 22.459 | +0.0% |
| smtp | 17.125 | 17.209 | 17.5 | 19.083 | +0.5% |
| ssh | 11.167 | 11.167 | 11.375 | 11.625 | +0.0% |
| http_after_identification | 37.458 | 37.209 | 38.0 | 43.041 | -0.7% |
| mqtt | 15.125 | 15.125 | 15.583 | 16.541 | +0.0% |
| resp | 21.333 | 21.208 | 21.792 | 25.416 | -0.6% |
| amqp_091 | 9.25 | 9.292 | 9.459 | 9.625 | +0.5% |
| amqp_10 | 9.25 | 9.292 | 9.459 | 9.75 | +0.5% |
| mqtt5 | 16.541 | 16.541 | 16.917 | 18.375 | +0.0% |
| dns_tcp | 21.417 | 21.458 | 22.125 | 24.875 | +0.2% |
| stun_tcp | 13.167 | 13.208 | 13.5 | 14.667 | +0.3% |
| postgresql_startup | 20.375 | 20.459 | 20.833 | 22.041 | +0.4% |
| postgresql_ssl | 10.542 | 10.541 | 10.708 | 10.916 | -0.0% |
| rfb | 10.583 | 10.542 | 10.75 | 10.916 | -0.4% |
| bittorrent | 22.958 | 22.917 | 23.25 | 25.875 | -0.2% |
| memcached | 14.333 | 14.334 | 14.583 | 15.0 | +0.0% |
| ldap | 14.292 | 14.334 | 14.75 | 15.166 | +0.3% |
| sip_tcp | 102.458 | 102.209 | 103.875 | 109.875 | -0.2% |
| rtsp | 29.75 | 29.708 | 30.125 | 31.708 | -0.1% |
| bgp_open | 16.833 | 16.791 | 17.042 | 17.375 | -0.2% |
| smb2_negotiate | 36.917 | 36.917 | 37.459 | 40.375 | +0.0% |
| smb311_negotiate | 42.75 | 42.875 | 43.541 | 46.084 | +0.3% |
| stomp_connect | 34.0 | 34.041 | 35.209 | 38.458 | +0.1% |
| stomp_connected | 19.667 | 19.542 | 19.875 | 20.834 | -0.6% |
| nats_info | 64.75 | 64.542 | 66.583 | 70.542 | -0.3% |
| nats_connect | 54.542 | 54.5 | 55.792 | 64.75 | -0.1% |
| imap_capability | 34.042 | 34.083 | 34.625 | 36.791 | +0.1% |
| rdp_negotiate | 14.416 | 14.375 | 16.167 | 16.458 | -0.3% |
| mysql_hint_whole | 13.5 | 13.417 | 13.833 | 14.042 | -0.6% |
| mysql_hint_fragmented | 30.708 | 30.833 | 31.417 | 36.917 | +0.4% |
| mongodb_hint_whole | 15.375 | 15.333 | 15.709 | 17.209 | -0.3% |
| mongodb_hint_fragmented | 27.0 | 26.959 | 27.458 | 31.75 | -0.2% |
| mongodb_crc_3k | 252.917 | 251.875 | 262.125 | 275.292 | -0.4% |
| mongodb_crc_60k_default_budget | 6.208 | 6.166 | 6.292 | 6.458 | -0.7% |
| mongodb_crc_60k_raised_budget | 4472.146 | 4474.833 | 4624.125 | 4721.416 | +0.1% |
| mongodb_binary_60k | 23.833 | 23.959 | 24.583 | 26.583 | +0.5% |

## New paths

| Fixture | p50 | p95 | p99 |
|---|---:|---:|---:|
| fastcgi_whole | 16.375 | 16.792 | 19.875 |
| fastcgi_fragmented | 27.458 | 28.166 | 33.833 |
| fastcgi_binary_60k | 22.0 | 22.5 | 27.625 |
| fastcgi_128_params | 101.542 | 104.875 | 108.792 |
| fastcgi_128_records | 297.375 | 306.583 | 316.667 |
| rsync_whole | 10.959 | 11.25 | 11.458 |
| rsync_fragmented | 19.25 | 19.583 | 20.459 |

FastCGI large binary values are skipped by length during validation, not decoded.
Small parameter/record counts matter: 128 records cost roughly 297 microseconds,
versus 16 for the small fixture. Both record and parameter counts are bounded at
min(max_headers,128); applications may lower max_headers to reduce allowed work,
with corresponding coverage loss. This does not establish a worst-case time bound.
Rsync line and digest bounds cap its parser work; only greetings are inspected.
MongoDB's separate default CRC budget remains unchanged: the 60KiB checksummed
case is rejected. Explicitly raising that budget costs roughly 4.5ms on this host.

## Datagram and capture adapter

| UDP fixture | v0.8 p50 | v0.9 p50 | v0.9 p99 |
|---|---:|---:|---:|
| dns | 8.083 | 8.042 | 9.792 |
| stun | 4.584 | 4.584 | 4.792 |
| dhcp/4 | 5.166 | 5.125 | 5.375 |
| coap | 6.166 | 6.167 | 6.5 |
| syslog/5424 | 13.458 | 13.416 | 14.166 |
| sip/2.0 | 41.25 | 41.167 | 42.542 |
| snmp/2c | 13.375 | 13.375 | 14.625 |
| tftp | 8.625 | 8.625 | 9.083 |
| ntp/4 | 5.0 | 5.0 | 5.208 |

| Current adapter fixture | p50 | p95 | p99 |
|---|---:|---:|---:|
| tcp_http_flow | 77.917 | 130.917 | 154.541 |
| udp_dns | 18.084 | 18.958 | 65.708 |

Adapter tails include scheduler/noise effects and are not claimed as production
capacity. This run compares engine versions, not adapter versions.

## Reproduce and provenance

```bash
python3 -B benchmark_v09.py --baseline /path/to/v08-project --iterations 500 --rounds 5
```

The baseline directory must contain its protocol_engine package. Without
--baseline the tool measures current behavior only. Temporary development path
/private/tmp/protocol-engine-v08-baseline is not a runtime dependency.
Primary protocol sources and exact scope are in PROTOCOLS.md. Verification:
181 unit tests, 96-packet synthetic PCAP replay / 30 detections / EOF, and real
IPv4 loopback capture with synthetic payloads / 13 families / 15 detections /
zero reported kernel drops. No real FastCGI application or rsync daemon session,
external traffic, integration or production accuracy corpus was exercised.
