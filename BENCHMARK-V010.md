# v0.10 CPU regression and FIN optimization measurements

Python 3.9.6 / macOS arm64, 2026-10-19. Synthetic inputs only. 500 samples per
round, five rounds, 50 warmups, GC enabled and randomized version order. Engine
and actual capture adapter comparisons ran separately, without concurrent capture
or tests. Source fingerprints and full distributions are in benchmark-v010.json
and benchmark-capture-v010.json. All correctness assertions passed.

These are local CPU costs per fixture, excluding construction/imports, capture
syscalls, output I/O, TLS decryption and concurrency. They are not network/SWG
latency, throughput, accuracy measurements or worst-case bounds. No target latency
or deployment hardware specification has been supplied.

## FIN optimization and lifecycle correctness

The adapter previously scanned present[end:] across the reassembly window to find
bytes beyond FIN. Stream.highest_end now makes that check one integer comparison.
Tests compare the metadata to actual retained positions under gaps, duplicates,
clipped data and ignored bytes outside the window. Contiguous incomplete FIN now
finishes as incomplete; out-of-order FIN waits for gaps. Half-close is per direction.

A preliminary v0.10 measurement before this optimization is preserved as
benchmark-capture-v010-before-fin-optimization.json; its partial-FIN p50 was 419us.
That is a historical measurement of different source. The table below is the final
same-run comparison to v0.9, in isolated subprocesses loading each full adapter.
FIN results intentionally differ because v0.9 left the scope detecting.

| Adapter fixture | v0.9 p50 | v0.10 p50 | v0.9 p99 | v0.10 p99 | Current status |
|---|---:|---:|---:|---:|---|
| http_flow | 80.709 | 78.208 | 162.709 | 88.209 | identified |
| partial_fin | 409.958 | 58.042 | 516.875 | 66.042 | incomplete |
| dns_datagram | 18.459 | 18.25 | 66.292 | 19.542 | identified |

The partial-FIN fixture has three packets (SYN, SYN-ACK, FIN carrying four payload
bytes), using the default 64KiB window. Thus these numbers describe the whole
three-packet adapter path, not a standalone FIN instruction or general traffic.
Other paths retain validation and conflict handling. Lower observed tails also
coincide with removal of owner reference cycles; this run is not a controlled
attribution of all tail improvements. Full endpoint TCP validation remains absent.

## Existing engine paths

49 TCP cases compared against v0.9; largest p50 increase in this run: 3.0% (bittorrent), including noise. No RADIUS work was added to automatic dispatch.

| TCP fixture | v0.9 p50 | v0.10 p50 | v0.10 p95 | v0.10 p99 | p50 change |
|---|---:|---:|---:|---:|---:|
| http_small | 24.542 | 24.458 | 25.667 | 28.875 | -0.3% |
| http_fragmented | 613.125 | 618.27 | 698.917 | 727.042 | +0.8% |
| tls_whole | 39.875 | 39.917 | 41.375 | 45.541 | +0.1% |
| tls_fragmented | 51.25 | 51.041 | 53.209 | 57.5 | -0.4% |
| http2_whole | 9.541 | 9.542 | 10.0 | 10.708 | +0.0% |
| http2_fragmented | 16.084 | 16.167 | 16.833 | 21.5 | +0.5% |
| socks5 | 20.709 | 20.75 | 21.333 | 22.834 | +0.2% |
| smtp | 17.208 | 17.042 | 17.375 | 18.166 | -1.0% |
| ssh | 11.125 | 11.125 | 11.292 | 11.5 | +0.0% |
| http_after_identification | 37.583 | 37.458 | 38.459 | 43.5 | -0.3% |
| mqtt | 15.292 | 15.291 | 15.75 | 16.583 | -0.0% |
| resp | 21.5 | 21.666 | 23.125 | 23.5 | +0.8% |
| amqp_091 | 9.167 | 9.167 | 9.458 | 9.75 | +0.0% |
| amqp_10 | 9.125 | 9.125 | 9.292 | 9.542 | +0.0% |
| mqtt5 | 16.625 | 16.5 | 17.042 | 18.584 | -0.8% |
| dns_tcp | 21.5 | 21.792 | 22.5 | 25.541 | +1.4% |
| stun_tcp | 13.25 | 13.25 | 13.541 | 13.791 | +0.0% |
| postgresql_startup | 20.792 | 20.75 | 21.125 | 21.542 | -0.2% |
| postgresql_ssl | 10.458 | 10.333 | 10.666 | 10.917 | -1.2% |
| rfb | 10.541 | 10.541 | 10.792 | 11.042 | +0.0% |
| bittorrent | 22.583 | 23.25 | 23.792 | 25.167 | +3.0% |
| memcached | 14.416 | 14.459 | 14.708 | 14.916 | +0.3% |
| ldap | 14.292 | 14.291 | 14.709 | 14.917 | -0.0% |
| sip_tcp | 104.042 | 104.709 | 107.666 | 113.458 | +0.6% |
| rtsp | 30.042 | 30.167 | 30.667 | 32.041 | +0.4% |
| bgp_open | 16.958 | 16.959 | 17.292 | 17.542 | +0.0% |
| smb2_negotiate | 37.333 | 37.708 | 38.541 | 40.25 | +1.0% |
| smb311_negotiate | 42.938 | 43.291 | 44.833 | 48.875 | +0.8% |
| stomp_connect | 34.167 | 34.208 | 35.084 | 37.75 | +0.1% |
| stomp_connected | 19.333 | 19.292 | 19.583 | 19.917 | -0.2% |
| nats_info | 67.0 | 66.916 | 70.333 | 75.458 | -0.1% |
| nats_connect | 55.417 | 55.584 | 57.75 | 62.166 | +0.3% |
| imap_capability | 34.167 | 34.25 | 35.5 | 37.291 | +0.2% |
| rdp_negotiate | 14.666 | 14.625 | 14.875 | 15.125 | -0.3% |
| mysql_hint_whole | 13.458 | 13.375 | 13.708 | 14.041 | -0.6% |
| mysql_hint_fragmented | 31.417 | 31.209 | 31.791 | 34.417 | -0.7% |
| mongodb_hint_whole | 15.5 | 15.416 | 15.875 | 18.583 | -0.5% |
| mongodb_hint_fragmented | 27.375 | 27.292 | 27.792 | 33.334 | -0.3% |
| mongodb_crc_3k | 250.625 | 251.084 | 279.0 | 313.792 | +0.2% |
| mongodb_crc_60k_default_budget | 6.25 | 6.25 | 6.417 | 6.625 | +0.0% |
| mongodb_crc_60k_raised_budget | 4483.792 | 4482.542 | 4705.75 | 4788.667 | -0.0% |
| mongodb_binary_60k | 23.75 | 23.625 | 24.25 | 24.916 | -0.5% |
| fastcgi_whole | 16.166 | 16.167 | 17.875 | 18.417 | +0.0% |
| fastcgi_fragmented | 26.959 | 26.917 | 27.792 | 30.791 | -0.2% |
| fastcgi_binary_60k | 21.834 | 21.667 | 22.334 | 23.792 | -0.8% |
| fastcgi_128_params | 102.5 | 101.875 | 106.042 | 110.416 | -0.6% |
| fastcgi_128_records | 295.083 | 292.416 | 301.625 | 316.25 | -0.9% |
| rsync_whole | 10.792 | 10.792 | 11.084 | 11.417 | +0.0% |
| rsync_fragmented | 18.584 | 18.75 | 19.209 | 20.25 | +0.9% |

## UDP paths and new RADIUS budgets

| UDP fixture | v0.9 p50 | v0.10 p50 | v0.10 p95 | v0.10 p99 |
|---|---:|---:|---:|---:|
| dns | 8.041 | 8.0 | 8.334 | 8.666 |
| stun | 4.542 | 4.542 | 4.667 | 4.75 |
| dhcp/4 | 5.167 | 5.167 | 5.333 | 5.417 |
| coap | 6.125 | 6.084 | 6.292 | 6.375 |
| syslog/5424 | 13.417 | 13.459 | 14.667 | 14.834 |
| sip/2.0 | 40.916 | 40.75 | 42.291 | 47.416 |
| snmp/2c | 13.208 | 13.188 | 14.084 | 14.25 |
| tftp | 8.459 | 8.417 | 8.666 | 8.75 |
| ntp/4 | 4.917 | 4.916 | 5.042 | 5.166 |
| radius | new | 7.417 | 7.75 | 7.875 |
| radius_128_attributes | new | 66.375 | 68.916 | 72.583 |
| radius_4096_bytes | new | 14.708 | 15.083 | 15.417 |

RADIUS is explicitly hinted, structure-only, with no HMAC/credential verification.
The 128-attribute fixture illustrates count cost; a 4096-byte packet with fewer,
longer opaque values is cheaper. Bounds: min(max_headers,128) attributes and 4096
RADIUS bytes, plus the general datagram budget. Existing MongoDB default CRC limit
still refuses large checksum work; raised-limit case remains millisecond-scale.

## Reproduce and verification

```bash
python3 -B benchmark_v010.py --baseline /path/to/v09-project --iterations 500 --rounds 5
python3 -B benchmark_capture_v010.py --baseline /path/to/v09-project --iterations 500 --rounds 5
```

The second comparison needs a full baseline project, not just the engine package.
Temporary preserved baseline: /private/tmp/protocol-engine-v09-baseline. Historical
pre-optimization source: /private/tmp/protocol-engine-v010-before-fin-optimization.
Neither is a runtime dependency. No baseline flag means current measurements only.

209 tests passed, including published RFC2865 PAP/CHAP examples, RADIUS/DNS overlap,
FIN gaps/wrap/retransmissions/half-close, bounded parsing and owner-cycle release.
Synthetic IPv4 loopback smoke passed for base 13 families/15 detections, MySQL1,
MongoDB2, RADIUS1, with zero kernel drops reported. Base/RADIUS capture reran after
FIN optimization. Expanded synthetic replay: 96 packets/30 detections; 22 empty
reverse directions incomplete and zero active connections at EOF. RADIUS PCAP:
one hinted identification. No external traffic or actual RADIUS authentication.
