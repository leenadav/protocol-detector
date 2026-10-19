# v0.4 versus v0.3: local engine measurements

Measured on 2026-10-19 with Python 3.9.6.
Platform: `macOS-26.6.2-arm64-arm-64bit`.

Each result pools 5 rounds of 500 flows (2,500 samples), after 50 warmup flows
per case/version. A seeded shuffle changes version order between rounds.
GC remains enabled. Both versions receive the same bytes and fragmentation;
each sample asserts the expected identified protocol. Existing parsers have
unchanged protocol checks. New recognizers are measured only in v0.4.

Times cover the Python feed loop, parser and classification events. Inspector
construction and shared Config/RuleIndex construction occur before timing.
Import, packet capture/reassembly, TLS decryption, forwarding, concurrency and
logging are excluded. These are processing costs, not time waiting for enough
network bytes, end-to-end SWG latency, throughput or a production SLA.

| Fixture | v0.3 p50 µs | v0.4 p50 µs | p50 change | v0.4 p95 µs | v0.4 p99 µs |
|---|---:|---:|---:|---:|---:|
| http_small | 12.583 | 11.875 | -5.6% | 14.917 | 18.875 |
| http_fragmented | 307.354 | 301.541 | -1.9% | 337.0 | 351.167 |
| tls_whole | 19.666 | 19.25 | -2.1% | 20.584 | 25.75 |
| tls_fragmented | 25.583 | 24.833 | -2.9% | 27.375 | 33.708 |
| http2_whole | 12.166 | 4.666 | -61.6% | 4.958 | 6.25 |
| http2_fragmented | 14.083 | 7.666 | -45.6% | 8.25 | 10.334 |
| socks5 | 10.5 | 10.083 | -4.0% | 10.75 | 11.875 |
| smtp | 8.667 | 8.0 | -7.7% | 8.459 | 10.583 |
| ssh | 5.75 | 5.166 | -10.2% | 5.5 | 6.792 |
| http_after_identification | 19.25 | 18.542 | -3.7% | 19.75 | 24.792 |
| mqtt | — | 7.209 | new | 7.708 | 8.584 |
| resp | — | 10.083 | new | 10.917 | 13.333 |
| amqp_091 | — | 4.459 | new | 4.75 | 4.916 |
| amqp_10 | — | 4.292 | new | 4.584 | 5.791 |

The clearest change is HTTP/2: bounded prefix comparison replaces 24 Python
routing iterations, and complete input uses one parser call instead of two.
For fragmented HTTP/2 the routing prefix is retained until it can be resolved;
only the selected parser receives it. Complete HTTP/1/TLS/SOCKS5 inputs also
avoid the old separate one-byte parser call.

Small percentage changes may reflect measurement noise. Some p99 values
(SMTP, SSH and the post-identification fixture) increased slightly in this
run; no universal tail-latency improvement is claimed. Repeat with independent
runs and representative traffic under load before using these numbers for
capacity planning. The dispatcher has a fixed small family set; this does not
benchmark thousands of protocol signatures.

Raw distributions, per-round medians, input sizes, call counters and SHA-256
digests of the engine source packages are in [benchmark-v04.json](benchmark-v04.json).

Reproduce with a preserved v0.3 checkout or an extracted pre-v0.4 backup:

```bash
python3 -B benchmark_compare.py --baseline /path/to/v0.3 --iterations 500 --rounds 5
```

The baseline directory must contain its original `protocol_engine` package.
Omit `--baseline` for current-only measurements. The old benchmark_engine.py
is retained for historical comparisons to the weaker educational detector;
that detector is not the baseline in this report.
