# v0.22 App-ID verdict layer and session ledger CPU comparison

Python 3.13.16 on Linux-6.18.44-fc-v139-x86_64-with-glibc2.39 (cloud container, 4 vCPU, no pinning).
Five shuffled paired subprocess rounds of 300 samples per case after 50 warmups,
`python3 -B benchmark_capture_v022.py --baseline <v0.21 checkout> --iterations 300 --rounds 5`.
Synthetic IPv4 packet decoding through emitted capture events; excludes monitor
construction, capture and output I/O. Microseconds per flow/datagram on this
host; absolute values are not comparable with the Mac numbers in earlier
BENCHMARK files, only the paired v0.21/v0.22 ratio is meaningful here.

| Case | v0.21 p50 | v0.22 p50 | Change |
|---|---:|---:|---:|
| tls_server12 | 74.745 | 83.657 | +11.9% |
| tls_server13 | 76.171 | 83.573 | +9.7% |
| tls_retry | 75.671 | 82.403 | +8.9% |
| dcerpc_flow | 64.260 | 71.796 | +11.7% |
| socks_flow | 65.996 | 74.165 | +12.4% |
| giop_flow | 62.101 | 69.740 | +12.3% |
| http_giop_method | 82.347 | 90.629 | +10.1% |
| git_flow | 85.260 | 92.760 | +8.8% |
| http_git_method | 88.338 | 99.737 | +12.9% |
| tls_flow | 102.775 | 113.845 | +10.8% |
| ssh_flow | 61.833 | 72.275 | +16.9% |
| http_flow | 82.260 | 92.674 | +12.7% |
| partial_fin | 60.992 | 63.508 | +4.1% |
| dns_datagram | 21.284 | 30.021 | +41.0% |
| reordered_http | 97.412 | 110.198 | +13.1% |
| leading_duplicate | 98.109 | 114.282 | +16.5% |
| old_payload_after_fin | 115.552 | 122.481 | +6.0% |
| pre_origin_fin | 67.505 | 72.169 | +6.9% |
| control_rejection | 117.528 | 134.140 | +14.1% |
| leading_conflict | 113.263 | 131.390 | +16.0% |
| dtls_datagram | 25.924 | 34.072 | +31.4% |
| udp_unknown | 12.305 | 14.819 | +20.4% |
| udp_dns | 21.036 | 29.946 | +42.4% |
| udp_stun | 15.564 | 24.154 | +55.2% |
| udp_dhcp_4 | 16.610 | 25.812 | +55.4% |
| udp_coap | 17.868 | 26.498 | +48.3% |
| udp_syslog_5424 | 28.618 | 37.859 | +32.3% |
| udp_sip_2.0 | 57.181 | 66.353 | +16.0% |
| udp_snmp_2c | 24.590 | 33.935 | +38.0% |
| udp_tftp | 21.001 | 29.912 | +42.4% |
| ike_datagram | 35.916 | 44.661 | +24.3% |
| ike_marker | 36.816 | 45.301 | +23.0% |
| ike_coap_ambiguous | 36.092 | 38.705 | +7.2% |
| tls_rsa_ec_invalid | 64.629 | 66.541 | +3.0% |
| full_session | 171.477 | 205.716 | +20.0% |
| udp_flow_pair | 40.017 | 57.791 | +44.4% |

## What changed and what it costs

v0.22 performs new work on every event and at every connection end:

- `appid.classify` per emitted classification event: about 2.1 us (NamedTuple
  verdict, catalog dictionary reads, precomputed port tables). It was 3.9 us
  with a frozen dataclass and per-call port parsing before optimization.
- Per-connection counters (packets, payload bytes per endpoint) and the UDP flow
  table entry: about 2-3 us per packet/datagram, dominated by dictionary work.
- One session record per retired connection/flow (`session_verdict` plus
  `verdict_fields`): paid once at retirement, visible in `full_session`.

Short UDP datagram cases therefore show the largest relative change (about
+8-9 us on a 15-25 us baseline); TCP flows change by +6..+17 us across three
packets. These are additional semantics (a session verdict and a traffic-log
record that v0.21 did not produce), not slower parsing: the parser paths are
unchanged and `tls_rsa_ec_invalid`/`ike_coap_ambiguous`, which emit no
identification, move by +3%/+7% (host noise plus counter updates). The two new
cases exercise the ledger end to end: `full_session` (handshake, request,
response, both FINs; one session record) and `udp_flow_pair` (two datagrams in
one flow).

Raw p95/p99, statuses and source/harness SHA256 values are in
benchmark-capture-v022.json. No production latency, throughput or detection
accuracy claim is made; measure on target hardware with representative traffic.

## Verification

324 tests pass (15 new in test_appid.py: catalog integrity, verdict precedence,
custom mappings, port usage, session records for complete/handshake-only/
SYN-only/insufficient-data/unknown/rejected TCP sessions, bounded UDP flows,
hostname opt-in, live and offline output). Offline replay of
sample-expanded.pcap produces 30 TCP/UDP session records with the expected
applications; the live smoke test could not be executed in this container
(no tcpdump installed) and remains an operator check.


## Erratum (recorded in v0.24)

The paired table above compared a byte-compiled development tree against a
fresh baseline checkout without `__pycache__`. CPython executes code compiled
from source at import time about 50% slower than code loaded from `.pyc` on
this interpreter, so the baseline column is pessimistic. See BENCHMARK-V024.md
for the corrected v0.21 -> v0.24 chain measured with `benchmark_ab.py`, which
byte-compiles both trees first.
