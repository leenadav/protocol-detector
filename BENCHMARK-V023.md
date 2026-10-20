# v0.23 custom signatures: context retention and evaluation cost

Python 3.13.16 on Linux-6.18.44-fc-v139-x86_64-with-glibc2.39 (shared cloud container, 4 vCPU).

## Method note: the paired subprocess harness is noise-dominated on this host

`benchmark_capture_v023.py --baseline <v0.22> --iterations 200 --rounds 10`
(raw data: benchmark-capture-v023.json) produced swings of -35%..+19% between
v0.22 and v0.23 on cases whose code path did not change (for example `http_flow`
-34.8% and `udp_syslog_5424` +19.0%), and a previous run with 5 rounds showed the
same cases with the opposite sign. The container's CPU frequency and neighbour
load vary faster than the shuffled rounds can average out, so **the paired table
below is reproduced for completeness only and must not be read as a v0.23
regression or improvement**.

| Case | v0.22 p50 | v0.23 p50 | Change |
|---|---:|---:|---:|
| tls_server12 | 128.729 | 90.485 | -29.7% |
| tls_server13 | 128.641 | 98.525 | -23.4% |
| tls_retry | 111.823 | 115.171 | +3.0% |
| dcerpc_flow | 97.454 | 78.700 | -19.2% |
| socks_flow | 104.888 | 80.124 | -23.6% |
| giop_flow | 104.599 | 70.643 | -32.5% |
| http_giop_method | 144.440 | 98.219 | -32.0% |
| git_flow | 133.472 | 128.396 | -3.8% |
| http_git_method | 153.659 | 121.674 | -20.8% |
| tls_flow | 169.073 | 119.451 | -29.3% |
| ssh_flow | 115.966 | 76.182 | -34.3% |
| http_flow | 150.811 | 98.324 | -34.8% |
| partial_fin | 96.486 | 63.983 | -33.7% |
| dns_datagram | 46.306 | 32.163 | -30.5% |
| reordered_http | 170.504 | 112.158 | -34.2% |
| leading_duplicate | 166.457 | 125.760 | -24.4% |
| old_payload_after_fin | 168.502 | 163.305 | -3.1% |
| pre_origin_fin | 104.463 | 98.088 | -6.1% |
| control_rejection | 175.060 | 182.234 | +4.1% |
| leading_conflict | 159.911 | 176.700 | +10.5% |
| dtls_datagram | 36.133 | 40.145 | +11.1% |
| udp_unknown | 20.005 | 19.609 | -2.0% |
| udp_dns | 35.261 | 34.559 | -2.0% |
| udp_stun | 31.391 | 28.390 | -9.6% |
| udp_dhcp_4 | 33.825 | 35.514 | +5.0% |
| udp_coap | 31.829 | 36.339 | +14.2% |
| udp_syslog_5424 | 45.856 | 54.550 | +19.0% |
| udp_sip_2.0 | 86.448 | 102.277 | +18.3% |
| udp_snmp_2c | 51.380 | 40.952 | -20.3% |
| udp_tftp | 45.322 | 34.713 | -23.4% |
| ike_datagram | 57.867 | 62.349 | +7.7% |
| ike_marker | 64.192 | 50.555 | -21.2% |
| ike_coap_ambiguous | 48.712 | 40.007 | -17.9% |
| tls_rsa_ec_invalid | 78.213 | 72.974 | -6.7% |
| full_session | 241.068 | 256.425 | +6.4% |
| udp_flow_pair | 73.399 | 78.552 | +7.0% |
| http_flow_sig | n/a | 143.243 | new |
| tls_flow_sig | n/a | 213.627 | new |
| dns_datagram_sig | n/a | 50.870 | new |
| http_intranet_sig | n/a | 133.296 | new |
| unknown_sig_match | n/a | 95.091 | new |
| unknown_sig_miss | n/a | 79.811 | new |
| udp_beacon_sig | n/a | 35.321 | new |

An alternating A/B run of both trees (7 repeats of 500 flows, minimum taken,
constructor cost subtracted, three alternations) gives stable values that agree
within a few percent, which is the expected result because the unsuffixed paths
only gained a `contexts is None` test per header line:

| Case | v0.22 min us | v0.23 min us |
|---|---:|---:|
| http_flow | 103.3 | 103.1 |
| tls_flow | 124.4 | 125.2 |
| ssh_flow | 81.7 | 81.5 |
| dns_datagram | 36.0 | 39.1 |

## Cost of signatures (same tree, min of 7 x 400 flows, constructor subtracted)

Microseconds per flow/datagram through `CaptureMonitor.accept`, with context
retention off and no signatures versus the six-signature example set
(signatures-example.json), which has conditions for http, tls, ssh, dns,
unknown-tcp and unknown-udp:

| Case | retention off, no signatures | example signature set | delta |
|---|---:|---:|---:|
| http_flow | 112.2 | 115.5 | +3.3 |
| tls_flow | 133.9 | 151.7 | +17.8 |
| dns_datagram | 37.3 | 42.6 | +5.3 |
| http_intranet | 106.9 | 130.7 | +23.8 |
| unknown_match | 65.4 | 85.5 | +20.1 |
| unknown_miss_2100B | 65.3 | 84.4 | +19.1 |
| unknown_miss_60B_then_eof | 82.7 | 96.2 | +13.5 |
| udp_beacon | 17.9 | 34.2 | +16.3 |
| udp_unknown_30B | 17.2 | 20.6 | +3.4 |


Reading the deltas:

- HTTP without a match costs about 3 us: the parser keeps method, path, version,
  User-Agent and a bounded header block, then one anchored host pattern misses.
- TLS costs about 18 us: `ClientHelloInfo` materializes cipher/extension tuples
  and the context sets. This same structure feeds the v0.24 fingerprints.
- A matching HTTP signature (`http_intranet`) adds about 24 us: the match itself
  plus a custom-application verdict with signature metadata.
- Unknown TCP prefixes cost about 20 us whether the signature matches at the
  first update or the 2000-byte buffer fills (two regex prefilters per update).
- DNS over UDP costs about 5 us for the question-name context; an unknown
  30-byte datagram costs about 3 us for one anchored prefilter miss.

These are additional semantics, not parser slowdowns. Signature cost grows with
the number of signatures per family (one `bytes.find` per signature on a miss),
so keep sets specific. No production latency or accuracy claim is made.

## Verification

339 tests pass, 15 new in test_signatures.py: pattern safety (anchor length,
nested quantifiers, backreferences, lookaround, repeat counts, Latin-1),
document validation (contexts, operators, kinds, depth, counts, duplicates,
scope), retention off by default and bounded header block, HTTP/TLS/SSH/DNS/
SOCKS/unknown contexts, eager and EOF evaluation of unknown prefixes, hint
isolation, negate/or/absent semantics, bounded evaluation with 2000 signatures,
decrypted plaintext, verdict metadata and carriers, Analyzer/live/offline
integration without payload leakage. `tools/fuzz_fixtures.py` passes with
retention off; the nightly workflow runs it with 20,000 mutations per fixture.


## Erratum (recorded in v0.24)

The paired table above compared a byte-compiled development tree against a
fresh baseline checkout without `__pycache__`. CPython executes code compiled
from source at import time about 50% slower than code loaded from `.pyc` on
this interpreter, so the baseline column is pessimistic. See BENCHMARK-V024.md
for the corrected v0.21 -> v0.24 chain measured with `benchmark_ab.py`, which
byte-compiles both trees first.
