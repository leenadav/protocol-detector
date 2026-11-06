# v0.20 DTLS datagram CPU comparison

Python3.9.6 on this Mac, five shuffled paired subprocess rounds,1,000 samples
per case per round after warmup. Synthetic IPv4 packet decoding through capture
events; monitor construction, capture and output I/O excluded. Units:microseconds
per flow/datagram. This is local CPU cost, not end-to-end SWG latency.

| Case | v0.19 p50 | v0.20 p50 | Change |
|---|---:|---:|---:|
| tls_server12 | 37.208 | 37.459 | +0.7% |
| tls_server13 | 37.333 | 37.667 | +0.9% |
| tls_retry | 36.500 | 36.875 | +1.0% |
| dcerpc_flow | 29.958 | 30.041 | +0.3% |
| socks_flow | 31.916 | 31.750 | -0.5% |
| giop_flow | 30.167 | 30.042 | -0.4% |
| http_giop_method | 39.084 | 38.917 | -0.4% |
| git_flow | 39.708 | 40.792 | +2.7% |
| http_git_method | 42.541 | 43.167 | +1.5% |
| tls_flow | 47.791 | 47.875 | +0.2% |
| ssh_flow | 29.333 | 29.917 | +2.0% |
| http_flow | 38.750 | 39.041 | +0.8% |
| partial_fin | 29.667 | 29.958 | +1.0% |
| dns_datagram | 9.000 | 9.083 | +0.9% |
| reordered_http | 47.333 | 47.270 | -0.1% |
| leading_duplicate | 46.667 | 46.208 | -1.0% |
| old_payload_after_fin | 52.833 | 52.375 | -0.9% |
| pre_origin_fin | 29.750 | 28.750 | -3.4% |
| control_rejection | 54.458 | 53.833 | -1.1% |
| leading_conflict | 52.750 | 52.125 | -1.2% |
| dtls_datagram | 5.709 | 12.875 | +125.5% |
| udp_unknown | 5.709 | 5.709 | +0.0% |
| udp_dns | 8.750 | 8.709 | -0.5% |
| udp_stun | 6.917 | 7.000 | +1.2% |
| udp_dhcp_4 | 7.291 | 7.333 | +0.6% |
| udp_coap | 7.750 | 7.875 | +1.6% |
| udp_syslog_5424 | 11.833 | 11.958 | +1.1% |
| udp_sip_2.0 | 25.583 | 25.750 | +0.7% |
| udp_snmp_2c | 11.625 | 11.792 | +1.4% |
| udp_tftp | 8.958 | 9.167 | +2.3% |

DTLS changes from unknown to structural identification, so its +7.166us is new
validation work. Existing UDP p50 changes range -0.5%..+2.3%; unrelated TCP cases
range -3.4%..+2.7%. These small changes include host noise and do not establish a
zero-regression guarantee or production latency bound. Raw p95/p99, statuses,
source fingerprints and harness SHA256 are in benchmark-capture-v020.json.

294 tests pass, including every DTLS truncation/fragment split, nested lengths,
maximum record and byte budgets, extension count caps, asserted-only metadata,
2,500 mutations, prior UDP ambiguity and an opaque DHCP-cookie collision.
Python3.9 syntax, immutable39-family catalog and35 automatic families verified.

Canonical LibreSSL3.3.6 client: initial DTLS1.2 ClientHello and cookie retry against
a synthetic IPv4 loopback responder, using Python3.9.6 classifier. No completed
handshake or cryptographic/cookie authentication claim. See dtls-interop-v020.json.

Real synthetic loopback capture:186 packets,22 identifications,17 families,
zero reported kernel drops. Live output identifies DTLS as an encryption layer;
no application protocol is inferred. Source/script hashes recorded in reports.
