# v0.21 IKEv2 feature and TLS EC-context CPU comparison

Python3.9.6 on this Mac. Five shuffled paired subprocess rounds of1,000 samples
per case, after warmup. Synthetic IPv4 packet decoding through emitted capture
events; excludes monitor construction, capture and output I/O. Microseconds per
flow/datagram, not a production SWG latency measurement.

| Case | v0.20 p50 | v0.21 p50 | Change |
|---|---:|---:|---:|
| tls_server12 | 37.292 | 37.459 | +0.4% |
| tls_server13 | 37.375 | 37.750 | +1.0% |
| tls_retry | 36.375 | 36.458 | +0.2% |
| dcerpc_flow | 29.750 | 29.959 | +0.7% |
| socks_flow | 31.833 | 31.709 | -0.4% |
| giop_flow | 30.083 | 29.959 | -0.4% |
| http_giop_method | 38.916 | 38.250 | -1.7% |
| git_flow | 39.959 | 39.625 | -0.8% |
| http_git_method | 42.750 | 42.667 | -0.2% |
| tls_flow | 47.750 | 47.291 | -1.0% |
| ssh_flow | 28.958 | 28.958 | +0.0% |
| http_flow | 37.125 | 37.833 | +1.9% |
| partial_fin | 28.166 | 28.791 | +2.2% |
| dns_datagram | 9.000 | 9.125 | +1.4% |
| reordered_http | 46.208 | 47.042 | +1.8% |
| leading_duplicate | 45.917 | 45.917 | +0.0% |
| old_payload_after_fin | 51.500 | 51.959 | +0.9% |
| pre_origin_fin | 28.167 | 28.416 | +0.9% |
| control_rejection | 53.584 | 53.625 | +0.1% |
| leading_conflict | 52.125 | 51.916 | -0.4% |
| dtls_datagram | 12.833 | 12.792 | -0.3% |
| udp_unknown | 5.791 | 5.750 | -0.7% |
| udp_dns | 8.792 | 8.875 | +0.9% |
| udp_stun | 7.000 | 7.083 | +1.2% |
| udp_dhcp_4 | 7.333 | 7.375 | +0.6% |
| udp_coap | 7.834 | 7.916 | +1.0% |
| udp_syslog_5424 | 11.875 | 11.917 | +0.4% |
| udp_sip_2.0 | 25.792 | 25.708 | -0.3% |
| udp_snmp_2c | 11.709 | 11.750 | +0.4% |
| udp_tftp | 9.083 | 9.083 | +0.0% |
| ike_datagram | 5.834 | 14.917 | +155.7% |
| ike_marker | 6.000 | 15.042 | +150.7% |
| ike_coap_ambiguous | 7.750 | 14.917 | +92.5% |
| tls_rsa_ec_invalid | 37.125 | 32.041 | -13.7% |

New IKE requests change unknown to identified; dual CoAP/IKE changes identified
to unknown; TLS RSA+EC formats changes identified to malformed. These are different
work/semantics, not performance regressions on equivalent supported inputs.
Existing UDP cases change approximately -0.7%..+1.4%; existing TCP -1.7%..+2.2%.
Host noise is included; no zero-regression or production latency/accuracy claim.
Raw p95/p99, statuses and source/harness SHA256 are in benchmark-capture-v021.json.

309 tests: algorithm combinations, every truncation, bounded nested chains,
nonce/KE proposal consistency,3,000 mutations, real dual CoAP/IKE and DHCP/IKE
structures and the three-candidate ceiling. Aggregate IKE work counts payloads,
proposals and transforms and is capped at128; no algorithm Cartesian product,
cryptography, retained UDP input or registry scan.

Review4319051025 independently reproduced onv0.20: RSA-only cipher0x002f plus EC
point-format extension was identified. It now rejects across every TCP/TLS-record
split while all supported ECC suites remain valid. Current LibreSSL TLS1.2
MemoryBIO interoperability check passes (tls-interop-v021-libressl.json).

Independent tcpdump dissection agrees on SA transforms, MODP2048 KE, nonce and
native/non-ESP framing for both synthetic IKE fixtures (ike-decoder-v021.json).
This is decoder agreement, not a real IKE peer exchange or crypto validation.
Real synthetic IPv4 loopback capture:186 packets,24 identifications,18 families,
zero reported kernel drops (live-smoke-v021.json). No external/user traffic.
