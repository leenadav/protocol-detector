# v0.19 TLS server profile CPU comparison

Python3.9.6 on this Mac; five shuffled paired subprocess rounds with1,000 samples per case per round after warmup. Synthetic IPv4 packets to capture events; monitor construction, capture and output I/O excluded. Per-flow microseconds, not production latency.

| Case | v0.18 p50 | v0.19 p50 | Change |
|---|---:|---:|---:|
| tls_server12 | 25.417 | 36.958 | +45.4% |
| tls_server13 | 24.916 | 37.083 | +48.8% |
| tls_retry | 24.750 | 36.208 | +46.3% |
| dcerpc_flow | 29.792 | 29.834 | +0.1% |
| socks_flow | 31.084 | 31.834 | +2.4% |
| giop_flow | 29.625 | 29.916 | +1.0% |
| http_giop_method | 38.083 | 38.750 | +1.8% |
| git_flow | 40.000 | 39.792 | -0.5% |
| http_git_method | 42.750 | 42.708 | -0.1% |
| tls_flow | 47.333 | 47.458 | +0.3% |
| ssh_flow | 29.625 | 28.917 | -2.4% |
| http_flow | 37.709 | 37.750 | +0.1% |
| partial_fin | 29.416 | 28.625 | -2.7% |
| dns_datagram | 8.917 | 8.875 | -0.5% |
| reordered_http | 46.917 | 47.250 | +0.7% |
| leading_duplicate | 46.000 | 46.125 | +0.3% |
| old_payload_after_fin | 51.875 | 52.583 | +1.4% |
| pre_origin_fin | 29.375 | 29.625 | +0.9% |
| control_rejection | 53.708 | 54.541 | +1.6% |
| leading_conflict | 52.041 | 52.834 | +1.5% |

New TLS server/retry cases perform validation where the baseline rejected. Existing-case p50 changes range -2.7% to +2.4%; ClientHello +0.3%. An earlier run showed +2.4% for ClientHello and up to +4.8% on unchanged SSH; a repeated measurement and final-source run illustrate host noise. This is not proof of zero regression or a statistical latency bound. Raw final p95/p99, statuses and source/harness hashes are in benchmark-capture-v019.json.

283 tests pass: all TCP splits and TLS-record splits, bytewise input, 2,000 mutated inputs, extension dependencies/contexts, strict cipher/group profiles, budgets, retry semantics and metadata boundaries. Python3.9 AST compatibility and38/34 coverage inventory checked.

Canonical MemoryBIO interoperability (no sockets): Python3.9 engine validates LibreSSL2.8.3 TLS1.2 and OpenSSL3.5.8 TLS1.2/1.3 ServerHello plus TLS1.3 retry. Server group secp256r1 explicitly configured; OpenSSL default hybrid groups remain unsupported. TLS1.2 ALPN appears only as selected_alpn assertion; TLS1.3 ALPN remains encrypted. Temporary generated certificate/private key and wire bytes are not published.

Final-source synthetic live IPv4 capture: 185 packets,21 identifications,16 families,0 reported kernel drops. Exactly two server_hello and one hello_retry_request observations verified, plus the existing ClientHello. Reports include matching source/script fingerprints.
