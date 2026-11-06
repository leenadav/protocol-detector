# v0.35 ClientHello hot path: CPU cost

Python 3.13 on Linux-6.18.44-fc-v139-x86_64 (shared cloud container).

## Isolated (same interpreter, minimum of 7 x 3000, constructor subtracted)

| Stream | v0.34 | v0.35 |
|---|---:|---:|
| TLS ClientHello inspection (SNI + ALPN, no fingerprints) | 73.7 | 54.5 |
| with `Config(fingerprints=True)` | about 172 | 159.6 |

## A/B harness, v0.34 (d517837) versus v0.35, 3 x 7 x 400 flows

| Case | v0.34 | v0.35 |
|---|---:|---:|
| http_flow | 159.3 | 158.7 |
| tls_flow | 187.8 | 181.1 |
| tls_server13 | 138.3 | 138.5 |
| ssh_flow | 122.1 | 116.7 |
| dns_datagram | 50.3 | 50.7 |
| dtls_datagram | 45.3 | 51.8 |
| udp_unknown | 23.4 | 22.6 |
| quic_initial | 2694.0 | 2616.8 |

The isolated measurement is the meaningful one: the end-to-end TLS flow
includes about 110 µs of packet decode, reassembly, event and verdict work
that did not change, and this host's run-to-run noise (DTLS +14% here with no
code change on its path, as in earlier records) is larger than the 19 µs saved.

## What changed and how it was checked

`parse_hello` reads the fixed ClientHello fields and walks the extension list
with explicit offsets; `Reader` remains for the SNI, ALPN and list
sub-structures and for the ServerHello. Every slice is preceded by the same
bound check the helper performed, with the same `ParseError` message, so the
set of accepted inputs and the error reported for each rejected input are
unchanged. `tools/compare_client_hello.py BASELINE_TREE` replays every
truncation and seeded mutations of three synthetic ClientHellos through both
implementations and compares results and exceptions: 12,640 cases against
the v0.28 tree and 3,640 against v0.34, zero differences. 424 tests pass
(the TLS, DTLS, QUIC, fingerprint, signature and shift suites exercise the
parser directly).
