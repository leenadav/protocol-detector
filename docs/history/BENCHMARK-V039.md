# v0.39 TLS 1.2 certificate watch: CPU cost

Python 3.13 on Linux-6.18.44-fc-v139-x86_64 (shared cloud container).
Isolated in-process measurement: minimum of 7 x 3000 `Inspector(config).feed(data)`,
constructor (2.7 µs) subtracted. Microseconds per direction.

| Input | `Config()` | `Config(certificates=True)` |
|---|---:|---:|
| ServerHello only (58 bytes) | 28.7 | 33.2 |
| ServerHello + Certificate record, RSA-2048 leaf and RSA-4096 CA (1357 bytes) | 31.6 | 111.8 |
| ServerHello + Certificate record, single P-256 leaf (377 bytes) | about 31 | 108.9 |
| `x509.leaf_profile` alone, 510-byte RSA-2048 leaf | | 27.4 |
| `x509.leaf_profile` alone, 771-byte RSA-4096 certificate | | 27.1 |

With the option off the flight costs the same as the ServerHello alone: the
parser is released at identification and later bytes are not inspected. With
it on, about 80 µs are added per TLS 1.2 server direction: the DER walk itself
is 27 µs and is independent of key size (key bytes are measured, not read);
the rest is the second `_identified()` build, the `refined` event and the
record/handshake framing loop. The watch stops at the end of the leaf, so an
intermediate chain of any length adds nothing. A TLS 1.3 server flight is
unaffected (no watch is started). Default configurations are unchanged;
`tools/compare_engine.py` against the parent commit reports no behaviour
differences.
