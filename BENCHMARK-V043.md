# v0.40-v0.43 additions: CPU cost check against v0.39

Python 3.13 on Linux-6.18.44-fc-v139-x86_64 (shared cloud container).
`benchmark_ab.py --baseline <v0.39 tree> --alternations 3 --repeat 5 --flows 300`,
microseconds per flow (constructor subtracted), minimum of alternated runs.

| Case | v0.39 (2d73b36) | v0.43 | Delta |
|---|---:|---:|---:|
| http_flow | 164.8 | 158.5 | -3.8% |
| tls_flow | 204.1 | 182.8 | -10.4% |
| tls_server13 | 147.1 | 148.4 | +0.9% |
| ssh_flow | 120.9 | 126.1 | +4.3% |
| dns_datagram | 51.4 | 53.7 | +4.5% |
| dtls_datagram | 53.8 | 54.4 | +1.1% |
| udp_unknown | 22.7 | 23.4 | +3.1% |
| quic_initial | 2608.6 | 2723.1 | +4.4% |

The deltas are inside this host's run-to-run noise (earlier records show
+/-10% on unchanged paths); none of the four releases touched the HTTP, TLS,
SSH, DTLS or QUIC hot paths. The DNS datagram is the one path whose work grew:
every DNS result now carries `dns_message` (and `dns_rcode`) evidence and the
analyzer keeps one observation per UDP direction.

A first version of that change built the evidence rows and imported their
classes inside `dns()` on every call and measured +27% on `dns_datagram`
(46.2 to 58.7 µs). The committed version hoists the imports to module level and
precomputes the sixteen possible header outcomes as immutable tuples; in
isolation `DatagramInspector().inspect(DNS)` is 13.5 µs against 17.3 µs for the
first version (SNMP Get 18.7 µs, DNS response 17.5 µs). Dispatch changes for
the new families cost nothing measurable on the existing prefixes: `select()`
on a GET prefix 0.35 µs, an HTTP response prefix 0.42 µs, a TLS record 0.23 µs;
the leading-0x00 block (TNS test added) 2.2 µs, unchanged within noise.
