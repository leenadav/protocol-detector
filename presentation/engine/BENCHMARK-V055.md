# Benchmark v0.55: name services on the DNS layout

Local CPU work, not production SWG latency. Baseline is the v0.54 final tree
(492b9e8) in a worktree; `benchmark_ab.py --baseline` (3 alternations x 7
repeats, 400 flows). Host noise on this container is wide (about +-15%, and
the small udp paths swing more between runs). The DNS validator is the only
hot path that changed: the probe gained the plausibility rule for the rarer
layouts (one length check, one byte range, one four-short sum, evaluated only
when the question count is not exactly one), and the validator now expands
every question name, reads the QU and cache-flush bits during the walk and
decides the family afterwards.

| Flow | v0.54 (us) | v0.55 (us) | Note |
|---|---|---|---|
| http_flow | 167.1 | 165.1 | noise (no change on this path) |
| tls_flow | 172.2 | 178.7 | noise |
| tls_server13 | 148.0 | 143.3 | noise |
| ssh_flow | 127.1 | 126.2 | noise |
| dns_datagram | 52.7 | 58.0 | about +5 us: name expansion per question, marker bits, family decision |
| dtls_datagram | 54.1 | 40.9 | noise (the DTLS path did not change; the swing shows the host band) |
| udp_unknown | 14.0 | 18.3 | the 32 bytes of 0xff fail the probe at its first byte test as before; the swing is host noise (a direct 20000-iteration loop measures 9.6 vs 10.8 us) |
| quic_initial | 2654.1 | 2871.0 | noise (no change on this path) |

A direct loop of `DatagramInspector().inspect(...)` (best of seven runs of
20000 iterations, constructor included) gives DNS query 22.3 us (v0.54) vs
24.9 us (v0.55) and the unknown datagram 9.6 vs 10.8 us. The new families are
new work on their own messages: mDNS announcement about 27 us, NetBIOS
registration about 31 us, hinted LLMNR query about 18 us on this host. Every
bound raises the same error as before; the probe only adds exclusions and the
validator only adds `ParseError`/`UnsupportedPrefix` outcomes.
