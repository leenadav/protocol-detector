# Benchmark v0.58: SSH algorithm posture

Local CPU work, not production SWG latency. Baseline is the v0.57 tree
(71103d8) in a worktree; `benchmark_ab.py --baseline` (3 alternations x 7
repeats, 400 flows). Host noise was high again (the unchanged `dns_datagram`
moved by about 19%).

| Flow | v0.57 (us) | v0.58 (us) | Note |
|---|---|---|---|
| http_flow | 167.5 | 174.9 | no change on this path: noise |
| tls_flow | 181.2 | 185.6 | no change on this path: noise |
| tls_server13 | 151.1 | 157.9 | no change on this path: noise |
| ssh_flow | 130.8 | 133.1 | banner only: the parser now stays attached waiting for a KEXINIT that never comes |
| dns_datagram | 51.5 | 61.4 | no change on this path: noise |
| dtls_datagram | 55.4 | 56.1 | unchanged |
| udp_unknown | 22.6 | 21.6 | unchanged |
| quic_initial | 2573.5 | 2689.3 | no change on this path: noise |

The changed path, a banner plus one 298-byte KEXINIT (319 bytes, fresh
Inspector, best of five runs of 3000):

| Configuration | v0.57 (us) | v0.58 (us) |
|---|---|---|
| fingerprints off | 25.9 (banner only; KEXINIT not read) | 78.9 (KEXINIT read, posture classes, `refined` event) |
| fingerprints on | 70.6 | 81.7 |

The posture classification itself costs about 11 us (set lookups over the
split name-lists). The KEXINIT name-list check, which already ran for HASSH,
moved from a per-byte Python loop to `bytes.translate` with the same accepted
set and error; without it the default path measured about 97 us. Work stays
bounded by the existing KEXINIT budgets: one packet of at most 35000 bytes and
`max_bytes`, ten name-lists of at most 4096 bytes each.

Review round 1 repair (Terrapin pairs cipher and MAC within one direction;
RFC 4251 name-list grammar: non-empty names of at most 64 characters). The
grammar check splits each non-empty list once per KEXINIT, inside the same
4096-byte list budget. Banner plus modern KEXINIT (517 bytes), best of 5 x
3000, before then after, three runs: 78.9/86.0, 71.5/75.6, 75.2/72.5 us with
fingerprints off; 92.9/86.8, 81.2/82.8, 77.8/79.9 us with fingerprints on.
The difference is within run-to-run noise.
