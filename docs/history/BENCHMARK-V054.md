# Benchmark v0.54: LDAP StartTLS, IRC, TURN, DNS query types

Local CPU work, not production SWG latency. Baseline is the v0.53 tree
(c1276c9) in a worktree; `benchmark_ab.py --baseline` (3 alternations x 7
repeats, 400 flows). Host noise is about +-10%. Two hot paths changed: the
DNS validator adds one `dns_query_type` row per message (a dictionary lookup
and, for types 32/33, a 32-byte label check), and the STUN validator computes
the class, checks method/class consistency and tests TURN attribute tags in
the attribute loop. The HTTP/1 method table gained three tokens (a frozenset
membership test, unchanged cost). IRC and the LDAP extended operations are new
code on their own routes and messages.

| Flow | v0.53 (us) | v0.54 (us) | Note |
|---|---|---|---|
| http_flow | 166.1 | 168.4 | three more method tokens in the same frozenset: within noise |
| tls_flow | 181.6 | 167.6 | noise (no change on this path) |
| tls_server13 | 135.8 | 144.9 | noise (no change on this path) |
| ssh_flow | 127.3 | 122.7 | noise |
| dns_datagram | 53.2 | 54.7 | `dns_query_type` row: about +1.5 us, within noise |
| dtls_datagram | 48.2 | 54.1 | noise (no change on this path; the run-to-run spread on this flow is the widest) |
| udp_unknown | 22.9 | 23.9 | unchanged |
| quic_initial | 2787.7 | 2835.9 | noise (no change on this path) |

The STUN datagram is not part of the standard flow set; a separate
measurement of `DatagramInspector().inspect(...)` (best of five runs of 20000
iterations, constructor included) gives:

| Datagram | v0.53 (us) | v0.54 (us) | Note |
|---|---|---|---|
| STUN Binding request (no attributes) | 11.8 | 13.9 | class arithmetic, method/class consistency check and the DatagramMatch with two more evidence rows: about +2 us on a 12 us path |
| TURN Allocate request (REQUESTED-TRANSPORT) | rejected (unknown) | 15.2 | new: one attribute walked through the TURN size/value checks |

The STUN cost is a fixed per-message addition (two evidence rows and three
integer operations), not an amplification: every bound raises the same error
as before and the new checks only add `ParseError` cases.
