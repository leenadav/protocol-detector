# Benchmark v0.64: weak cipher suites in TLS ClientHello offers

Local CPU work, not production SWG latency. Baseline is the v0.63 tip with the
v0.61 self-review repair (77a6689) in a worktree. The ClientHello is the hottest
path in the engine, so it was measured three ways.

`benchmark_ab.py --baseline` (three runs): `tls_flow` moved by +9.1, -6.5 and
+14.9 us, and `quic_initial` by +131, +264 and +229 us, while `http_flow`,
`tls_server13`, `ssh_flow` and the datagram cases stayed within a few us. The
QUIC path only gained one list slot and one reference assignment (no
classification), so that harness was checked directly.

Direct, interleaved (fresh Inspector, best of seven runs, three pairs):

| Case | v0.63 (us) | v0.64 (us) |
|---|---|---|
| QUIC Initial datagram (`QUIC_INITIAL`) | 2122.8, 2283.4, 2167.7 | 2108.1, 2018.7, 2155.3 |
| Modern ClientHello, 16 suites, none weak | 45.6, 46.1, 46.0 | 48.4, 48.4, 48.0 |
| Legacy ClientHello offering 3DES and RC4 | 37.6, 40.2, 38.2 | 43.3, 46.3, 44.5 |

QUIC is unchanged. A modern offer costs about 1-3 us more, within this host's
run-to-run noise (swapping the classifier for a no-op moved the same case by
-0.9 and +4.4 us); in isolation the classifier measures about 0.8 us for 16
suites (a native-order memoryview with one C-level `isdisjoint` pass; the first
draft's `struct.unpack` plus intersection measured 0.95 us). An offer with weak
suites costs about 6-8 us more, almost all of it the extra evidence rows, which
are bounded at six (one per class).
