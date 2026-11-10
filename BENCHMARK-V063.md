# Benchmark v0.63: Kerberos encryption types

Local CPU work, not production SWG latency. Baseline is v0.62 (fc115ca) in a
worktree. The A/B flows of `benchmark_ab.py` do not include Kerberos; the
changed paths are the KDC request and reply datagrams and the risk pass,
measured directly (fresh DatagramInspector, then `classify`; best of five runs
of 3000, two runs each):

| Message | v0.62 inspect (us) | v0.63 inspect (us) | v0.62 classify (us) | v0.63 classify (us) |
|---|---|---|---|---|
| AS-REQ (`KERBEROS`, 98 bytes) | 18.9, 18.3 | 27.4, 28.8 | 3.2, 3.1 | 3.6, 4.1 |
| AS-REP (`KERBEROS_AS_REP`, 179 bytes) | 25.3, 24.9 | 34.8, 35.2 | 3.2, 3.4 | 4.0, 4.1 |
| TGS-REP (`KERBEROS_TGS_REP`, 179 bytes) | 24.6, 24.9 | 35.1, 35.2 | 3.2, 3.3 | 4.0, 4.2 |

This is a real cost, not noise: about 9-10 us per message. Reading the etypes
means walking the KDC-REQ-BODY (up to 12 fields and 32 etypes), or the Ticket
(4 fields) and two EncryptedData structures (3 fields each); the request walk
alone measures about 5.5 us, and each message gains two evidence rows (about
0.5 us each to build). A first draft walked with the generator used for the
outer message and measured 29-30 us (request) and 37-40 us (replies); a
list-returning field walk with the same rules saved about 2 us. The work per
message is bounded by those field and etype limits, so it cannot be amplified
by a crafted message. Kerberos is low-rate traffic (port 88), so this was
accepted rather than trading away the clean-walk rule that keeps labels
structural.
