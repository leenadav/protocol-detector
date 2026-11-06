# Benchmark v0.60: RDP security posture

Local CPU work, not production SWG latency. Baseline is v0.59 (b5dae20) in a
worktree. The A/B flows of `benchmark_ab.py` do not include RDP; the changed
path is the X.224 Connection Request and Confirm, measured directly (fresh
Inspector, best of five runs of 3000, two runs each):

| Message | v0.59 (us) | v0.60 (us) |
|---|---|---|
| RDP Connection Request offering TLS and CredSSP (`RDP`, 19 bytes) | 38.3, 37.7 | 39.3, 40.5 |
| RDP Connection Confirm selecting TLS (`RDP_CONFIRM`, 19 bytes) | 41.2, 37.7 | 39.8, 37.0 |

The label rows depend only on validated small integers (32 offer sets x 4
credential-mode flag pairs; 6 selections x 32 response flag sets), so they are
built once per distinct input and cached; the first draft built them per
message and measured 41-42 us for the request. The remaining difference is the
two or three extra evidence rows per message.
