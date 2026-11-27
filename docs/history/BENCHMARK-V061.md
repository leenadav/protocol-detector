# Benchmark v0.61: database transport protection

Local CPU work, not production SWG latency. Baseline is v0.60 (0336be0) in a
worktree. The A/B flows of `benchmark_ab.py` do not include these databases;
the changed paths are the TDS PRELOGIN response, the PostgreSQL StartupMessage
and the risk pass, measured directly (fresh Inspector, then `classify` on the
resulting observation; best of five runs of 3000, two runs each):

| Message | v0.60 inspect (us) | v0.61 inspect (us) | v0.60 classify (us) | v0.61 classify (us) |
|---|---|---|---|---|
| TDS PRELOGIN response (`TDS_PRELOGIN_RESPONSE`, 49 bytes) | 38.1, 33.1 | 33.4, 33.9 | 4.3, 4.1 | 4.4, 4.5 |
| PostgreSQL StartupMessage (`POSTGRESQL`, 36 bytes) | 25.1, 24.6 | 24.9, 25.2 | 6.2, 7.6 | 6.8, 6.7 |

Each change is one dictionary lookup or one constant tuple per message and one
more `elif` arm per evidence row in the risk pass; differences are within
run-to-run noise.
