# Benchmark v0.65: built-in server-name application catalog

Local CPU work, not production SWG latency. Baseline is v0.64 (fe5a293) in a
worktree. Observations and parsers are unchanged; the cost is in `classify`
for a TLS ClientHello observation (best of seven runs of 20000, three runs):

| Server name | v0.64 (us) | v0.65 (us) |
|---|---|---|
| `rr3---sn-abc.googlevideo.com` (maps to youtube) | 3.67, 3.77, 3.84 | 4.42, 4.39, 4.47 |
| `a.b.c.d.example.org` (no mapping, five labels) | 3.56, 3.63, 3.53 | 4.78, 4.74, 4.87 |

One dictionary probe per label, plus a cached carrier-specific application
(`lru_cache`, at most one entry per catalog application and carrier). The first
draft built the application on every call and scanned the evidence for ECH
before the lookup: 6.2-6.4 us (mapped) and 4.9-5.6 us (unmapped).
