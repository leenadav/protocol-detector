# Synthetic soak (stage 8)

`tools/soak.py` (the numbers are from `--connections 200 --gap-flows 1000` on the cloud container; the JSON
of the latest run is docs/SOAK-V065.json). Synthetic traffic in memory only.

**Overload.** 5,000 SYN-only handshakes: the retained tier keeps its configured 256 connections, rejects
4,744 beyond the limit with a counter (nothing allocated per direction, 2.6 MiB peak for the whole flood),
and releases all of them at the idle tick. Then 200 real TLS 1.3 exchanges (OpenSSL fixture replayed on
distinct ports) with the key log arriving only after all packets, and a consumer that drains every 25
connections: all 200 decrypt once the keys arrive (`bytes.decrypted` 25,800, `keys.pending` 0 at the end),
retained bytes stay far under the 8 MiB aggregate budget, the consumer queue never overflows, peak 6.1 MiB,
1.6 s.

**Sparse gaps.** 1,000 flows each with a 29 KB hole before 1,400 bytes of data: the retained tier fills to
2,071,640 of its 2,097,152-byte aggregate budget, then rejects 310,800 further bytes with a counted reason
instead of growing; the affected connections report `unavailable` and the others are untouched.

**Worker crashes.** Crashing, hanging and healthy workers submitted together through the JobRunner (2
running, 6 queued, 1 s lifetime): outcomes are `done` for the healthy ones, `failed` for the crashes and
`expired` for the hangs, nine further submissions are rejected at admission, and no outcome is affected by
another job.

These are local, bounded-run measurements that show the budgets hold; they are not capacity or latency
figures for any production host.
