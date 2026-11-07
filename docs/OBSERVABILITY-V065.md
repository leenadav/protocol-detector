# Observability model (stage 7, A15)

One registry per capture path (`protocol_adapters/observability.py`, dependency-free): integer counters and
fixed-bucket histograms, rendered into the live `summary`/`progress` event (`telemetry`, schema
`$defs/telemetry`) and readable in tests. No payload, name or key is ever recorded: values are counts,
byte totals and durations.

| series | kind | written by | meaning |
|---|---|---|---|
| `bytes.new` | counter | Analyzer (per session record) | unique payload bytes reassembled |
| `bytes.replayed` | counter | Analyzer | retransmitted bytes seen again (fed once, never twice) |
| `bytes.decrypted` | counter | Decryptor | authenticated plaintext released |
| `bytes.retained` | gauge | coordinator (per tick) | bytes currently held by the retained reassembly tier |
| `keys.pending` | gauge | Decryptor | connections waiting for secrets |
| `signatures.candidates` | counter | Analyzer (from Inspector metrics) | custom signatures evaluated |
| `decryption.auth_failures` | counter | Decryptor | AEAD rejections |
| `capture.gaps` | counter | coordinator | capture loss/truncation events |
| `events.dropped` | counter | coordinator | consumer-queue overflows (bounded queue) |
| `queue.depth` | gauge | coordinator (per tick) | consumer events waiting to be drained |
| `sessions.<status>` | counter | Analyzer | session records by verdict status |
| `session_lifetime_seconds` | histogram | Analyzer | capture time from the first packet to the session record (retirement); this is lifetime, not decision latency |
| `time_to_first_decision_seconds` | histogram | Analyzer | capture time from the first packet to the first identification (TCP: first identified event; UDP: first identified datagram); session records carry `decision.first_seconds` |
| `time_to_stable_verdict_seconds` | histogram | Analyzer | capture time from the first packet to the last change of the identified label (`decision.stable_seconds`) |
| `stage_seconds.packet` | histogram | CaptureMonitor | one packet through the coordinator |
| `stage_seconds.tick` | histogram | coordinator | one idle-expiry pass |
| `stage_seconds.decrypt` | histogram | Decryptor | one bounded decryption slice |
| `stage_seconds.report` | histogram | Decryptor | one status report assembly |

Histograms keep counts per bucket, sum, min and max only; p50/p95/p99 are bucket upper bounds. Series are
capped at 64 per registry. Baselines before the refactor are in docs/STAGE0-BASELINE-V065.md; the labelled
corpus report (`tools/corpus_report.py`, docs/CORPUS-REPORT-V065.md) gives true/false outcomes by family and
input class over the synthetic fixture corpus, which is not a real-world accuracy figure. Overload, late keys,
disconnect, slow consumer and worker-crash behaviour are exercised by the stage-4 and stage-6 test suites and
the stage-8 soak run.
