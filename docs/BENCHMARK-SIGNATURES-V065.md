# Signature evaluation benchmark (stage 7, A11)

`python3 -B benchmark_signatures.py --lookups 1000` on the cloud container used for the v0.65 plan
(Python 3.13.16, x86_64, no other load). Local CPU work including Python call overhead; not a production
latency or throughput figure. Compilation and runtime are reported separately; memory is the tracemalloc
peak during compilation of the set.

Workloads: `spread` (three families; 60 % exact-host signatures, the rest patterns, OR roots and negations),
`one-family` (every signature in `http`, half exact and half pattern: the worst case for a per-family scan),
`prefilter` (pattern signatures whose literal anchor is present in the input but whose regex does not match:
the prefilter passes and the regex runs), `nonmatch` (exact signatures, input that matches none).
`indexed` is `SignatureSet.match_counted` (stage 7); `linear` is the reference scan of the whole family
(`match_linear`, equivalent by `test_signature_index.py`). Candidates = signatures whose conditions were
evaluated per lookup.

| workload | signatures | compile ms | peak KiB | indexed/scanned | indexed p50/p99 µs | candidates | linear p50/p99 µs | candidates |
|---|---|---|---|---|---|---|---|---|
| spread | 100 | 10.7 | 100 | 68/32 | 3.5 / 8.4 | 3.0 | 2.2 / 15.4 | 35.3 |
| spread | 1000 | 119.2 | 1037 | 598/402 | 15.5 / 59.9 | 32.1 | 3.4 / 140.4 | 363.4 |
| spread | 4096 | 452.7 | 4018 | 2460/1636 | 54.6 / 226.7 | 144.3 | 4.1 / 533.9 | 1491.4 |
| one-family | 100 | 14.8 | 106 | 50/50 | 8.0 / 46.5 | 20.2 | 5.0 / 62.7 | 52.1 |
| one-family | 1000 | 139.9 | 1029 | 500/500 | 43.0 / 303.1 | 192.5 | 20.0 / 483.4 | 509.0 |
| one-family | 4096 | 566.3 | 4265 | 2048/2048 | 246.5 / 1373.4 | 793.5 | 198.9 / 2022.6 | 2129.9 |
| prefilter | 100 | 23.5 | 121 | 0/100 | 53.0 / 77.2 | 100.0 | 50.9 / 74.5 | 100.0 |
| prefilter | 1000 | 217.6 | 1137 | 0/1000 | 549.3 / 821.4 | 1000.0 | 509.3 / 635.3 | 1000.0 |
| prefilter | 4096 | 954.1 | 4969 | 0/4096 | 2213.5 / 2411.3 | 4096.0 | 2057.5 / 3106.4 | 4096.0 |
| nonmatch | 100 | 5.0 | 90 | 100/0 | 0.5 / 0.8 | 0.0 | 30.1 / 50.6 | 100.0 |
| nonmatch | 1000 | 48.8 | 868 | 1000/0 | 0.5 / 0.9 | 0.0 | 315.6 / 362.4 | 1000.0 |
| nonmatch | 4096 | 212.4 | 3993 | 4096/0 | 0.5 / 0.8 | 0.0 | 1333.6 / 1501.0 | 4096.0 |

## Reading the numbers

- **Exact-value signatures are now O(1) per lookup.** With 4,096 exact-host signatures a non-matching
  lookup evaluates no candidate and costs 0.5 µs (linear: 1.3 ms, 4,096 candidates). This is the common
  production case (most sessions match no custom signature).
- **Mixed sets scale with their scan list, not with their size.** `spread` at 4,096 evaluates 144
  candidates instead of 1,491; the remaining cost is the pattern/OR/negation signatures that cannot be
  keyed, which are exactly the ones a per-family scan must still evaluate. Priority and first-match are
  preserved (equivalence test over seeded sets, every lookup compared with the linear reference).
- **Pattern-heavy sets are bounded by the regex engine, not by selection.** In `prefilter` the literal
  anchor passes for every signature by construction, so all 4,096 regexes run (2.2 ms per lookup); the
  index cannot help there. A multi-pattern (Aho-Corasick style) anchor matcher would reduce this only for
  sets where many anchors are absent; in `nonmatch`-like inputs the anchor prefilter already rejects in
  Python string time. The measurement does not justify a regex-engine change now: the 4,096 cap, the
  per-pattern literal-run requirement and the repeat restrictions keep the worst case at milliseconds,
  and every regex-engine change would need the equivalence and adversarial suite rerun.
- **Compilation is linear and separate**: about 0.1 ms and 1 KiB per signature. A rule set is compiled once
  per process, is immutable, and carries a `digest`; session records pin it (`signature_set`), so a verdict
  can always be tied to the rule-set version that produced it.

Regenerate with the command above; `--json` prints the raw rows.
