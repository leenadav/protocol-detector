# PRO-596: TLS flow benchmark rebaseline (classical and hybrid key exchange)

perf-history has been red on `main` since `593f6a4` (2026-11-24). The last green run was at `bdafcc9`. Measured
on this container (4 vCPU Xeon 2.30 GHz, go1.27.4, `-count 8`, benchstat). The raw tables are in this directory.

## Cause, by bisect

1. **PRO-260 (#105, `e0dce45`): the benchmark moved from cheap refusal to the real hybrid parse.** The single
   `tls` case built its flights with crypto/tls defaults, which negotiate X25519MLKEM768. Before #105 the engine
   refused that ServerHello early ("Server key share group outside supported profile"). After #105 it parses it
   fully. With the flights forced to X25519, `bdafcc9`, `e0dce45`, `593f6a4` and `main` all cost the same:
   89 allocs and 11.59 KiB per flow, with 97 allocs and 12.23 KiB bytewise. The hybrid parse after #105 costs
   90 allocs and 13.94 KiB, which is the classical full parse plus one allocation and the larger flights. The
   regression is the engine doing the work it was meant to do.
2. **PRO-394 (#123, `23bbc0c`): +3 allocs per flow for every TLS ClientHello.** This was a real regression,
   and this change fixes it. `parseHello` copied every ALPN offer into a fresh `[][]byte` (two copies and two
   slice growths for `h2,http/1.1`), even when no fingerprint was collected. JA4 reads only the first offer. Now
   the first offer is copied once, and only when the fingerprint is collected. JA4S reads the selected value in
   place, because it is used before `parseServerHello` returns. This was bisected over #107 (90), #121 (90),
   #123 (93), and #123 onwards stayed at 93.

## Before and after (this change versus main)

| benchmark | main B/op | after B/op | main allocs | after allocs |
|---|---|---|---|---|
| Flow/tls-classical | 11.81 Ki | 11.74 Ki | 92 | **89** |
| Flow/tls-hybrid | 14.17 Ki | 14.09 Ki | 93 | **90** |
| FlowBytewise/tls-classical | 12.43 Ki | 12.36 Ki | 100 | **97** |
| FlowBytewise/tls-hybrid | 22.89 Ki | 22.85 Ki | 114 | **111** |

Timings are noise on a shared host: Flow/tls-hybrid went from 14.3 to 12.3 µs, and the bytewise rows moved by
10 to 30 % in both directions between runs of unchanged code. Detection output is unchanged: the golden, parity
and fingerprint tests pass unmodified, apart from the JA4/JA4S test inputs taking the new byte-slice type.

## The proposed new baseline, and why

The benchmark now has two explicit cases. Their key exchange is pinned, so a library default can no longer
move it. `TestFlowAllocationBudget` fails if the hybrid flights stop carrying the ML-KEM shares.

- `tls-classical` (X25519): 89 allocs and 11.74 KiB. This equals the `bdafcc9` classical cost (89 allocs,
  11.59 KiB) within +1.3 % B/op (+150 B, under the 10 % threshold, not attributed further).
- `tls-hybrid` (X25519MLKEM768): 90 allocs and 14.09 KiB. Compared with classical, that is +1 allocation and
  +2.35 KiB. The extra bytes are the two flights' reassembly buffers: the ClientHello carries a 1,216-byte
  ML-KEM encapsulation key and the ServerHello a 1,120-byte share. Each hello is buffered once, because a hello
  may span Feeds and records. The key share itself is not copied: `parseServerHello` checks it in place (length,
  point format) and keeps only `selected_group` and `selected_key_exchange`.
- The old `go.BenchmarkFlow/tls.*` metrics end. The new `go.BenchmarkFlow/tls-classical.*` and `/tls-hybrid.*`
  metrics start without a baseline: perf-history records them and does not judge them on the first run, and the
  next runs judge them against these numbers. That is the rebaseline, made explicit here rather than through
  `accept_regression`.

## What is inherent, and the follow-up

- **Inherent in the whole-flight path (the path a proxy drives):** for each flight, one buffered copy of the
  hello, grown with the flow's memory credit. For hybrid this is about +2.3 KiB per flow and does not grow
  with anything else.
- **Bytewise hybrid (the adversarial shape):** 111 allocs versus 97 for classical. The +14 allocations come
  from the reassembly buffer growing step by step (`parsing.Credit.Append`: doubling under 256 bytes, then
  +25 %) up to the 1.7 KiB ClientHello and 1.2 KiB ServerHello. This scales with the logarithm of the hello
  size, not with any copy of the share. Removing it would mean reserving the whole hello as soon as its length
  is read. That changes when the memory credit is charged, so a flow under a tight `MaxRetained` or
  `MaxRetainedTotal` would be refused at a different byte. That is a budget-semantics decision, not a pure
  refactor, so it is left for a separate task.

## The two other numbers in the red runs

- **`memory.a +50.0% (1000 -> 1500)`** is not a measurement. It is the deliberate failing fixture inside
  `tools/perf_history.py --self-test`: the self-test calls `compare` on a synthetic record with `memory.a`
  1000 → 1500 to prove that a +50 % bytes change fails. `compare` prints its `::error::` annotation even inside
  the self-test, so the line appears in every run's annotations, green or red.
- **The one-off `unknown` ns/op +103 %** is timing noise. perf-history runs each Go benchmark once with
  `-benchtime 200x`, and an unknown flow costs about 1.3 to 2.9 µs, so the whole sample is about 0.3 to 0.6 ms
  on a shared runner. One scheduling hiccup doubles it and crosses the +100 % fail line for timings. No code
  path changed for unknown flows (11 allocs, unchanged).
