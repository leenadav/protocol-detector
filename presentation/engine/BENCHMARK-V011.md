# v0.11 reassembly measurements

Python 3.9, local synthetic CPU microbenchmarks; not SWG latency. Stream.feed uses a counter inspector; preparation, construction and copying are excluded. 200 samples x 5 rounds, GC enabled. Real capture adapter comparison: 100 samples x 3 rounds in benchmark-capture-v011.json.

| Case | v0.10 p50 us | v0.11 p50 us |
|---|---:|---:|
| in_order_1400 | 1.833 | 1.833 |
| duplicate_1400 | 202.708 | 1.833 |
| duplicate_64k | 9357.188 | 35.0 |
| pending_duplicate_1400 | 197.688 | 1.833 |
| two_reverse_segments_1400 | 533.188 | 5.625 |
| fill_one_byte_gap_64k | 9758.021 | 9.584 |
| partial_overlap_1400 | 359.938 | 101.021 |
| alternating_holes_64k | 21249.125 | 4567.792 |
| duplicate_conflict_first_64k | 1.25 | 32.708 |
| duplicate_conflict_last_64k | 6009.188 | 35.208 |
| mixed_conflict_last_64k | 3240.959 | 3275.291 |

Tradeoff: a conflicting first byte in a fully present 64KiB range now pays for the bounded bitmap count before comparison (~33us versus ~1us). Mixed late conflicts remain approximately unchanged. Alternating holes retain a bounded Python validation loop. No claim of uniform speedup. Memory stays bounded by the initial window; duplicates do not accumulate history.

218 tests passed in staging, including exhaustive small-window presence arrangements, seeded overlap/wrap cases, atomic conflicts, clipping and temporary-memory checks. Protocol coverage is unchanged: 35 families, 31 automatic.

Sequence-number background: [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html). Conflicting overlap invalidation is our conservative observation policy, not endpoint TCP emulation.
