# Chunk 05 (Tier 2): long fuzzing, performance history (442 lines)

**Diff:** `git diff e927d44 ddc557d -- tools/go_fuzz_long.py tools/perf_history.py`
**Commits:** 3e1f7f2, 8c243ea (fuzzing); d7c482c, b57b819 (performance history).

**What changed, and why**
- **`go_fuzz_long.py` (166 lines, nightly `go-fuzz` job):**
  - It discovers every `func FuzzXxx(*testing.F)` (L39–51; vendor/ and testdata/ excluded) and splits the budget evenly, at least 60 s each (L53–57).
  - Every target runs even after one fails, and new failing inputs are copied out for upload (L65–101).
  - The dispatch budget is validated as a whole number from 1 to 100 (`parse_budget`, L141–145).
- **`perf_history.py` (276 lines, `perf-history.yml`):**
  - It extracts metrics from `perf_profile.py --json` (L61–78) and from Go `-benchmem` output (L80–93).
  - `judge` (L147–164) compares each metric with the median of up to 5 comparable earlier records: the same Python, and for timings the same CPU.
  - Thresholds (L46): bytes and counts fail above +10%; time warns above +30% and fails above +100%.
  - `--accept true` reports regressions without failing.

**Risks to check**
1. **Failure masking:** can a crash or timeout in one fuzz target hide another's failure, or pass the job? Each target's exit code is checked.
2. **Corpus snapshot (L60–63, L85–88):** does it copy only new failing inputs, never pre-existing corpus files?
3. **History input:** can a malformed or hostile history line crash `compare` or skew the baseline? `read_history` skips invalid lines; values come only from this workflow's own successful runs on the same branch.
4. **Zero baseline:** in `judge`, a zero baseline gives `inf`. Is a metric that rises from 0 handled sensibly?
5. **`--accept` validation (L264):** strictly `true` or `false`?

**Already run (no need to redo)**
- **Self-tests:** fuzzing (discovery, budget split and validation); performance history (12 verdict cases, compare and append). Both pass on 3.13 and 3.9.
- **Local long-fuzz run:** 9 targets passed; a deliberately failing target's crasher was captured.
- **Hosted fuzzing:** 44381003776 and 44381167748.
- **Performance history:** two local records compared cleanly. Hosted chain 44556584362 → 44558066232 → 44559135921 (baseline found: 20 ok, 2 improved), then main 44561555248.
- **CodeQL:** `py/uninitialized-local-variable` fixed in 8c243ea; `py/side-effect-in-assert` fixed in b57b819.

**Out of scope:** `tools/perf_profile.py` (the existing measurement, unchanged); Go fuzz targets themselves (engine lane).
