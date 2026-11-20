# Chunk 04 (Tier 2): content-pack gate, merge readiness (451 lines)

**Diff:** `git diff e927d44 ddc557d -- tools/content_gate.py tools/merge_readiness.py`
**Commit:** 3e1f7f2.

**What changed, and why**
- **`content_gate.py` (283 lines, the ci `content-pack` job).** It is inert without the Go content pack (`PACK_FILES`, L40). When the pack is present it runs:
  - `make content` and `make content-pack`;
  - a check that `pack.json` equals the export, byte for byte;
  - `scan_pack` (L105–136): duplicate JSON keys (`strict_load`, L52–62), application and alias uniqueness, host entries and domains claimed once, and lookup tables equal to the entries (`host_catalog_problems`, L64–103);
  - `go test ./internal/content/...` for Python/Go parity.
- **`merge_readiness.py` (168 lines):** `git merge-tree --write-tree` trial merge (L59–73), with ref names validated (`REF`, L28; `resolve`, L50–57). It reports clean, or the full list of conflicting files. A conflict is a warning; only errors fail the job.

**Risks to check**
1. **`decide` (L145–157):** can a partial pack pass as "skip"? Expected: any one of the pack files present means the rest must be present too.
2. **Lookup-table comparison (L91–102):** does it really catch a domain mapped to two apps? JSON object keys can't repeat (`strict_load`), so a conflict shows up as a table/entries mismatch.
3. **Allowed failure codes:** `merge_readiness.git()` accepts only listed exit codes (L35–42). Does `merge-tree` exit 1 mean exactly "conflicts" (git ≥ 2.38)?
4. **Side effects:** can the trial merge modify refs, the index or the working tree? The self-test asserts it doesn't (L135–144).

**Already run (no need to redo)**
- **Self-tests:** content gate 16 identifier refusals; merge readiness clean and conflicting cases, refs untouched, 4 bad refs refused. Both pass on 3.13 and 3.9.
- **Content gate on go-migration `cb6707f`:** passes. Changing an earlier release's digest fails both `make content-pack` and the Go tests. Hosted on probe 3eb45f6 and 407bfcc (`content-pack` green).
- **Merge readiness:** reported 7 conflicting files on 2026-11-18 (push run 44380982843, dispatch 44555659227).

**Out of scope:** the engine's content model itself (`protocol_engine/content.py`, C11), which belongs to the engine lane's packet.
