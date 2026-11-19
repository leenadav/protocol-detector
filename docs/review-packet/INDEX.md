# CI/CD lane: Codex review packet

This packet covers everything the CI/CD lane merged since the last `CODEX_REVIEW_RESULT` for this lane (item 25
round 3 at `926789c`, and Part A at `eaa8a99`, both on issue #7): PRs #28, #30 and #31. Nothing below has had a
Codex review.

- **Range:** `e927d44..ddc557d`. `e927d44` is the base of PR #28; `ddc557d` is `main` after PR #31's merge.
- **Lane commits in the range:** `c58fe65`, `3e1f7f2`, `8c243ea`, `eb18353`, `91113bc`, `5442d05`, `d7c482c`,
  `b57b819`, `8a129c7`. The only other commit in the range that touches these paths is Dependabot's `2e11de0`
  (see EXCLUDE.md).
- **Per chunk:** read the cumulative diff of its listed files, `git diff e927d44 ddc557d -- <files>`. Every file
  listed was changed only by the lane commits above, so this is exactly the lane's change.
- **Fix rounds:** reviewed as the fix diff only (`git diff <reviewed-head> <fix-head> -- <files>`), never the
  whole range again.

## Chunks, in suggested order

| # | Tier | Subject | Files | Changed lines | Est. reading |
|---|---|---|---|---|---|
| [01](chunk-01.md) | 1 | Workflow triggers, permissions, tokens, pins, new jobs | 6 workflows | 438 | 25 min |
| [02](chunk-02.md) | 1 | Release supply chain: reproducible Go binaries, SBOM, dry-run provenance and signing | 3 tools | 387 | 20 min |
| [03](chunk-03.md) | 1 | Go toolchain, minimum, vendoring and network (`GOPROXY`) decisions | `go_ci.py`, `check_go_drift.py`, Makefile | 451 | 25 min |
| [04](chunk-04.md) | 2 | Content-pack gate and merge-readiness report logic | 2 tools | 451 | 15 min |
| [05](chunk-05.md) | 2 | Long fuzzing and performance-history logic | 2 tools | 442 | 15 min |
| [06](chunk-06.md) | 1 | Dependabot action pin bumps `b97adc8` (PR #26), never reviewed | 6 workflows | 56 | 5 min |

- **Tier 1** (1,332 lines): Codex must review these chunks. They cover workflow permissions, tokens and secrets
  handling, privilege-sensitive triggers, action pinning, supply-chain steps (vendoring, SBOM, signing,
  provenance), and anything that can push or publish.
- **Tier 2** (893 lines): a lighter review of CI helper logic. These scripts run with a read-only token and
  write only to job summaries and artifacts.
- **If budget allows only part:** review 01 → 02 → 03 → 06 (Tier 1). Then 04 and 05 can each stand alone.

## Tier 3: no Codex review needed (gate that covers each)

| Path | Lines | What it is | Covered by |
|---|---|---|---|
| `tools/workflows.lock.json` | 444 | Generated (`check_workflow_policy.py --write-workflow-lock`) | Rule 14 in `make workflow-policy` and the `workflow-lint` ci job: every workflow line must equal the lock |
| `SSDLC.md` (items 28–34, job table) | 135 | Rationale and sources | `tools/check_docs_counts.py` (docs numbers); the content mirrors chunks 01–05 |
| `docs/RELEASING.md` | 107 | Release procedure | Describes chunk 02, nothing executes from it |
| `Makefile` self-test lines (`workflow-policy` target) | ~10 | Adds `--self-test` calls | `make workflow-policy` and the ci `workflow-lint` job run them |
| `7e7835c` (`SSDLC.md`, `tools/go_ci.py` docstring) | 5 | Wording fix Codex requested (result 6882602432) | Prose only; `go_ci --self-test` in `workflow-lint` |

## Coverage of earlier history

The engine lane asked whether the CI/CD history that `claude/go-migration` merges in was already reviewed.

**How it was checked:** every commit before `e927d44` that touches `.github/`, this lane's CI tools, the locks,
`tools/scanners` or `requirements-dev.txt` (92 commits) was tested against the 73 commits named in the 57
`CODEX_REVIEW_RESULT` comments on issue #7, using `git merge-base --is-ancestor`.

**Result:** every one is an ancestor of a reviewed head, except two:
- `b97adc8`, Dependabot action pin bumps (PR #26): now chunk 06.
- `7e7835c`, a 5-line wording fix in `SSDLC.md` and the `go_ci.py` docstring, made at Codex's own request in
  result 6882602432: Tier 3.

**Limit of this check:** being an ancestor of a reviewed head shows the commit was in the reviewed snapshot,
not that every line of it was read. The task scope of each round is in its result comment.

## Gates already run on `ddc557d` (all succeeded)

`ci` 44561555271, `codeql` 44561555222, `supply-chain-drift` 44561555182, `perf-history` 44561555248,
`publish-release` (dry run) 44561555092. Locally, all passed: `make check`, CPython 3.9, workflow policy,
actionlint, zizmor pedantic (no findings), the PyYAML cross-check and ruff. Each chunk lists its own extra runs.
