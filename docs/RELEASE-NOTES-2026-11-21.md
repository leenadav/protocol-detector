# Release notes: merges of 2026-11-21 (PRs #33–#39)

Docs-only summary of seven merges to `main` on 2026-11-21. No content pack changed: `go/internal/content/pack.json` and the release history are the same as before, so no application is added, removed, or identified differently. No detection, parser or benchmark result changed. Every entry below is taken from the merge diff; `git show <sha>` shows the full change.

## What changed

| PR | Merge commit | Change | Operator or reviewer note |
|---|---|---|---|
| #33 | `d2e7e9a` (head `851eddb`) | `merge-readiness.yml` and `perf-history.yml` lost their branch-limited `push` triggers. `merge-readiness` now runs on `schedule` and `workflow_dispatch`; `perf-history` runs on `push` to `main` only. | To prove a workflow change on a branch, dispatch it on that branch. |
| #34 | `c402073` (head `a179db6`) | New `tools/check_required_checks.py`; `SSDLC.md` required-checks tables must match the real `ci` and `codeql` job names. The `ci` gate runs the check. | A job that is added or renamed needs its table row in the same PR. |
| #35 | `a6b096a` (head `12a56ae`) | `docs/LANE-BRIEF-platform.md` added; scope and cadence lines in `AGENTS.md`; SSDLC review-loop step 9. | Documentation only. |
| #37 | `0d32281` (head `7d04266`) | `docs/CONTENT-GOVERNANCE.md` now matches the release history: `HISTORY` on `main` ends at `2026.11.0`; `2026.11.1` to `2026.11.9` are on `claude/go-migration` only. | Those releases are not on `main` until that branch is merged. |
| #38 | `51b5e94` (head `7c33b1a`) | `AGENTS.md` gains "Code Review Rules" for automatic Codex review: four rules (untrusted parsers, content packs, the frozen Python reference, CI). | Review guidance; no runtime effect. |
| #39 | `0ef7349` (head `37b3c84`) | `protocol_engine/content.py`: release versions are compared numerically per component, so `2026.11.9` sorts before `2026.11.10`. `host_entries`, `host_provenance` and `check()` use the new comparison. | Python reference change, approved by Lee on 2026-11-20 (PRO-31). On `main` the history has two releases, so the result is the same as before; it matters from `2026.11.10` on. |

## Operator review before deploying

- No application identification moves between applications in these merges (no catalog change).
- The only code change is the version ordering in `protocol_engine/content.py` (#39). Check it only if you compare or roll back content releases by version.

## Verification (run on the PR branch)

- `python3 -B -m unittest test_content`: 15 tests, OK (`test_content.py` gained 5 test functions in #39).
- `tools/check_content.py`: ok, release `2026.11.0`, 2 releases, 54 host entries.
- `tools/check_required_checks.py`: ok.
- `tools/check_workflow_policy.py`: ok, 8 workflow files.
- `tools/check_docs_counts.py`: ok (families 88, automatic 79, applications 156, tests 838, version 0.66.0).
- Benchmarks: none in these merges; no performance number is claimed.

## Related

- Content releases: [RELEASE-NOTES-CONTENT.md](RELEASE-NOTES-CONTENT.md).
- Content governance: [CONTENT-GOVERNANCE.md](CONTENT-GOVERNANCE.md).
- Platform lane state: [LANE-BRIEF-platform.md](LANE-BRIEF-platform.md).
