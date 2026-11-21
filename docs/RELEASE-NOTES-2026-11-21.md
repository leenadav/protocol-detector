# Release notes: merges of 2026-11-21 (PRs #33–#39 and #41–#54)

Docs-only summary of the merges to `main` on 2026-11-21: PRs #33–#39 (first part) and PRs #41–#54 (second part). No content pack changed in either part: `go/internal/content/pack.json` and the release history are the same as before, so no application is added, removed, or identified differently. No detection, parser or benchmark result changed. Every entry below is taken from the merge diff; `git show <sha>` shows the full change.

## PRs #33–#39

### What changed

| PR | Merge commit | Change | Operator or reviewer note |
|---|---|---|---|
| #33 | `d2e7e9a` (head `851eddb`) | `merge-readiness.yml` and `perf-history.yml` lost their branch-limited `push` triggers. `merge-readiness` now runs on `schedule` and `workflow_dispatch`; `perf-history` runs on `push` to `main` only. | To prove a workflow change on a branch, dispatch it on that branch. |
| #34 | `c402073` (head `a179db6`) | New `tools/check_required_checks.py`; `SSDLC.md` required-checks tables must match the real `ci` and `codeql` job names. The `ci` gate runs the check. | A job that is added or renamed needs its table row in the same PR. |
| #35 | `a6b096a` (head `12a56ae`) | `docs/LANE-BRIEF-platform.md` added; scope and cadence lines in `AGENTS.md`; SSDLC review-loop step 9. | Documentation only. |
| #37 | `0d32281` (head `7d04266`) | `docs/CONTENT-GOVERNANCE.md` now matches the release history: `HISTORY` on `main` ends at `2026.11.0`; `2026.11.1` to `2026.11.9` are on `claude/go-migration` only. | Those releases are not on `main` until that branch is merged. |
| #38 | `51b5e94` (head `7c33b1a`) | `AGENTS.md` gains "Code Review Rules" for automatic Codex review: four rules (untrusted parsers, content packs, the frozen Python reference, CI). | Review guidance; no runtime effect. |
| #39 | `0ef7349` (head `37b3c84`) | `protocol_engine/content.py`: release versions are compared numerically per component, so `2026.11.9` sorts before `2026.11.10`. `host_entries`, `host_provenance` and `check()` use the new comparison. | Python reference change, approved by Lee on 2026-11-20 (PRO-31). On `main` the history has two releases, so the result is the same as before; it matters from `2026.11.10` on. |

### Operator review before deploying

- No application identification moves between applications in these merges (no catalog change).
- The only code change is the version ordering in `protocol_engine/content.py` (#39). Check it only if you compare or roll back content releases by version.

### Verification (run on the PR branch)

- `python3 -B -m unittest test_content`: 15 tests, OK (`test_content.py` gained 5 test functions in #39).
- `tools/check_content.py`: ok, release `2026.11.0`, 2 releases, 54 host entries.
- `tools/check_required_checks.py`: ok.
- `tools/check_workflow_policy.py`: ok, 8 workflow files.
- `tools/check_docs_counts.py`: ok (families 88, automatic 79, applications 156, tests 838, version 0.66.0).
- Benchmarks: none in these merges; no performance number is claimed.

## PRs #41–#54

Research, lane-brief and instruction-file merges. The only paths changed since #39 (`0ef7349`) are `CLAUDE.md`, `docs/` and `research/`. Nothing under `go/`, `protocol_engine/`, `.github/` or `tools/` changed. The research files hold host names, counts and synthetic test vectors; they change no product behaviour and no content pack.

### What changed

| PR | Merge commit | Change | Operator or reviewer note |
|---|---|---|---|
| #41 | `8674def` | `docs/LANE-BRIEF-platform.md` refreshed after #33–#38; adds the 32-bit Go test item (PRO-71). | Open, not in CI. `claude/go-migration` `5f01fcb` does not compile for `GOARCH=386` (13 constant overflows of `int`: framed 5, reassembly 2, signatures 6). The brief proposes a 386 step in `go-engine`. |
| #42 | `01a0bdd` | Research method v2 in `research/README.md`; `research/LANE-BRIEF.md`, `research/backlog.md`, `research/allowlist-requests.md`, `research/blocked-urls.md`. | Method and queue only. Confidence levels N3, N2, N1, S, U, plus the L (live-verified) and O (observed) inputs. |
| #43 | `dfaac0d` | `research/datasets.md`: dataset survey and licence rules. | LEE-1 (decided 2026-11-18): use only data whose licence clearly allows evaluation for a commercial product. The CIC dataset licence statements conflict, so the download (LEE-2) is held. CrUX (CC BY 4.0) and Majestic Million (CC BY 3.0) pass LEE-1; no list content is committed. The merge adds no dataset file. |
| #52 | `ec98d7e` | `research/patches/`: `README.md` and 14 patch files (batches A–L, R, B2, K). These are **proposed** content-pack changes for the Engine lane. | **Proposals, not implemented on `main`.** `main`'s `pack.json` is unchanged. The patch README records batches A, B, B2 and C as applied by the Engine lane on `claude/go-migration` (content 2026.11.3 to 2026.11.6, see the table above). It does not record D to F as applied; the batch F ids (`prisma-access`, `jetbrains-ai`, `loom`) are absent from that branch's pack. Batches G to L, J, K and R are not applied anywhere: their ids (for example `google-gemini-api`, `citrix-cloud`, `jamf-pro`, `meta-base`) are absent from `go/internal/content/pack.json` on `claude/go-migration` (`0081f6f`). The release numbers in the README for G to L are placeholders (2026.12.x). |
| #53 | `baba26f` | Research data: live-verification results (`live-results-2026-11-20.tsv` and `-r2.tsv`), live host lists (`live-hosts*.txt`), dependency observations (`observations/pass1-2026-11-19.json`, `observations/pass2-2026-11-20.tsv`, `web-urls.txt`), registry data (`apps.json`, `app-domains.json`), `source-state.json`. | Host-name level only: DNS and TLS fields, request counts and page status. The research README says observation outputs hold host names, request counts and page status only, and the raw JSON stays on the server. No packet capture or payload is in the merge. These results are inputs to specs; they are not product results. |
| #54 | `2e03ea1` | Root `CLAUDE.md` (new), which imports `AGENTS.md` (`@AGENTS.md`) and adds Claude Code commands and conventions. `docs/LANE-BRIEF-platform.md` refreshed after PRO-73. | Documentation only. Changes which instructions Claude Code sessions read; no runtime effect. |

### Operator review before deploying

- Nothing to review for deployment: no content, application identification, parser or detection change. The `#52` patches change nothing until an Engine-lane release applies them; check that release's notes when it ships.

### Verification

- Changed paths since `0ef7349`: `CLAUDE.md`, `docs/` and `research/` only (`git diff --name-only 0ef7349 origin/main`).
- `go/internal/content/pack.json` and `protocol_engine/content.py` are unchanged since #39.
- No test gate was run for this section: the change is docs-only and touches no code.

## Related

- Content releases: [RELEASE-NOTES-CONTENT.md](RELEASE-NOTES-CONTENT.md).
- Content governance: [CONTENT-GOVERNANCE.md](CONTENT-GOVERNANCE.md).
- Platform lane state: [LANE-BRIEF-platform.md](LANE-BRIEF-platform.md).
- Patch proposals (#52): [research/patches/README.md](../research/patches/README.md).
- Research method and dataset licences (#42, #43): [research/README.md](../research/README.md), [research/datasets.md](../research/datasets.md).
