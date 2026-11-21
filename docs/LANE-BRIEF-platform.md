# Lane brief: Platform & CI (the CI/CD lane)

Read this first in any new chat for this lane, then your Paperclip instructions. **Update this file at the end of
every task** (state, open items, frozen SHAs, pitfalls) and commit it with the task's last commit.

## 1. Purpose and scope

The lane builds and guards the repository's CI/CD and supply chain: GitHub Actions workflows, the CI tools that make
their decisions, the policy locks, and the release controller.

- **Owns:**
  - `.github/` (all workflows, `dependabot.yml`).
  - CI tools in `tools/`: `check_workflow_policy.py`, `check_workflow_yaml.py`, `check_action_pins.py`,
    `check_pin_drift.py`, `check_go_drift.py`, `go_ci.py`, `content_gate.py`, `merge_readiness.py`,
    `go_fuzz_long.py`, `perf_history.py`, `build_go_release.py`, `release_provenance.py`, `codeql_gate.py`,
    the release checks and the SBOM checks.
  - The locks `tools/workflows.lock.json` and `tools/scanner_config.lock.json`, and `tools/scanners/`.
  - The `Makefile`'s CI targets.
  - `SSDLC.md`, `docs/RELEASING.md`, `docs/review-packet/` and this file.
  - Mailbox issue #7.
- **Never touches:** `go/`, `migration/` and product code (Engine lane), Engine or Culvert branches (send patches
  by message instead), issue #2.
- **Never does:** merge, tag, release, deploy, change settings or permissions, force-push, comment on GitHub
  unless the lane rules call for it, or delete probe branches without Lee's word.

## 2. Current state (2026-11-21, after PRO-103)

- `main` = `dfaac0d`. PRO-42, PRO-59 and PRO-31 merged: #33 (`d2e7e9a`), #34 (`c402073`), #35 (`a6b096a`), #37 (`0d32281`), #38 (`51b5e94`), #39 (`0ef7349`);
  #41 and #54 (PRO-73) too. Open lane PRs: drafts #55 (PRO-77) and #57 (PRO-102) into `claude/go-migration`, #59 stacked on #57 and
  #60 stacked on #59 (PRO-103), and this brief update. `claude/cicd-next` (`46c3122`) is superseded and stale.
- **Merged so far:**

  | PR | Content |
  |---|---|
  | #28 | Go minimum and toolchain jobs |
  | #30 | Nightly Go fuzz, content-pack gate, merge readiness, vendored Go, go-vendor and go-build jobs |
  | #31 | Performance history; draft release pipeline: reproducible Go binaries, SBOM, dry-run signing |
  | #32 | govulncheck over the engine's vendored source; Codex review packet |
  | #33 | Branch-limited `push` triggers removed from `merge-readiness.yml` and `perf-history.yml` |
  | #34 | `tools/check_required_checks.py`: the SSDLC required-checks tables match the real job names |
  | #35 | This brief; current scope and cadence lines in `AGENTS.md`; SSDLC review-loop step 9 |
  | #37 | `docs/CONTENT-GOVERNANCE.md` matches the release history (`HISTORY` on `main` ends at 2026.11.0) |
  | #38 | `AGENTS.md` "Code Review Rules" for Codex automatic PR review; the Codex-comment rule |
  | #39 | `protocol_engine/content.py`: numeric version compare (2026.11.9 before 2026.11.10); 5 tests (Lee's exception, 2026-11-20) |
  | #41 | This brief after #33–#38; the 32-bit Go test item |
  | #54 | Root `CLAUDE.md` importing `AGENTS.md` (PRO-73). Codex's automatic review did not run (usage limit); not required for a docs-only change |
- **On `main`:**
  - Every Go job runs with `GOPROXY=off` and the vendor tree; only the `go-vendor` job has module access.
  - Schedules: `nightly-fuzz`, `merge-readiness` (daily trial merge of `claude/go-migration`) and `perf-history`
    (on each push to `main`).
- **In flight:** draft PR #55 (`claude/cicd-release-per-target-modules` → `claude/go-migration`, head `07cda53`;
  PRO-77, for Engine's PR #40). It applies Engine's per-target module sets to `tools/build_go_release.py`, adds
  `go:targets` per SBOM component, and takes `go:sum` from `go/go.sum`, since a `-mod=vendor` build records none.
  It merges only after code review and Lee's decision.
  Draft PR #57 (`claude/cicd-go-lint` → `claude/go-migration`, head `c050e4d`; PRO-102) adds the `go-lint` ci job:
  golangci-lint 2.15.0, staticcheck 2026.2.2 and gosec 2.29.0 (pinned modules in `tools/golint/`), `tools/go_lint.py`,
  and a 194-finding baseline that only shrinks (SSDLC item 35). Engine triages the baseline.
  Draft #59 (`claude/cicd-go-deep-gate`, head `5dde24e`, base #57's branch; PRO-103) adds `go-determinism` (`go test
  -race -shuffle=on -count=2`) and `go-licenses` (go-licenses 2.0.1; forbidden, restricted and unknown fail; x/crypto
  and x/sys are BSD-3-Clause), both via `tools/go_deep.py` (item 36). Draft #60 (`claude/cicd-ci-consistency`, head
  `07a2eed`, base #59's branch) adds `tools/check_ci_consistency.py`: every `uses:` in any spelling pinned with a
  revision comment, and one Go compiler across go.mod files, setup-go, GOTOOLCHAIN and the policy (item 37). PRO-71 is parked until Engine answers PRO-72. Also waiting
  on Codex's review and on the Engine lane's merge of `claude/go-migration`.

## 3. Where things live (reading order)

1. `CLAUDE.md` (imports `AGENTS.md`) and `AGENTS.md` on `main`: lanes, ownership, mailbox rules. It may be stale on old branches, so read it from `main`.
2. `SSDLC.md`: controls, the required-checks table, the CI/CD backlog (items 18–34 are the recent ones).
3. `docs/review-packet/INDEX.md`: what awaits Codex, chunked.
4. `docs/RELEASING.md`: the release controller and dry runs.
5. `tools/check_workflow_policy.py` docstring: rules 1–16 every workflow change must pass.
6. Issue #7 (mailbox) and `migration/MERGE-READINESS.md` on `claude/go-migration` (the Engine lane's merge plan).

## 4. How to verify

| Command | What it checks | Runtime |
|---|---|---|
| `make check PYTHON=python3` | Full product gate: lint, 838 tests, policy, docs counts, manifest, parity, and more | 1–5 min, depending on the machine |
| `make workflow-policy PYTHON=python3` | Policy rules and the self-tests of every lane tool | ~20 s |
| `python3 -B tools/check_workflow_policy.py --write-workflow-lock` | Regenerates the lock; run after any workflow edit | — |
| `actionlint`, `zizmor --persona pedantic`, `tools/check_workflow_yaml.py` | Workflow lint via `make workflow-lint`; needs the hash-pinned dev toolchain (`pip install --require-hashes -r requirements-dev.txt` in a venv) and actionlint 1.7.7 | ~30 s |
| CPython 3.9: `python3.9 -B -m unittest discover -q` | Second-interpreter tests | ~1 min |
| `make fuzz PYTHON=python3`, `python3 -B tools/check_security_requirements.py` | Fuzz and security requirements | ~20 s |
| Hosted: push the branch; ci, codeql and supply-chain-drift run | | ~15 min |
| Hosted, new workflow | Dispatch with the GitHub `run_workflow` tool | |

Go checks need Go 1.27.4, run with `GOPROXY=off GOTOOLCHAIN=local`. The container's Go is 1.24.7; get the
pinned one through `GOTOOLCHAIN=go1.27.4 go env GOROOT`.

## 5. Open items

| Item | Waits on |
|---|---|
| Codex review of `docs/review-packet/` (7 chunks: Tier 1 1,350 lines, Tier 2 893) | QA Reviewer (Codex), currently paused |
| Delete probe branches `claude/cicd-go-probe`, `-go-minimum-probe`, `-content-probe`, `-engine-probe` | Lee, after the Codex review |
| `claude/go-migration` → `main` merge (its `ci.yml` hunks resolve to `main`'s; CI is ready, probe `407bfcc` was green) | Engine lane and Lee |
| First real tag release (attest and publish steps have never run) | Lee |
| PR #55 merged into `claude/go-migration` (release build per-target modules) | Hermes's review, then Lee |
| PR #57 merged into `claude/go-migration` (go-lint job); the 194 baseline findings fixed or justified | Hermes's review, then Lee; Engine for the findings |
| Stacked #59, then #60, merged after #57 (each retargets to `claude/go-migration` when its base merges) | Hermes's review, then Lee |
| 32-bit Go tests (PRO-71, asked from PRO-46): a `GOARCH=386 go vet` + `go test ./...` step in `go-engine` (no `-race` on 386; offline; ~9 s for `./internal/protocols/...`) | Engine: `claude/go-migration` `5f01fcb` does not compile for 386 (13 constant overflows of `int`: framed 5, reassembly 2, signatures 6) |

## 6. Frozen SHAs awaiting Codex

- **Range `e927d44..ddc557d`, lane commits:** `c58fe65`, `3e1f7f2`, `8c243ea`, `eb18353`, `91113bc`, `5442d05`,
  `d7c482c`, `b57b819`, `8a129c7`.
- **Also:** `b97adc8` (Dependabot pins, chunk 06) and `85e99e9` (govulncheck, chunk 07).
- **The packet:** `3d9a40e`, `0a01368`, `58a1c0d`.
- **Merged, not yet Codex-reviewed:** #33 `851eddb`, #34 `a179db6`, #35 `d3faff8`..`12a56ae`, #37 `7d04266`, #38 `7c33b1a`, #39 `37b3c84`.
- **Rules:** do not rewrite these. Fix rounds are reviewed as the fix diff only.

## 7. Pitfalls learned

- **Stale checkout:** a restarted container may check out an old branch (`claude/appid-engine`). Run
  `git fetch` and work on `claude/cicd-next` at `origin/main` first.
- **Masked failures:** `cmd | tail` hides the exit status. Use `set -o pipefail` and check `make check`'s status
  before committing. One broken push (`91113bc`) came from this.
- **Workflow lock:** every workflow edit needs `--write-workflow-lock`. Rule 7 wants one SHA per action across all
  workflows. Rule 13 forbids `if:` and shell conditionals in `ci.yml`, so put the decision in a tool with a
  self-test.
- **Policy self-test mutations:** they replace the *first* occurrence of a line. When a job gains steps, anchor
  them with `in_job()`.
- **CodeQL error gate:** no `assert` around a call with side effects, and no variable read after
  `parser.error`.
- **Paths in tools:** a tool that runs subprocesses with `cwd=go` must resolve output paths to absolute.
- **New workflows:** `workflow_dispatch` works only once the workflow is registered. Give a new workflow a
  branch-limited `push` trigger, push, then dispatch. Schedules run only from `main`.
- **Go:** `GOPROXY=off` means dependencies must be vendored. `-mod=vendor` on a module with no dependencies is
  fine. `GOTOOLCHAIN=<name>` downloads unless the local Go matches.
- **Cancelled runs:** a gate red only because a newer push cancelled the run's jobs is not a failure.
  Presentation `test_jobs` can fail under heavy local CPU load, so re-run before suspecting code.
- **Scheduled-task cleanup:** deleting a scheduled task is denied by the auto-mode classifier; disable it with
  `update_trigger` instead.
- **Opening PRs:** `gh` is not available in these sessions; open them with the GitHub MCP `create_pull_request`
  tool, ready for review (`draft: false`). Lee merges and the lane never merges, closes or comments. Before
  pushing, trial-merge PRs that touch the same files (`SSDLC.md`, the lock) with `git merge-tree`, and check the
  lock with the policy tool after a real merge.
- **Codex review comments on a lane PR:** push the fix to the same branch, then reply in the PR's board task naming
  the commit. Never reply on GitHub: Hermes verifies the fix and resolves the thread. The rules Codex applies are
  in `AGENTS.md` "Code Review Rules" (#38).
- **Edits after a merge:** a commit pushed to a PR branch after Lee merges it never reaches `main`. Check the PR
  state before adding to its branch; otherwise cut a new branch from `origin/main` (PRO-71: `eae6718` missed #35).
- **Vendored Go build info:** `go version -m` on a `-mod=vendor` binary records no module `Sum`. Take hashes from
  `go/go.sum`; per target, the linked modules differ (x/crypto pulls x/sys on amd64 only).
- **gosec on Go 1.27:** gosec v2.29.0's own x/tools (v0.49.0) cannot read Go 1.27 export data. It then reports 0
  issues with "Golang errors" set. `tools/golint/gosec/go.mod` raises x/tools to v0.52.0, and `tools/go_lint.py`
  fails on any load error. Never trust a 0 without checking that the tool loaded the tree.
- **Stacked PRs:** CI PRs into `claude/go-migration` that edit the same `ci.yml` gate line, policy and locks are
  stacked (each PR's base is the previous one's branch), not parallel. Parallel PRs would conflict on every merge.
  ci runs on any `pull_request` base, so stacked PRs get full CI. Update a lower branch by merging, never by rebasing.
