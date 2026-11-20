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

## 2. Current state (2026-11-20, after PRO-42)

- `main` = `2b97e2d`. Three ready-for-review PRs (PRO-42; #33 passed `ci gate (all jobs)`), one topic each, all cut from `main`:
  - #33 `claude/ci-drop-branch-push-triggers`;
  - #34 `claude/ci-required-checks-table`;
  - #35 `claude/docs-lane-brief-agents-scope` (this brief, `AGENTS.md`, `SSDLC.md` step 9).

  `claude/cicd-next` (`46c3122`) holds the same content as #33 and #35, and is superseded by them.
- **Merged so far:**

  | PR | Content |
  |---|---|
  | #28 | Go minimum and toolchain jobs |
  | #30 | Nightly Go fuzz, content-pack gate, merge readiness, vendored Go, go-vendor and go-build jobs |
  | #31 | Performance history; draft release pipeline: reproducible Go binaries, SBOM, dry-run signing |
  | #32 | govulncheck over the engine's vendored source; Codex review packet |
- **On `main`:**
  - Every Go job runs with `GOPROXY=off` and the vendor tree; only the `go-vendor` job has module access.
  - Schedules: `nightly-fuzz`, `merge-readiness` (daily trial merge of `claude/go-migration`) and `perf-history`
    (on each push to `main`).
- **In flight:** the three PRs above, waiting on Hermes's review and Lee's one-tap merge. Also waiting on Codex's
  review and on the Engine lane's merge of `claude/go-migration`.

## 3. Where things live (reading order)

1. `AGENTS.md` on `main`: lanes, ownership, mailbox rules. It may be stale on old branches, so read it from `main`.
2. `SSDLC.md`: controls, the required-checks table, the CI/CD backlog (items 18–34 are the recent ones).
3. `docs/review-packet/INDEX.md`: what awaits Codex, chunked.
4. `docs/RELEASING.md`: the release controller and dry runs.
5. `tools/check_workflow_policy.py` docstring: rules 1–16 every workflow change must pass.
6. Issue #7 (mailbox) and `migration/MERGE-READINESS.md` on `claude/go-migration` (the Engine lane's merge plan).

## 4. How to verify

| Command | What it checks | Runtime |
|---|---|---|
| `make check PYTHON=python3` | Full product gate: lint, 833 tests, policy, docs counts, manifest, parity, and more | 1–5 min, depending on the machine |
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
| PRs #33, #34 and #35 merged | Hermes's review, then Lee |

## 6. Frozen SHAs awaiting Codex

- **Range `e927d44..ddc557d`, lane commits:** `c58fe65`, `3e1f7f2`, `8c243ea`, `eb18353`, `91113bc`, `5442d05`,
  `d7c482c`, `b57b819`, `8a129c7`.
- **Also:** `b97adc8` (Dependabot pins, chunk 06) and `85e99e9` (govulncheck, chunk 07).
- **The packet:** `3d9a40e`, `0a01368`, `58a1c0d`.
- **Not yet on `main`:** #33 head `851eddb`; #34 head `a179db6`; #35 head: the latest commit on `claude/docs-lane-brief-agents-scope`.
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
