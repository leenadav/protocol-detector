# Lane brief: Platform & CI (the CI/CD lane)

Read this first in any new chat for this lane, then your Paperclip instructions. **Rule (PRO-347, 2026-11-24):
every task adds its own `migration/notes/PRO-<n>.md`** (front matter: task, lane, date, title, PRs, SHAs; then one
paragraph; `migration/notes/README.md`) with the task's last commit; it is the task's record and its frozen SHAs.
**Never edit a section between `BEGIN GENERATED` and `END GENERATED` markers** ("Recent work" below, the
README/REVIEW-SCOPE test counts): `tools/build_ledgers.py` writes them after merge. Edit the hand-written sections
(state, open items, frozen SHAs, pitfalls) only when the lane's standing state changes, not to log a task.

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

## 2. Current state (2026-11-24, after PRO-262 and PRO-202 step 3)

- **PRO-402 (Python removal 2/3, PR B):** #125, branch `claude/platform-PRO-402-demo-go-serve`, merged with `main`
  after PR A (#127). PR A made `protodetect serve` interpreter-free; this PR removes the Python backend selection
  that was left: `serve` has no `--python`, `presentation/launch.py` and `protodetect.py analyze|live|serve` run the
  Go binary only (no `--backend`, no fallback), `main.py` starts the page, and `make serve` does the same.
  `test_ui.GoServiceBrowserTests` runs the Playwright dashboard suite against the Go service with no Python engine
  reachable. PR C (PRO-403) deletes `presentation/server.py` and the Python engine.
- **PRO-262 (32-bit protocol tests):** `make go-check-386` and the `go-engine` step "32-bit protocol tests" (offline, vendored, `CGO_ENABLED=0`, no `-race` on 386). Proven on the old SEC-X509-1 check (`pos+size > limit`): the 386 run fails `x509x`, amd64 passes. The job name is unchanged, so required checks keep matching.
- **PRO-202 (CI speed), step 3:** branch `claude/platform-PRO-202-ci-speed` adds the docs-only fast path:
  `tools/ci_scope.py` (fail-closed: only `pull_request`, only a two-parent merge HEAD, only `*.md` and
  `research/` outside `research/tools/`) and `--docs-only-fast-path` on `go-engine`, `go-fuzz-smoke`, `go-parity`,
  `go-minimum` and `go-determinism` (checkout `fetch-depth: 2`). No job-level `if:`; the gate is unchanged. Measured
  before: code PR run 45422975498 (#107) 5.7 min wall, critical path go-parity and go-determinism 4.4 min each;
  steps 1 (one run per change, cancel-in-progress) and 2 (#96, the split) are on `main`. Docs-only floor after this
  step is the Python and presentation jobs (~2.2-2.8 min), which keep running in full. Next: step 4, Go build cache
  saved on `main` only (cache-poisoning rules first), and the presentation chain (`package` -> `presentation-ui`).
- **PRO-202 (CI speed), step 2:** recovery PR #93 merged (`d3a4dab`), so #59–#64, #75, #76, #89 and #91 are on `main`.
  Step 2 (`claude/cicd-go-engine-split`) splits the ~10.5-minute `go-engine` job into `go-engine` (`make
  go-check-static` + `make go-check-race`), `go-fuzz-smoke` (a `["1/3", "2/3", "3/3"]` matrix over `make
  go-check-fuzz`, sharded by `tools/go_fuzz_smoke.py` from the Makefile's GO_FUZZ_SMOKE list) and `go-parity` (`make
  go-check-parity`). `make go-check` still runs the four parts in order. `tools/go_fuzz_smoke.py --check-matrix`
  (workflow-lint, `make workflow-policy`) fails a matrix that drops a shard; a listed target that no test defines
  fails. Steps 3 (tool-decided docs-only fast path) and 4 (GOMODCACHE cache saved on `main` only) follow as their own PRs.
- **PRO-194** (`build_go_release.py`), on branch `claude/determined-mayer-cyjpa0` from `main` `23bbc0c`. Finding 1 is
  the cherry-pick `305f8ef` of `695bb09`: the release fails when `go/go.mod` exists and `go/cmd/protodetect` does
  not. Finding 2 adds `-X main.version=<version>` and requires the linux/amd64 binary's `protodetect version` to
  report exactly that version (`docs/RELEASING.md`). The local `5324543` was lost with its container and was
  rewritten here. **Merge order:** Engine's PR #143 (PRO-195, `var version`) first, then merge `main` into this
  branch. Until then the publish-release dry run fails, correctly, because `main` still has `const version`.
  #143 merged; `83ad798` (PRO-478) merged `main` in. The release build then failed on two launcher tests: the
  launchers default to the Go engine and the job never built `go/bin/protodetect`. It now runs `go_ci.py build`
  before the gate, as `ci.yml` does; the docs test count was refreshed to 909.

- `main` = `2a33183`. PRO-42, PRO-59 and PRO-31 merged: #33 (`d2e7e9a`), #34 (`c402073`), #35 (`a6b096a`), #37 (`0d32281`), #38 (`51b5e94`), #39 (`0ef7349`);
  #41 and #54 (PRO-73) too. #56 (the brief through PRO-103) and #66 (gitleaks allowlist for the r5 CNAME false positive, PRO-145) are merged.
  Open lane PRs: drafts #55 (PRO-77) and #57 (PRO-102) into `claude/go-migration`, and the stack on #57: #59 and #60 (PRO-103),
  #61, #62 and #64 (PRO-104), #65 (PRO-136); #63 (the brief through PRO-104) is merged. Draft #73 (PRO-105,
  `claude/cicd-verify-flaky-policy`, head `33fcd00`, base `claude/go-migration` `cdb385b`, independent of the stack) adds the
  verify skills and the flaky-test policy (39/39 green); #74 (the brief through PRO-105) is merged. PRO-128 adds two
  drafts on top of the stack: #75 (`claude/cicd-osv-scanner`, head `71fafdc`, base #65's branch) and #76
  (`claude/cicd-scorecard`, head `ee40000`, base #75's branch). #65 merged `claude/go-migration` `bb2af2e` (`a7888f8`)
  for its gitleaks allowlist, plus this brief update. `claude/cicd-next` (`46c3122`) is superseded and stale.
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
  | #56 | This brief through PRO-77, PRO-102 and PRO-103 |
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
  revision comment, and one Go compiler across go.mod files, setup-go, GOTOOLCHAIN and the policy (item 37). Draft #61 (`claude/cicd-go-coverage`, head
  `2df7e83`, base #60's branch) adds `go-coverage`: `-coverpkg=./...`, module floor 78.0% (79.0% measured), and a floor for
  every `internal/protocols/*` parser (item 38). Draft #62 (`claude/cicd-go-api`, head `7f75239`, base #61's branch) adds
  `go-api`: apidiff, where a public break fails without the `api-break` label (item 39). The module has no public package
  yet, so draft #64 (`claude/cicd-contract-compat`, head `a5b287a`, base #62's branch; Hermes in PRO-131) adds
  `contract-compat`: `tools/contract_check.py` compares schemas/*.schema.json ($ref resolved) and the protodetect CLI, read
  from its own help, at the same base and with the same `api-break` label (item 40). Draft #65 (`claude/cicd-nightly-parity-random`, head `6fdaa33`, base
  #64's branch; it merges `claude/go-migration` `d7a9290`) adds the nightly `parity-random` job: Engine's
  `make parity-random-long`, 50,000 cases in batches of 25,000 with one seed each. PRO-71 is parked until Engine answers PRO-72. Also waiting
  on Codex's review and on the Engine lane's merge of `claude/go-migration`.
- **PRO-105 (#73):** `.claude/skills/verify-parity`, `verify-content-pack` and `verify-go` name the exact commands
  and healthy output an agent checks before reporting done. `AGENTS.md` "Flaky tests and verify skills": never re-run to
  green; a test that fails twice intermittently is quarantined with an issue link and a deadline; no quarantine of a
  security, parity, content or budget gate. `claude/cicd-verify-skills` (`4d4e463`, stacked on #65) is superseded by #73.
- **PRO-128 (#75, #76):** the `osv-scan` ci job (osv-scanner 2.7.1 from `tools/golint/osv-scanner`, `tools/osv_scan.py`,
  ignore file `tools/osv_ignore.json`: each entry has a lockfile, package, reason and an expiry at most 90 days ahead; SSDLC
  item 41) and the weekly `scorecard.yml` (scorecard-action v2.5.0, SARIF to code scanning, `publish_results: false`;
  item 42). The first OSV run found 52 groups, all in CI tool modules; bumps fixed all but rardecode 2.1.0 in the gitleaks
  build (accepted until 2026-12-22). Three more came with go-migration's gremlins module (x/sys, x/text; unreachable),
  accepted until 2026-12-06 while Engine bumps its own module.

### Recent work (generated)

Written by `tools/build_ledgers.py` from `migration/notes/PRO-<n>.md`, newest first. Never edit it: a task adds
its own notes file, and the section is refreshed after merge.

<!-- BEGIN GENERATED: recent-work lane=platform limit=15 -->
<!-- tools/build_ledgers.py writes this section from migration/notes/PRO-<n>.md. Do not edit it: add a notes file instead (migration/notes/README.md). -->

- 2026-11-25 · **PRO-402** · platform · Python removal 2/3 (PR B) - the demo page runs on the Go server with no interpreter: PR B of the Python removal, merged with main after PR A (PRO-401, #127). PR A had already made protodetect serve interpreter-free (embedded demo capture and catalog, Go TLS showcase), so the merge keeps main's implementation and drops this branch's duplicate. This PR now removes the last Python backend selection: serve has no --python option (TestServeHasNoPythonOption), presentation/launch.py and protodetect.py analyze|live|serve run the Go binary only, with no backend option and no fallback (test_launchers.py, test_launch_backend.py), main.py starts the page, and make serve does the same. test_ui.GoServiceBrowserTests runs the whole Playwright dashboard suite against the Go service from a directory holding only web/ and SOURCE.json. CODEOWNERS names /go/ and /presentation/, and the verify job allow-lists the new browser test (it runs with no skip allowed in presentation-ui). presentation/server.py stays for make golden-record until PR C deletes the Python engine. PRs: #125. SHAs: `cddaa1dd55125ba01d7fe0206e89c0e67ea069c0`, `476a7987ee162f4ea8fa3ce5432417eb117dbde6`, `356249b80c24eb1d5d780473a1f45e3d70cbb0aa`, `143be5843948a5ca78187ec2a69ac332d52256cd`. (merged in #125)
- 2026-11-24 · **PRO-347** · platform · Shared ledgers generated from per-task notes: Each task now adds migration/notes/PRO-<n>.md instead of editing the shared ledgers. tools/build_ledgers.py (stdlib, deterministic) writes the marked "Recent work" sections of both lane briefs and STATUS.md from the notes plus git log (the pull request that merged each note), and the README/REVIEW-SCOPE test counts from tools/check_docs_counts.py. The ci `ledgers` job fails on a hand edit or a malformed note and lets a pull request's own note lag; check_docs_counts.py fails on a lagging test count only with --strict (release gate, nightly job). The release build checks out the full history and runs build_ledgers.py --self-test and, for a tag, --check --strict (dry runs: --check). The nightly ledgers workflow runs the strict check and uploads the refresh patch read-only; opening the refresh pull request itself needs Lee's policy decision (write token). Two branches that each add a note merged with no conflict (self-test and a real trial merge). (merged in #119)
<!-- END GENERATED: recent-work -->

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
| PRO-347: the nightly `ledgers` workflow is read-only (strict check, refresh patch as an artifact). Opening the docs-only refresh pull request from it needs `contents: write` + `pull-requests: write` (rule 5 forbids both outside the release controller), the repository setting that lets Actions create pull requests, and a token whose pull requests trigger ci (`GITHUB_TOKEN` ones start no workflow). Until then Deputy applies the patch | Lee's decision (SSDLC item 43) |
| PRO-480: branch `claude/platform-PRO-480-release-dryrun-counts` refreshes the generated ledgers (895 → 909) and runs `check_docs_counts.py --strict` in `publish-release.yml` for a tag only (policy `check_release_docs_counts`); the release build job also builds the Go binary before its gate (PRO-402 made `analyze` Go-only). After it merges: merge `main` into #149 (`claude/determined-mayer-cyjpa0`, PRO-194) and refresh Dependabot #151 (PRO-478) | Hermes's review, then Lee; PRO-194 and PRO-478 owners for the refresh |
| Delete probe branches `claude/cicd-go-probe`, `-go-minimum-probe`, `-content-probe`, `-engine-probe` | Lee, after the Codex review |
| `claude/go-migration` → `main` merge (its `ci.yml` hunks resolve to `main`'s; CI is ready, probe `407bfcc` was green) | Engine lane and Lee |
| First real tag release (attest and publish steps have never run) | Lee |
| PR #55 merged into `claude/go-migration` (release build per-target modules) | Hermes's review, then Lee |
| PR #57 merged into `claude/go-migration` (go-lint job); the 194 baseline findings fixed or justified | Hermes's review, then Lee; Engine for the findings |
| The stack merged in order #57 → #59 → #60 → #61 → #62 → #64 → #65 (each retargets to `claude/go-migration` when its base merges) | Hermes's review, then Lee |
| PR #73 merged into `claude/go-migration` (verify skills, flaky-test policy); a quarantine-expiry checker in CI is a possible follow-up | Hermes's review, then Lee |
| The stack continued: #75 → #76 after #65 | Hermes's review, then Lee |
| PRO-136: draft #78 (`claude/cicd-nightly-parity-direct`, head `cd153f8`, base `claude/go-migration` `bb2af2e`) is the change, per Hermes; #65 is closed as superseded (its branch stays as #75's base). Dispatch 44995320464: parity 50,000 of 50,000 matched, mutation fuzz ok, Go fuzz job reported separately. `migration/LANE-BRIEF.md` line 82 is Engine's file; Engine updates it | Lee merges #78; Engine for its brief |
| Scorecard `publish_results: true` (needs `id-token: write` and no top-level `defaults:`, rules 5 and 6) | Lee's decision on a policy exception |
| OSV entry GO-2025-4020 (rardecode in the gitleaks build) expires 2026-12-22 | A gitleaks release whose archives dependency builds with rardecode 2.2.0 |
| Scorecard follow-ups: one task per check that scores low on the first run (expected: License, Code-Review, Branch-Protection, CII-Best-Practices, Signed-Releases, Packaging) | The first scheduled run on `main` after the stack merges |
| PR #81 merged to main: one `[[allowlists]]` entry, AND of path `research/live-results-*.tsv` and a whole-match `host>host` chain; `tools/check_gitleaks_allowlist.py` proves keys and tokens there still flag | Done |
| PR #82 merged to main (`fa191c1`, 10:15Z, board merge flow): release provenance and the audit compare against refs/heads/main's SHA; the audit fails on a tag named main | Done |
| PR #83 merged to main (PRO-172): policy rule 17 refuses refs a same-named tag could shadow; merge-readiness uses `refs/remotes/origin/...` | Done |
| PRO-200 skills: `.claude/skills/` holds 7 MIT skills copied from obra/superpowers 7.0.2 (`22f0b46`: systematic-debugging, test-driven-development, verification-before-completion, receiving-code-review) and samber/cc-skills-golang 2.0.1 (`d68d80a`: golang-testing 1.4.0, golang-performance 1.3.2, golang-error-handling 1.3.1); provenance in `.claude/skills/THIRD_PARTY.md`. Repo-declared plugins do not load in cloud sessions (smoke on `1542a34`); Trail of Bits (CC-BY-SA) not taken | Hermes's review, then Lee |
| Gitleaks hex HTTP/1 allowlist scoped (PRO-183/PRO-184, the gitleaks SEC-CI-1): branch `claude/cicd-gitleaks-hex-scope`, base main. Own `[[allowlists]]` entry, AND of path `^go/.*_test\.go$` and the hex regex; `check_gitleaks_allowlist.py` proves a hex request with a cookie still flags in .py, .json and non-test .go. `claude/go-migration` keeps its own repo-wide copy until it merges main | Hermes's review, then Lee |
| Bump `migration/mutation/gremlins/go.mod` (x/sys ≥ 0.44.0, x/text ≥ 0.41.0); then drop its 3 OSV entries before 2026-12-06 | Engine |
| Nightly mutation job (PRO-176): gremlins built in isolation, run with `GOPROXY=off` and `MUTATION_BIN`, artifact always uploaded | A Hermes task; Engine's `MUTATION_BIN` is in `e9b0ef0` (PR #72) |
| 32-bit Go tests (PRO-71 → PRO-262): `make go-check-386` (part of `make go-check`) runs `go test` with `GOARCH=386` on every `./internal/protocols/...` package except `GO_386_EXCLUDE`, as the `go-engine` job's third step (`go_ci.py go --part 386`). Branch `claude/platform-PRO-262-go-386`. Today 6 packages test, 2 have no tests, `framed` is excluded; an excluded package that compiles fails the target | Hermes's review, then Lee; Engine to make `framed` (5 constant overflows of `int`) build on 386, then drop it from `GO_386_EXCLUDE` |

## 6. Frozen SHAs awaiting Codex

- **Range `e927d44..ddc557d`, lane commits:** `c58fe65`, `3e1f7f2`, `8c243ea`, `eb18353`, `91113bc`, `5442d05`,
  `d7c482c`, `b57b819`, `8a129c7`.
- **Also:** `b97adc8` (Dependabot pins, chunk 06) and `85e99e9` (govulncheck, chunk 07).
- **The packet:** `3d9a40e`, `0a01368`, `58a1c0d`.
- **Merged, not yet Codex-reviewed:** #33 `851eddb`, #34 `a179db6`, #35 `d3faff8`..`12a56ae`, #37 `7d04266`, #38 `7c33b1a`, #39 `37b3c84`.
- **PRO-480 (#154):** `8e13f57a1303fca696db674da6414b833c4ad544` (strict docs counts on a tag only, ledgers refresh) and `031f23635834f4a42fa226b4adf8589c5ed2c7d8` (Go binary before the release gate).
- **PRO-194:** `305f8ef` (finding 1, cherry-pick of `695bb09`) and the finding 2 commit on
  `claude/determined-mayer-cyjpa0`.
- **Rules:** do not rewrite these. Fix rounds are reviewed as the fix diff only.

## 7. Pitfalls learned

- **Strict checks in release dry runs (PRO-478):** a generated count lags every pull request by design, so a
  `--strict` check in `publish-release.yml` must be gated on `REF_TYPE = tag`, as the ledgers step is. An
  unconditional `check_docs_counts.py --strict` turned every PR's release build red (Dependabot #151, #149).
- **Release gate needs the Go binary (PRO-478):** since PRO-402 `protodetect.py analyze` runs only the Go binary
  and exits 2 without it. Any job that runs `unittest discover` must first run `tools/go_ci.py build` (offline,
  vendored), as the ci test jobs do; `publish-release.yml` did not, and two launcher tests failed `2 != 0`.
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
- **Strict only on a tag:** a check that fails while `main`'s generated sections lag (`--strict` of `check_docs_counts.py`
  or `build_ledgers.py`) must not run on a pull request or a branch push; gate it on `REF_TYPE = tag` (PRO-480).
- **Job names are check names:** renaming a job (its `name:`) can orphan a required status check; add a step and keep the name.
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
- **Coverage numbers:** measure with `-coverpkg=./...`. Per-package coverage from a package's own tests understates the
  parsers, which the parity replay exercises: textroute is 4.5% from its own tests, 82.3% with `-coverpkg`. Count a block
  once across test binaries.
- **Tool pins and the cooldown:** `@latest` can resolve to a commit from today. Pin one at least 7 days old, as Dependabot's
  cooldown does (apidiff: x/exp `e3970619a1a4`).
- **Replay budget:** `protodetect replay` reads at most 64 MiB of cases per process (`MaxDocumentBytes`), about 37,000
  random cases. Long parity runs go in batches (25,000 per seed). `make` does not create `build/`, so create it first.
- **Flaky Engine test:** `internal/livectl` TestStopKillsTheProcessGroupOfAWorkerThatIgnoresTheInterrupt failed once in 4
  full `-coverpkg` runs under load, and passed 8 of 8 alone. Reported to Engine (PRO-104); never re-run blindly to mask it.
- **Planted self-check output:** `make parity-random` prints `random differential FAILED: engines differ on
  random/tls/1/00000` for its planted 300-case run. That line is expected; the check fails only if the plant is not caught.
- **Base of a doc-only PR:** a PR that touches no file of the stack goes directly on `claude/go-migration` (Lee's rule).
  Cutting it from the top of the stack drags the stack's lag behind `claude/go-migration` into its diff (139 files for #73).
- **OSV vs govulncheck:** osv-scanner reports every advisory against a pinned version; govulncheck `-mode=binary` on
  the built tool says which are reachable. Bump what you can (each release at least 7 days old), and prove behaviour
  unchanged (gitleaks findings old vs new build, the lint baseline, the licence report). rardecode 2.2.0 breaks
  gitleaks' mholt/archives 0.1.2, so the scanners module cannot take it alone.
- **Scorecard publishing:** `publish_results: true` conflicts with rules 5 and 6; never relax them without Lee.
- **Stack behind go-migration:** gitleaks reads every fetched branch, so a stack branch without go-migration's
  `.gitleaks.toml` allowlist fails static analysis once the known false positives exist on any branch. Merge
  go-migration into the top of the stack (#65), then merge up; never rebase.
- **gitleaks allowlists:** gitleaks 8.30 refuses `[allowlist]` next to `[[allowlists]]`; use only `[[allowlists]]`. Any synthetic secret or
  CNAME chain in a test tool must be built at run time, or the repository's own full-history scan reports it.
