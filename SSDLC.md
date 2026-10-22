# Secure software development lifecycle

The project follows a lightweight SSDLC in which every phase leaves an
artifact in the repository and every security claim has an executable check.

| Phase | Practice | Artifact / gate |
|---|---|---|
| Requirements | Security requirements written as testable statements (SR-n) | SECURITY-REQUIREMENTS.md; CI job `security-requirements` fails when a row has no existing test |
| Design | Threat model per trust boundary, STRIDE table, explicit contracts for budgets and evidence | THREAT-MODEL.md, ARCHITECTURE.md, PROTOCOLS.md profile per family |
| Implementation | Bounded parsing patterns (length before allocation, one parser per stream, immutable registries), no runtime dependencies, Python 3.9 syntax | CONTRIBUTING.md definition of done, code review via PR template checklist, issue templates that ask for synthetic inputs only; CODEOWNERS |
| Verification | Unit tests (every split point, single bytes, truncations), seeded mutation fuzzing, GC-release tests, work-bound assertions, static analysis, documentation numbers recomputed from the tree | `make check`, CI `verify` matrix (3.9/3.11/3.13) with job summaries, CI `behaviour-diff` (run-id seed) and CI `mutation-smoke` (a second, fixed seed under Python 3.9 plus a 100-mutation fuzz pass seeded by the run number, both with the reproducing command in the job summary), ruff, bandit, CodeQL with the `security-extended` and `security-and-quality` suites (error-level findings fail via `tools/codeql_gate.py`, which also writes a per-rule table to the job summary; SARIF kept as an artifact, uploaded to the Security tab once code scanning is enabled in repository settings), `tools/check_docs_counts.py` (README/REVIEW-SCOPE families, applications, tests and version), nightly fuzz |
| Supply chain | SHA-pinned actions whose tag comments are re-verified weekly, hash-pinned dev tools (wheel and source hashes where a wheel is platform specific), known-vulnerability audit of the toolchain, SBOM, read-only tokens with per-job additions only where a step needs them, Dependabot, workflow linting | CI `supply-chain`, CI `toolchain-audit` (pip-audit over requirements-dev.txt in hash mode, strict, also on the weekly schedule so new advisories surface without a code change), dependabot.yml, `tools/check_action_pins.py`, CI `workflow-lint` (actionlint fetched by version with its published SHA-256 verified before use, then zizmor from the hash-pinned toolchain auditing every workflow for template injection, credential persistence, cache poisoning, undocumented or excessive permissions, unpinned or superfluous actions and missing concurrency limits; pedantic persona, any finding fails), harden-runner egress audit on every job of every workflow, the release published with the runner's own `gh` CLI rather than a third-party action, `.github/workflows/supply-chain-drift.yml` (weekly and whenever any workflow file, requirements-dev.txt or the checker change, which `tools/check_workflow_policy.py` enforces against the files the drift checker scans: `tools/check_pin_drift.py` resolves each pinned SHA's tag comment against the action repository and fails when the tag moved or vanished; the actionlint release and SHA-256 named in ci.yml are downloaded and re-verified; every dev dependency is downloaded with `--require-hashes` and pip-audit is installed from those verified files alone) |
| Release | Every push builds the sdist and wheel, checks the wheel holds exactly the engine package with no runtime dependency (`tools/check_wheel.py`) and installs it into an empty environment under Python 3.13 and again under Python 3.9, where `tools/wheel_smoke.py` classifies an HTTP request and a DNS query from the installed package and refuses an import from the checkout (CI `package`); on a `v*` tag the release workflow's read-only build job passes the full gate (compile, tests, ruff, pins, security requirements, docs numbers, coverage matrix, policy lint), checks that the reported version equals pyproject.toml and the tag, refuses a tag whose commit is not already on `main` (GitHub compare API with the read-only token, `tools/check_release_ref.py`, failing closed on any unexpected answer; dry runs only report), builds, runs the wheel gate and smoke again and records the SBOM and SHA256SUMS; a separate publish job, the only one holding `contents`, `id-token` and `attestations: write`, checks out nothing, re-verifies the build job's checksums, attests SLSA-style build provenance (`actions/attest-build-provenance`, pinned by SHA) and publishes with the runner's `gh release create --verify-tag`, in one constant `release-publish` concurrency group so releases of different tags never publish at once. Manual dispatch and changes to publish-release.yml, its provenance helper or pyproject.toml run the build job alone as a dry run, so the release path is exercised before the first tag | `.github/workflows/publish-release.yml`, `make package` |
| Response | Private vulnerability reporting, SLAs, regression test with every fix, benchmark when the hot path changes | SECURITY.md, BENCHMARK-Vnnn.md |

## Definition of done for a change

1. Tests added for the new behaviour, including adversarial inputs.
2. `make check` passes locally.
3. PROTOCOLS.md / APPID.md / ARCHITECTURE.md updated; threat model touched if a boundary moved; schemas/ updated when an output field changes (OUTPUT.md).
4. SECURITY-REQUIREMENTS.md row added when the change introduces a new guarantee.
5. Benchmark recorded when a hot path changed, with a differential check against the previous tree when a parser was rewritten (tools/compare_client_hello.py is the model).
6. The direction coverage matrix in PROTOCOLS.md is regenerated (`tools/coverage_matrix.py --write PROTOCOLS.md`) when fixtures or evidence fields change; CI checks it.
7. The behaviour diff report of the CI job (`tools/compare_engine.py` against the parent commit of the pushed head, also on pull requests; uploaded as an artifact and shown in the job summary) lists only intended changes; an unexpected family in the report is a review finding.
8. README.md and REVIEW-SCOPE.md carry the current family, application, test and version numbers; `tools/check_docs_counts.py` (part of `make check` and CI) fails on drift.

## Enforced controls and recommended required checks

What is enforced today is what the workflows themselves do: every push and
pull request runs `ci`, `codeql` and (on workflow, checker or toolchain
changes) `supply-chain-drift`, a red check is visible on the commit and the
pull request, and the release workflow refuses to publish unless its own
gate, version check and checksum re-verification pass. Nothing currently
prevents a merge to `main` with a red or missing check: the repository has no
ruleset and no classic branch protection, and GitHub does not enforce either
on this private repository under its current plan (both settings forms warn
that enforcement needs an eligible Team or Enterprise organization plan; see
the diagnosis in issue #7, comment 6348347937). Until that changes, merging
only with green checks is a review discipline, not a guarantee.

| Control | Status |
|---|---|
| `ci`, `codeql`, `supply-chain-drift` and `release` workflow gates, job-level token permissions, SHA-pinned actions, hash-pinned toolchain | enforced by the workflows on every run |
| Release publishes serialized, publish only from a pushed `v*` tag that matches the package version | enforced by the guarded controller `publish-release.yml` for tags on commits that carry it |
| Release provenance: a `v*` tag publishes only a commit already on `main` | **not enforced yet.** `publish-release.yml` runs the check (`tools/check_release_ref.py`; rule 4 of `tools/check_workflow_policy.py` pins its exact env and run lines, the publish job's condition and its dependency path). But a tag push runs the workflow file at the tagged commit, and every older commit (for example `main` at 214042f, or 6e1cd61) still holds the unguarded `.github/workflows/release.yml`. A `v*` tag on such a commit publishes through it with no provenance check. The check becomes enforced, for tags on commits whose workflow passed the policy, once Lee disables the legacy `release` workflow (path `.github/workflows/release.yml`) in the Actions settings. Rule 5 keeps that path out of the tree, so disabling it never touches the controller. `python3 tools/check_release_exposure.py --ref <commit> [--disabled .github/workflows/release.yml]` models a tag on any commit without creating one |
| Release checks: a `v*` tag publishes only a commit whose `ci` and `codeql` workflows passed | enforced by `publish-release.yml` for tags on commits that carry it (`tools/check_release_checks.py`, with `actions: read` on the read-only build job). Results are bound to the workflow's identity, not to a job name another workflow could reuse: only `push` runs of `.github/workflows/ci.yml` and `.github/workflows/codeql.yml` for that exact commit count. A push run executes the commit's own copy of the file, and a `ci` run succeeds only when its `ci gate (all jobs)` does. At least one run of each must have completed, and the latest completed one must have succeeded. A run GitHub still shows as in progress neither passes nor blocks: a stale job state was observed on 6e1cd61 after its workflow run completed. A missing, only-pending, failed or cancelled run, or an unreadable API answer, fails the tag. Rule 4 pins the step. Same legacy caveat as provenance: not enforced for tags on older commits until the legacy `release` workflow is disabled. Tagging a commit whose ci or CodeQL is still running, or was cancelled by a newer push, fails the release; re-run it once a completed run exists |
| Attestation verified before publishing: every released file's provenance attestation must verify, bound to this controller workflow, the tag ref, the commit and a GitHub-hosted runner, before `gh release create` runs | enforced by `publish-release.yml` for tags on commits that carry it: `gh attestation verify` with `--signer-workflow`, `--source-ref`, `--source-digest` and `--deny-self-hosted-runners`. Rule 8 of the policy makes the publish job an allowlist: exactly its six steps, in order, each pinned by action identity or exact env and run lines, so no other step can publish before verification. It also enforces that only the publish job holds a write permission, that the workflow env sets no `BASH_ENV` or anything beyond the two Python variables, and that the controller references no `secrets`, `vars`, `inputs` or `client_payload` context in any syntax or case (`secrets['X']` and `toJSON(secrets)` included), so no credential but each job's own GITHUB_TOKEN can authenticate. The publish path only runs on a real tag, so a build-job dry-run step checks that the runner's `gh` supports every flag used. Same legacy caveat as provenance |
| Consistent action pins: one SHA and tag per action repository across every workflow; `upload-artifact` and `download-artifact` (the release handoff) on one major version | enforced by rule 7 of `tools/check_workflow_policy.py` (CI `workflow-lint`, `make check`, pre-commit). A partial bump fails before merge. Dependabot PR #8, computed before the release split, would have moved only the upload side to v7 |
| Workflow text means what GitHub reads: no YAML encoding that decodes into something the line-based policy rules did not see | enforced by rule 9 of `tools/check_workflow_policy.py`: outside literal block scalars, no backslash (so no `\u0073ecrets`-style escapes or escaped line breaks), and no tag, anchor, alias, merge key or explicit key. No flow mapping is allowed at all outside `${{ }}` expressions, and a flow sequence must be one line of plain or quoted scalars, so `push: {? tags: ["v*"]}` cannot hide a trigger from rule 5. No workflow may authenticate with a stored credential. On every line, comments included, the words `secrets` and `vars` may appear only as the exact `${{ secrets.GITHUB_TOKEN }}`, plus one job name. Comments are scanned because inside a `run: |` block a `#` line is script data, such as here-document input that Actions interpolates, not a YAML comment. This is a word ban rather than an expression parser, so no expression grammar can route around it: a quoted `}}` in a `format()` string, multi-line expressions, `secrets: inherit` and `if:` conditions are all covered. A read-only workflow therefore cannot publish with a PAT. Rule 5 also keeps release-relevant write scopes (`contents`, `id-token`, `attestations`, `packages`, `actions`, `deployments`, `statuses`, `write-all`) out of every workflow but the controller. The credential, trigger, pin and pinned-step rules therefore read the same text GitHub evaluates |
| Scheduled release audit: every `v*` tag points at a commit on `main`; every published release names an existing, on-`main` `v*` tag and that tag's current commit; and every downloaded file, hidden ones included, carries an attestation from `publish-release.yml` for that tag ref and commit | enforced after the fact, once merged to `main`, by `.github/workflows/release-audit.yml`. It runs daily and on manual dispatch. A scheduled run always uses the default branch's copy, so no tag, legacy `release.yml` or branch-edited workflow can swap it. It holds read-only permissions (`contents`, `attestations: read`); `tools/release_audit.py` decides, and fails closed on unreadable facts. A failing run is GitHub's notification to the owner. Rule 10 of the policy keeps the schedule and pins the gather-and-decide step. This is detective: it reports a bad release but cannot stop one being published |
| The policy reads what GitHub reads: the line parser in `tools/check_workflow_policy.py` and a real YAML parser agree on every fact the rules use | enforced by `tools/check_workflow_yaml.py` in CI `workflow-lint` and `make workflow-lint`, with the hash-pinned PyYAML. Rule 11 of the policy pins the CI step, including its own toolchain install, and forbids `if:` or `continue-on-error` on it or on its job, so the step cannot be dropped or masked while the gate stays green. `make check` does not run it because it needs the dev toolchain. Every workflow is parsed both ways. Any disagreement fails: top-level and job keys, job ids, `needs`, tag triggers, permissions, each step's keys, `name`, `if`, `uses`, `env`, `with` and `run` lines, or the `uses` list. The stored-credential ban is also re-run over every decoded key and string. Each review finding against the line rules was such a disagreement, so this closes the class rather than one spelling. Limit: PyYAML is YAML 1.1 and GitHub's parser is YAML 1.2; the one difference that matters here (`on` as a boolean) is normalized |
| No masked ci job: every job `ci gate (all jobs)` needs can actually fail | enforced by rule 13 of `tools/check_workflow_policy.py`. In `ci.yml`: no `continue-on-error`; no `\|\| true`, `\|\| :` or `set +e`; no job-level `if:` except the gate's exact `always()`; a step `if:` only on the three pull-request-only behaviour-diff base steps, pinned by job and every field; and the gate's decision step pinned |
| Failing checks fail their step (pipefail) | enforced: every workflow sets `defaults: run: shell: bash`, which is `bash -eo pipefail`. The unspecified default is `bash -e`, under which `check \| tee` passed when the check failed. Rule 6 of the policy forbids dropping or overriding it |
| Required status checks on `main` (the two names below) | recommended; not enforceable on the current plan |
| Required pull request review, stale-approval dismissal, no force push or deletion on `main` | recommended; not enforceable on the current plan |
| Tag protection for `v*`, a `release` environment with a required reviewer | recommended; not configured. The provenance check above compensates in part once the legacy workflow is disabled: an unreviewed branch commit cannot be released. A writer who can push to `main` directly, or who pushes a branch with a modified workflow and tags it, still can, since nothing enforces review |

### Recommended required checks

When rulesets or branch protection become available, protection matches
status checks by job name (the `name:` of each job, not the workflow name).
Two names are enough: the `ci` workflow ends in an
aggregate job, `ci gate (all jobs)`, that depends on every other ci job with
`if: always()` and fails when any of them failed, was cancelled or was
skipped. `toJSON(needs)` only sees direct dependencies, so
`tools/check_workflow_policy.py` (CI `workflow-lint`, `make check`,
pre-commit) fails when a ci job is missing from the gate's `needs` or a listed
job no longer exists, and fails closed on any entry of the `jobs:` mapping it
cannot read as a block-style job key (plain or quoted): a job added later
cannot pass unseen, whatever its spelling, and no settings change is needed. CodeQL runs in its own workflow and is required separately.

| Workflow | Recommended required check name | Gate |
|---|---|---|
| ci | `ci gate (all jobs)` | every ci job below succeeded |
| codeql | `CodeQL (python, security-extended)` | security-extended and security-and-quality suites, error level fails |
| codeql | `CodeQL (actions, security-extended)` | the workflows themselves, analysed by CodeQL's `actions` pack with the same suites; error level fails. Rule 12 of the policy keeps both CodeQL jobs, their pinned init, analyze and gate steps, and the push trigger the release checks gate relies on |

The jobs the gate covers, every one of which runs on every push and pull
request:

| Workflow | Job name | Gate |
|---|---|---|
| ci | `tests (python 3.9)`, `tests (python 3.11)`, `tests (python 3.13)` | compile, unit/fuzz/property tests, docs numbers, offline replay, coverage matrix |
| ci | `behaviour diff against the previous commit` | `tools/compare_engine.py` against the parent (and the pull request base) |
| ci | `per-commit mutation smoke (second seed, python 3.9)` | second-seed mutation diff and a 100-mutation fuzz pass |
| ci | `static analysis (ruff, bandit, secrets)` | ruff, bandit, gitleaks over the full history |
| ci | `supply chain (SBOM, licence, pins)` | action pins, CycloneDX SBOM, zero-runtime-dependency contract |
| ci | `package build (sdist, wheel, clean install)` | build, `tools/check_wheel.py`, wheel smoke under 3.13 and 3.9 |
| ci | `workflow lint (actionlint, zizmor)` | actionlint with shellcheck, then the zizmor security audit (pedantic persona, offline audits, any finding fails) over every workflow |
| ci | `known vulnerabilities in the dev toolchain (pip-audit)` | pip-audit in hash mode, strict |
| ci | `security requirements gate` | every SR row names an existing test |

Do not mark the `supply-chain-drift` jobs required: that workflow is path
filtered and scheduled, so it does not run on most pull requests and a
required check that never reports blocks the merge. Its failures are
review items (a moved tag, a vanished release, a changed index artifact)
to be handled on the next working day, never by re-pinning blindly.

Scheduled workflows (the weekly `ci` and `codeql` re-runs, the nightly fuzz,
`supply-chain-drift`) and Dependabot read their configuration from the
default branch only, so a schedule or `dependabot.yml` change takes effect
once it is merged to `main`. On a feature branch, `workflow_dispatch` and
the push/pull-request paths of `supply-chain-drift` are the only way to
exercise them.

## Recommended repository settings

The workflows enforce what a token can do; the following settings, which only
the repository owner can change, would complete the gate. None of them is in
force today (see "Enforced controls" above); the first is not available on
the current plan:

- Branch protection or a ruleset on `main`: require the checks listed above, require a
  pull request with one approving review (CODEOWNERS), dismiss stale
  approvals on new commits, forbid force pushes and deletions.
- Code security: enable Dependabot alerts and security updates, secret
  scanning with push protection, and code scanning so the CodeQL SARIF upload
  reaches the Security tab (the workflow keeps the SARIF as an artifact until
  then).
- Actions: allow only actions from GitHub and verified creators pinned by SHA
  (the repository already pins every reference), keep the default workflow
  token read-only, and require approval for workflows from outside
  collaborators.
- Releases: disable the legacy `release` workflow (Actions, the workflow
  named `release` at `.github/workflows/release.yml`, "Disable workflow").
  This is required for release provenance: until it is disabled, a `v*` tag
  on any older commit publishes through that commit's unguarded copy. Then
  confirm the workflow shows as disabled, and that
  `tools/check_release_exposure.py --ref <older commit> --disabled
  .github/workflows/release.yml` reports no unguarded path. Tags `v*` trigger
  `publish-release.yml`, which refuses a tag that does not match the package
  version or whose commit is not on `main`. Protect the tag pattern so only
  the owner can create it, and consider a `release` environment with a required
  reviewer on the publish job so a pushed tag still waits for a person before
  anything is attested or published.

## Pull request events

CI runs on every push and on pull requests. On a pull request the checkout is
GitHub's synthetic merge commit, so two jobs behave differently from a push:
the behaviour diff checks out the pull request head and compares it with its
own parent, then also with the pull request base when that base carries the
engine (the whole change as one report), and the secret scan needs
`pull-requests: read` to list the pull request's commits. Both are configured
in ci.yml; a red pull-request run with a green push run on the same commit is a
workflow defect, never an engine finding.

## CI/CD review loop (Codex, issue #7)

The CI/CD track has its own review mailbox, separate from the engine's
issue #2, and follows the same gated loop:

1. Before a request, merge-forward the current `claude/appid-engine` head
   into `claude/cicd` (merge commit, never rebase or force-push), run the
   gates, push, and freeze that head. An engine commit that lands while the
   review runs does not invalidate the frozen request.
2. Post the `CODEX_REVIEW_REQUEST` in issue #7: task, round (at most three
   per task), exact head and base SHAs, engine baseline SHA, files in
   scope, tests and results, and the current CI/CD pull request.
3. Post exactly one short `CODEX_REVIEW_REQUEST` notification on PR #3 that
   links the issue #7 request, repeats head, base and round, and says
   `lane=CI/CD`. PR #3 comments wake the reviewer for both lanes; issue #7
   stays authoritative for CI/CD. AGENTS.md makes PR #3 a shared wake
   channel: one short, lane-prefixed notification per canonical issue #7
   request, nothing else. Review content never goes on PR #3, and issue #2
   stays engine-only (the CI/CD session never writes there).
4. Subscribe to the current CI/CD pull request, where the reviewer mirrors
   its `CODEX_REVIEW_RESULT`. Pause CI/CD feature edits until a result names
   the exact frozen head; synchronization a repair round explicitly needs
   does not wait for it. A missing, blocked, failed or SHA-mismatched result
   is not approval, and a merge is not approval either: findings stay open
   until a later round verifies the repair.
5. A result with zero actionable findings passes the gate; otherwise repair
   with a regression check and request the next round. While a request is
   pending, at most one server-side fallback check-in every 30 minutes,
   quiet when nothing changed.
6. Continuation (Lee, 2026-10-22, confirmed in the CI/CD session; issue #7
   comment 6348691524):
   - No matching review within 60 minutes of the request's posting: work on
     the next CI/CD milestone may continue. The clock is not reset by polling
     or status-only messages. The open request and its frozen snapshot stay
     pending, and late findings are still evaluated and repaired.
   - An approving result (zero actionable findings in that task's scope)
     allows continuing at once. If no useful work has resumed 30 minutes
     after it, start the next milestone from the backlog below without
     waiting for another acknowledgement. A pass in one scope never resolves
     findings in another.
   - One cloud reminder at most, set for the nearest applicable deadline
     (60-minute missing review or 30-minute idle after approval), cancelled
     or re-armed when a result or progress makes it obsolete. No duplicate
     periodic pollers; an explicit stop or pause from Lee, or a concrete
     access or usage blocker, is reported once and respected.
   - The next milestone is the next bounded CI/CD item within this lane,
     never engine features. A snapshot that passed review is preserved: new
     milestones go on a branch cut from it (`claude/cicd-next`), so the
     pull request carrying the approved head does not change under review.

The loop never merges, deploys, deletes branches, or changes branch
protection, permissions or credentials.

## CI/CD backlog

Prioritized from concrete gaps; one bounded milestone at a time, each through
the review loop above.

1. Release tag provenance (compensating control; in review on
   `claude/cicd-next`; enforced only after the legacy `release` workflow is
   disabled, a Lee action). Tag protection and
   required checks are not enforceable on the current plan, so any `v*` tag
   pushed by a writer, on any commit, reaches the publish job. The release
   build job should refuse a tag whose commit is not already on `main`
   (GitHub compare API with the read-only token), with a tested decision
   helper and a workflow-policy rule that keeps the step on the publish
   job's dependency path.
2. Green-checks-on-tag (in review on `claude/cicd-next`). Before publishing, require that `ci gate (all jobs)`
   and CodeQL succeeded on the tagged commit (read-only `checks: read`), so
   a release cannot ship a commit whose CodeQL never passed (the release
   build re-runs the test gate but not CodeQL).
3. Artifact action pairing (in review on `claude/cicd-next`). `upload-artifact` and `download-artifact` hand
   the release files between jobs; Dependabot can move them to different
   majors (open PR #8 moves upload to v7 and leaves download at v4). A
   policy rule should require matching majors, or the pair should be
   updated together.
4. Post-publish verification (in review on `claude/cicd-next`; verification runs after
   attesting and before publishing, so a failed verification publishes nothing). After `attest-build-provenance`, verify the
   attestation of every published file with `gh attestation verify` in the
   publish job, so a failed or partial attestation fails the release.
5. Workflow encoding fail-closed (in review on `claude/cicd-next`). This carries
   over the milestone-4 round-3 finding, which arrived after that task's three
   rounds: a double-quoted YAML escape (`"${{ \u0073ecrets.X }}"`) hid a
   credential context from the line-based rule 8. Rule 9 bans every YAML
   encoding that decodes into different text.
6. Stored-credential word ban (in review on `claude/cicd-next`). This carries
   over the task-5 round-3 finding, which arrived after task 5's three rounds:
   the expression scan ended at a `}}` inside a quoted `format('{{x}}')` string,
   so a later `secrets.RELEASE_PAT` went unseen. The ban now works on words, not
   expression syntax.
7. Scheduled release audit (passed review in round 2).
8. Parser cross-check (passed review in round 2). Every review finding
   against the line-based policy (escapes, flow collections, explicit keys,
   comments inside run blocks) was a spelling a real YAML parser decodes
   differently. `tools/check_workflow_yaml.py` compares both parsers on every
   fact the rules use and fails on any disagreement.
9. CodeQL for the workflows (passed review in round 2). CodeQL's
   `actions` pack analyses the workflow files with the same suites as the
   Python analysis: an independent reading beside zizmor and the policy. Its
   results pass the same error-level gate, and since the release checks gate
   requires the whole `codeql` workflow, they bind releases too.
10. No masked ci job (in review on `claude/cicd-next`). The aggregate gate only
   means something if each job it needs can fail. Rule 13 forbids every way
   to make a job or step pass regardless of its outcome. A scheduled workflow always runs main's copy, so a
   tag on an older commit cannot bypass it. It would list every published
   release and check that its tag commit is on `main` and that its files'
   attestations verify.

## Caching and concurrency policy

- The only cache is the pip download cache of `actions/setup-python`, keyed
  on `requirements-dev.txt` (`cache-dependency-path`), in the jobs that
  install the toolchain. It spares the download; `--require-hashes` still
  verifies every file at install time, so a poisoned cache entry fails the
  install rather than running. Nothing built from the tree is cached, and
  the `verify` matrix, the behaviour diff and the mutation smoke install
  nothing at all.
- `ci`, `codeql` and `supply-chain-drift` each run in a concurrency group per
  ref with `cancel-in-progress`, so a newer push cancels the superseded run
  of the same branch.
- `release` and `nightly-fuzz` have a group per ref without cancellation: a
  run in flight is never cut short by another run of the same ref. Runs of
  different refs (two tags, two branches) do not share that group, so the
  release `publish` job also sits in one constant group, `release-publish`,
  without cancellation: publishes of different tags never overlap.
  `tools/check_workflow_policy.py` resolves the governing group for two
  different tags and fails unless they are equal and non-cancelling, and
  checks that branch dry runs keep a per-ref group.
- GitHub keeps at most one pending run per group: a newer pending run
  replaces an older pending one. So "never overlap" is guaranteed, but a
  burst of three tags can leave the middle tag's publish cancelled before it
  started (nothing attested or published); re-run that tag's release run by
  hand. The same holds for a second manual fuzz run.
- Every workflow sets `permissions: contents: read` at the top; a job adds a
  permission only for the step that needs it (`pull-requests: read` for the
  secret scan on pull requests, `security-events: write` for the SARIF
  upload, `contents/id-token/attestations: write` on the release publish job
  only, which runs solely for a pushed `v*` tag and never checks out code).

## Local commands

```bash
make check          # compile, tests, ruff, action pins, security-requirement gate, example policy lint, coverage matrix, docs numbers
pip-audit -r requirements-dev.txt --require-hashes --strict   # toolchain advisories (dev tools installed)
make ci-local       # make check plus extended fuzzing and the offline replay/schema validation CI runs
make package        # sdist and wheel plus the wheel-content gate (dev tools installed)
make workflow-lint  # actionlint (needs a local actionlint and shellcheck, which the hosted runner has; CI fetches a checksum-verified release) then zizmor from the dev toolchain
make pin-drift      # pinned action SHAs still match the tags in their comments (network; the weekly supply-chain-drift workflow runs the same check)
make fuzz           # extended seeded fuzzing
python3 -B tools/compare_engine.py ../previous-checkout --report diff.md   # behaviour diff against another tree
make sbom           # CycloneDX SBOM of the environment (requires dev tools)
```
