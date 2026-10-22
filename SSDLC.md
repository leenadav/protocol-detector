# Secure software development lifecycle

The project follows a lightweight SSDLC in which every phase leaves an
artifact in the repository and every security claim has an executable check.

| Phase | Practice | Artifact / gate |
|---|---|---|
| Requirements | Security requirements written as testable statements (SR-n) | SECURITY-REQUIREMENTS.md; CI job `security-requirements` fails when a row has no existing test |
| Design | Threat model per trust boundary, STRIDE table, explicit contracts for budgets and evidence | THREAT-MODEL.md, ARCHITECTURE.md, PROTOCOLS.md profile per family |
| Implementation | Bounded parsing patterns (length before allocation, one parser per stream, immutable registries), no runtime dependencies, Python 3.9 syntax | CONTRIBUTING.md definition of done, code review via PR template checklist, issue templates that ask for synthetic inputs only; CODEOWNERS |
| Verification | Unit tests (every split point, single bytes, truncations), seeded mutation fuzzing, GC-release tests, work-bound assertions, static analysis, documentation numbers recomputed from the tree | `make check`, CI `verify` matrix (3.9/3.11/3.13) with job summaries, CI `behaviour-diff` (run-id seed) and CI `mutation-smoke` (a second, fixed seed under Python 3.9 plus a 100-mutation fuzz pass seeded by the run number, both with the reproducing command in the job summary), ruff, bandit, CodeQL with the `security-extended` and `security-and-quality` suites (error-level findings fail via `tools/codeql_gate.py`, which also writes a per-rule table to the job summary; SARIF kept as an artifact, uploaded to the Security tab once code scanning is enabled in repository settings), `tools/check_docs_counts.py` (README/REVIEW-SCOPE families, applications, tests and version), nightly fuzz |
| Supply chain | SHA-pinned actions whose tag comments are re-verified weekly, hash-pinned dev tools (wheel and source hashes where a wheel is platform specific), known-vulnerability audit of the toolchain, SBOM, read-only tokens with per-job additions only where a step needs them, Dependabot, workflow linting | CI `supply-chain`, CI `toolchain-audit` (pip-audit over requirements-dev.txt in hash mode, strict, also on the weekly schedule so new advisories surface without a code change), dependabot.yml, `tools/check_action_pins.py`, CI `workflow-lint` (actionlint fetched by version with its published SHA-256 verified before use, then zizmor from the hash-pinned toolchain auditing every workflow for template injection, credential persistence, cache poisoning, undocumented or excessive permissions, unpinned or superfluous actions and missing concurrency limits; pedantic persona, any finding fails), harden-runner egress audit on every job of every workflow, the release published with the runner's own `gh` CLI rather than a third-party action, `.github/workflows/supply-chain-drift.yml` (weekly and whenever ci.yml, requirements-dev.txt or the checker change: `tools/check_pin_drift.py` resolves each pinned SHA's tag comment against the action repository and fails when the tag moved or vanished; the actionlint release and SHA-256 named in ci.yml are downloaded and re-verified; every dev dependency is downloaded with `--require-hashes` and pip-audit is installed from those verified files alone) |
| Release | Every push builds the sdist and wheel, checks the wheel holds exactly the engine package with no runtime dependency (`tools/check_wheel.py`) and installs it into an empty environment under Python 3.13 and again under Python 3.9, where `tools/wheel_smoke.py` classifies an HTTP request and a DNS query from the installed package and refuses an import from the checkout (CI `package`); on a `v*` tag the release workflow's read-only build job passes the full gate (compile, tests, ruff, pins, security requirements, docs numbers, coverage matrix, policy lint), checks that the reported version equals pyproject.toml and the tag, builds, runs the wheel gate and smoke again and records the SBOM and SHA256SUMS; a separate publish job, the only one holding `contents`, `id-token` and `attestations: write`, checks out nothing, re-verifies the build job's checksums, attests SLSA-style build provenance (`actions/attest-build-provenance`, pinned by SHA) and publishes with the runner's `gh release create --verify-tag`. Manual dispatch and changes to release.yml or pyproject.toml run the build job alone as a dry run, so the release path is exercised before the first tag | `.github/workflows/release.yml`, `make package` |
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

## Required checks on `main`

Branch protection matches status checks by job name (the `name:` of each job,
not the workflow name). Two names are enough: the `ci` workflow ends in an
aggregate job, `ci gate (all jobs)`, that depends on every other ci job with
`if: always()` and fails when any of them failed, was cancelled or was
skipped, so a job added later is covered without a settings change; CodeQL
runs in its own workflow and is required separately.

| Workflow | Required check name | Gate |
|---|---|---|
| ci | `ci gate (all jobs)` | every ci job below succeeded |
| codeql | `CodeQL (python, security-extended)` | security-extended and security-and-quality suites, error level fails |

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
the repository owner can change, complete the gate:

- Branch protection on `main`: require the checks listed above, require a
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
- Releases: tags `v*` trigger the release workflow, which refuses a tag that
  does not match the package version; protect the tag pattern so only the
  owner can create it, and consider a `release` environment with a required
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
  of the same branch. `release` and `nightly-fuzz` have a group per ref
  without cancellation: a release or fuzz run in flight is never cut short,
  a second one queues behind it.
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
