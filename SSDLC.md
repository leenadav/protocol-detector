# Secure software development lifecycle

The project follows a lightweight SSDLC in which every phase leaves an
artifact in the repository and every security claim has an executable check.

| Phase | Practice | Artifact / gate |
|---|---|---|
| Requirements | Security requirements written as testable statements (SR-n) | SECURITY-REQUIREMENTS.md; CI job `security-requirements` fails when a row has no existing test |
| Design | Threat model per trust boundary, STRIDE table, explicit contracts for budgets and evidence | THREAT-MODEL.md, ARCHITECTURE.md, PROTOCOLS.md profile per family |
| Implementation | Bounded parsing patterns (length before allocation, one parser per stream, immutable registries), no runtime dependencies, Python 3.9 syntax | Code review via PR template checklist; CODEOWNERS |
| Verification | Unit tests (every split point, single bytes, truncations), seeded mutation fuzzing, GC-release tests, work-bound assertions, static analysis, documentation numbers recomputed from the tree | `make check`, CI `verify` matrix (3.9/3.11/3.13) with job summaries, ruff, bandit, CodeQL (error-level findings fail via `tools/codeql_gate.py`; SARIF kept as an artifact, uploaded to the Security tab once code scanning is enabled in repository settings), `tools/check_docs_counts.py` (README/REVIEW-SCOPE families, applications, tests and version), nightly fuzz |
| Supply chain | SHA-pinned actions, hash-pinned dev tools, SBOM, read-only tokens with per-job additions only where a step needs them, Dependabot, workflow linting | CI `supply-chain`, dependabot.yml, `tools/check_action_pins.py`, CI `workflow-lint` (actionlint fetched by version with its published SHA-256 verified before use), harden-runner egress audit on every job |
| Release | The full gate on the tagged commit (compile, tests, ruff, pins, security requirements, docs numbers, coverage matrix, policy lint), tag must equal the package version, sdist/wheel, SBOM, build provenance attestation, checksums | `.github/workflows/release.yml` |
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

## Pull request events

CI runs on every push and on pull requests. On a pull request the checkout is
GitHub's synthetic merge commit, so two jobs behave differently from a push:
the behaviour diff checks out the pull request head and compares it with its
own parent (the base branch may predate the engine), and the secret scan needs
`pull-requests: read` to list the pull request's commits. Both are configured
in ci.yml; a red pull-request run with a green push run on the same commit is a
workflow defect, never an engine finding.

## Local commands

```bash
make check          # compile, tests, ruff, action pins, security-requirement gate, example policy lint, coverage matrix, docs numbers
make ci-local       # make check plus extended fuzzing and the offline replay/schema validation CI runs
make workflow-lint  # actionlint over .github/workflows (needs a local actionlint; CI fetches a checksum-verified release)
make fuzz           # extended seeded fuzzing
python3 -B tools/compare_engine.py ../previous-checkout --report diff.md   # behaviour diff against another tree
make sbom           # CycloneDX SBOM of the environment (requires dev tools)
```
