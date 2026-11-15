# Release gate (stage 8)

`make release-gate` runs, in order, everything a tagged commit must pass on a developer machine. The same
steps run in canonical CI where the runner can (GitHub Actions does not start jobs on this repository while
the account's spending limit stands; nothing below is claimed as passed in Actions). Each step prints an
`ok`/`FAILED` line; the target stops at the first failure.

| step | target | what it proves |
|---|---|---|
| 1 | `check` | ruff (correctness + security rules), engine unit/fuzz/property tests, requirement pins, policy lint, coverage matrix, documentation counts, build manifest, presentation suite when the extra is present, protocol inventory, no tracked key logs |
| 2 | `presentation-test` | the application suite against the checkout: HTTP contract, live bridge, jobs/control plane, decryption (offline, live, incremental engine), layered rows, security canaries, store unit tests and the real-browser tests when Playwright is available |
| 3 | `fuzz-smoke` | seeded mutation fuzz over every fixture through both inspection APIs |
| 4 | `corpus` | labelled-corpus report with zero intact false negatives (docs/CORPUS-REPORT-V065.md) |
| 5 | `soak` | synthetic overload, sparse gaps, late keys, slow consumer and worker-crash run within budgets (docs/SOAK-V065.json) |
| 6 | `dist` | sdist and wheel; the wheel holds exactly the engine and adapter packages and declares only the `decryption` extra |
| 7 | `installed-check` | the wheel installed with the hash-pinned extra into an empty environment, the engine imported from site-packages, the presentation suite run from a copy with no checkout beside it |

Also required before a tag, outside `make`: the behaviour diff against the previous release
(`tools/compare_engine.py <baseline checkout>`: no unexplained differences), the security requirements
check (`tools/check_security_requirements.py`, every SR row names an existing test), a local gitleaks run
with `.gitleaks.toml` (the `nss-key-log` rule included), and the Python 3.9 interpreter on the engine and the
new test modules. Release provenance (SBOM, attestation) is produced by the release workflow owned by the
CI/CD lane; the SBOM must include the decryption extra's lock (`presentation/requirements-decryption.lock.txt`).

Recorded run for the stage-8 commit (cloud container, Python 3.13.16 and 3.9.25, Node 22 + Playwright):
`make check` ok, presentation suite 59 tests ok (browser tests included), fuzz ok, corpus TP 1593 / FN 0,
soak within budgets (see docs/SOAK-V065.json), wheel 83 modules, installed check ok.
