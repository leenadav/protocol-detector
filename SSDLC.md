# Secure software development lifecycle

The project follows a lightweight SSDLC in which every phase leaves an
artifact in the repository and every security claim has an executable check.

| Phase | Practice | Artifact / gate |
|---|---|---|
| Requirements | Security requirements written as testable statements (SR-n) | SECURITY-REQUIREMENTS.md; CI job `security-requirements` fails when a row has no existing test |
| Design | Threat model per trust boundary, STRIDE table, explicit contracts for budgets and evidence | THREAT-MODEL.md, ARCHITECTURE.md, PROTOCOLS.md profile per family |
| Implementation | Bounded parsing patterns (length before allocation, one parser per stream, immutable registries), no runtime dependencies, Python 3.9 syntax | Code review via PR template checklist; CODEOWNERS |
| Verification | Unit tests (every split point, single bytes, truncations), seeded mutation fuzzing, GC-release tests, work-bound assertions, static analysis | `make check`, CI `verify` matrix (3.9/3.11/3.13), ruff, bandit, CodeQL (error-level findings fail via `tools/codeql_gate.py`; SARIF kept as an artifact, uploaded to the Security tab once code scanning is enabled in repository settings), nightly fuzz |
| Supply chain | SHA-pinned actions, hash-pinned dev tools, SBOM, read-only tokens, Dependabot | CI `supply-chain`, dependabot.yml, `tools/check_action_pins.py` |
| Release | Tests on the tagged commit, sdist/wheel, SBOM, build provenance attestation, checksums | `.github/workflows/release.yml` |
| Response | Private vulnerability reporting, SLAs, regression test with every fix, benchmark when the hot path changes | SECURITY.md, BENCHMARK-Vnnn.md |

## Definition of done for a change

1. Tests added for the new behaviour, including adversarial inputs.
2. `make check` passes locally.
3. PROTOCOLS.md / APPID.md / ARCHITECTURE.md updated; threat model touched if a boundary moved; schemas/ updated when an output field changes (OUTPUT.md).
4. SECURITY-REQUIREMENTS.md row added when the change introduces a new guarantee.
5. Benchmark recorded when a hot path changed, with a differential check against the previous tree when a parser was rewritten (tools/compare_client_hello.py is the model).

## Local commands

```bash
make check          # compile, tests, ruff, action pins, security-requirement gate, example policy lint
make fuzz           # extended seeded fuzzing
make sbom           # CycloneDX SBOM of the environment (requires dev tools)
```
