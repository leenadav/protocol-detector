# Contributing

The project is a bounded, dependency-free passive protocol classifier. Every
change is held to the contracts in AGENTS.md, PROTOCOLS.md, APPID.md and
ARCHITECTURE.md; SSDLC.md describes the gates that enforce them.

## Before you start

- Read PROTOCOLS.md for the family you touch: a positive classification must
  satisfy its documented structural profile, hints select candidates but never
  establish identity, and nothing from a payload (credentials, cookies, keys,
  paths, identifiers, log content) may reach evidence or reasons.
- Python 3.9 syntax, no runtime dependencies, every parser bounded by the
  byte/count/depth budgets in `Config`.
- Never commit captured traffic. Fixtures are synthetic, built in
  `protocol_fixtures.py` from specification examples with placeholder names.

## Definition of done

1. Tests for the new behaviour: every feed split, truncations, malformed and
   adversarial inputs, seeded mutations, and both message directions where the
   profile covers them. New fixtures join `STREAM_CASES` / `DATAGRAM_CASES`
   (or the hinted lists) so the generic contracts apply.
2. `make check` passes: compile, tests, ruff, action pins, security
   requirements, policy lint, coverage matrix, documentation numbers.
3. Documentation updated in the same change: PROTOCOLS.md (profile, limits,
   evidence vocabulary), APPID.md and RISKS.md when the catalog or risks move,
   ARCHITECTURE.md when a mechanism changes, OUTPUT.md and `schemas/` when an
   output field changes, README.md and REVIEW-SCOPE.md counts (the
   documentation-number gate fails on drift).
4. SECURITY-REQUIREMENTS.md row for every new guarantee, pointing at the tests
   that prove it; THREAT-MODEL.md when a trust boundary moves.
5. `tools/coverage_matrix.py --write PROTOCOLS.md` after fixtures or evidence
   fields change.
6. A benchmark record (BENCHMARK-Vnnn.md) when a hot path changes, measured
   with `benchmark_ab.py --baseline <previous tree>`.
7. The behaviour diff against the parent commit (`tools/compare_engine.py`,
   shown in the CI job summary) lists only the families you meant to change.

## Local commands

```bash
make check          # the full gate, same as CI
make ci-local       # make check plus extended fuzzing and the offline replay/schema validation
make fuzz           # extended seeded fuzzing
make workflow-lint  # actionlint over the workflows; install shellcheck too, the runner has it
pip-audit -r requirements-dev.txt --require-hashes --strict   # toolchain advisories
```

## Pull requests

One concern per pull request, with the fixture bytes and the specification
section the profile follows named in the description. CI runs the same gates
on pull requests as on pushes, plus a behaviour diff against the pull request
base. Reviews focus on size arithmetic against containers, dispatch
discriminators against existing families, and anything that could leak a
value from the payload into evidence. Security issues go through SECURITY.md,
not public issues.
