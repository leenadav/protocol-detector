# Chunk 06 (Tier 1, small): action pin bumps not yet reviewed (56 lines)

**Diff:** `git show b97adc8`. This is Dependabot PR #26, merged as `4429fe1` on 2026-11-15.
It is the only lane-file commit before `e927d44` that no `CODEX_REVIEW_RESULT` head on issue #7 covers;
see INDEX.md, "Coverage of earlier history".

**What changed:** patch bumps across six workflows. Every `uses:` keeps a full SHA and a tag comment, and only the SHA and comment changed:
- `github/codeql-action` `init`, `analyze` and `upload-sarif`: v4.39.2 `1fc58d0…` → v4.39.3 `33d7b85…`
- `step-security/harden-runner`: v2.22.3 `46b06ce…` → v2.22.4 `1d88384…`

**Risks to check**
1. **Pins:** does each new SHA resolve to the tag its comment names? The weekly `supply-chain-drift` `action-pin-drift` job checks this live; its runs since 2026-11-15 are green.
2. **Changelogs:** does either release change inputs, permissions or default behaviour that our pinned CodeQL gate (policy rule 12) or `egress-policy: audit` relies on? Read the two upstream release notes; the source is not needed.
3. **Consistency:** is the same SHA used in every workflow? Policy rule 7 fails otherwise, and it passes on `ddc557d`.

**Already run (no need to redo):** CI and CodeQL on PR #26's head (47 check runs) and on every `main` commit since, including `ddc557d` (`ci` 44561555271, `codeql` 44561555222); `supply-chain-drift` pin drift 44561555182.

**Out of scope:** the workflows' own logic, which is unchanged by this commit.
