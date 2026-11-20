# Chunk 01 (Tier 1): workflow triggers, permissions, tokens, pins (438 lines)

**Diff:** `git diff e927d44 ddc557d -- .github/workflows/` (six files; the lock is Tier 3).
**Commits:** c58fe65, 3e1f7f2, eb18353, 91113bc, d7c482c, b57b819.

**What changed, and why**
- **`ci.yml`:**
  - New `go-minimum` job (L631–671): setup-go installs `go/go.mod`'s `go` release, read by `go_ci.py minimum-version` (digits and dots only).
  - New `go-vendor` job (L672–707): the only Go step with module access, for `make go-vendor-check`.
  - New `content-pack` job (L708–745).
  - setup-go plus an offline `go_ci.py build` in `verify` (L55–65) and `presentation-ui` (L150–160).
  - The decryption-extra install in `go-engine` (L617).
  - `GOPROXY: "off"` in every Go job except `go-vendor`.
  - All new jobs added to the gate's `needs` (L772).
- **New `merge-readiness.yml`:** daily trial merge, report only.
- **New `perf-history.yml`:** artifact-stored history.
- **`nightly-fuzz.yml`:** new `go-fuzz` job (L73–114) and a failure-only log upload.
- **`publish-release.yml`:** the read-only `build` job gains setup-go, the Go binaries step (L175) and the dry-run provenance step and upload (L218–232). The `release-gate` and `publish` jobs are unchanged.
- **`supply-chain-drift.yml`:** two path filters added.

**Risks to check**
1. **Write permissions:** does any new job or workflow gain a write permission, `id-token`, or `secrets`/`vars`? Expected: only `contents: read`, plus `actions: read` in `perf-history.yml` L27.
2. **`perf-history` (L73–80):** `gh run download` runs with `${{ github.token }}`. Can a run on one branch read an artifact written from a less trusted ref? It filters `--branch "$BRANCH" --status success` on this workflow only. A pull_request from a fork cannot trigger it, because there is no `pull_request` trigger.
3. **`go-minimum`:** `go-version: ${{ steps.minimum.outputs.version }}` takes its value from repository content. Is it constrained enough? The digits-and-dots check is in chunk 03 (`minimum_version`).
4. **Action pins:** are the new `uses:` all the same SHAs already pinned elsewhere (rule 7)? No new third-party action is introduced.
5. **`publish-release` (L218–232):** can the dry-run artifact or the new Go files reach the publish job by a path other than `dist/`? They should go through `SHA256SUMS`, attest and verify.
6. **Leftover triggers:** the `push` triggers on `claude/cicd-next` (`merge-readiness.yml` L14–19) and `claude/cicd-release-prep` (`perf-history.yml` L13–19) were registration aids. Are they harmless now? Both workflows are read-only.
7. **Template injection:** is any `${{ github.event.inputs.* }}` interpolated into `run:`? Expected: only through `env:` (nightly L97, perf L88).

**Already run (no need to redo)**
- **Policy and lint:** workflow policy rules 1–16 pass with 8 files; actionlint, zizmor pedantic and the PyYAML cross-check pass. CodeQL `actions` analysis passed on `ddc557d` (44561555222).
- **Dispatches:**
  - nightly-fuzz 44381003776 (main tree, 9 Go targets) and 44381167748 (vendored go-migration probe, 17 targets).
  - merge-readiness 44555659227.
  - perf-history 44558066232, followed by push 44559135921, which used that run as its baseline.
  - publish-release dry run 44559157154: publish skipped; artifacts `release-dist-…` and `release-dry-run-…`.
- **Engine probe:** `claude/cicd-engine-probe` (407bfcc), full ci run 44388423818 green, including `go-vendor` and `go-build`.
- **State:** no tag and no release exist in the repository.

**Out of scope:** the pinned `release-gate` and `publish` jobs (unchanged; rules 4 and 8 pin them); scanner jobs (unchanged).
