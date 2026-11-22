# Chunk 07 (Tier 1, small): govulncheck over the Go engine module (18 lines)

**Diff:** `git show 85e99e9 -- .github/workflows/ci.yml` (the lock and SSDLC lines are Tier 3).
**Commit:** 85e99e9, on `claude/cicd-next`; not yet in a PR.

**What changed, and why**
- `toolchain-audit` gains a step (`ci.yml` L588–605): the pinned govulncheck, already built in that job from
  `tools/scanners`, runs in source mode over `go/`.
- This ports the engine lane's `34ea6b0` (`claude/go-migration`, their chunk-43), so `ci.yml` has one writer.
- The step changes the engine's version from `GOFLAGS=-mod=readonly` with the module proxy to
  `GOFLAGS=-mod=vendor` with `GOPROXY=off`. It analyses exactly the committed vendor tree, and the only network
  it uses is govulncheck's vulnerability database (`vuln.go.dev`).

**Risks to check**
1. **Scanners first:** the step runs after the pinned scanner steps. Is it outside the scanner-first prefix that
   rule 15 pins? It runs no repository code: only `$RUNNER_TEMP/bin/govulncheck` with a fixed environment.
2. **No dependencies:** `-mod=vendor` on a module with no dependency and no vendor directory (`main` today) loads
   the module alone, and on an unvendored dependency it fails. Is failing the job there the wanted outcome? It
   matches `go_ci.py`'s vendor rule.
3. **Vulnerability database:** is relying on the database's default host acceptable, or should `GOVULNDB` be
   written out like `GOPROXY`?

**Already run (no need to redo)**
- Locally, with the pinned govulncheck: `main`'s `go/` reports no vulnerability. The engine head's vendored
  `go/` also reports none, scanning golang.org/x/crypto v0.59.0 from `go/vendor` with an empty module cache.
  The same scan with `-mod=readonly` and `GOPROXY=off` cannot load the module.
- Workflow policy, actionlint, zizmor pedantic, the YAML cross-check and `make check` pass.

**Out of scope:** the scanner build and the binary-mode scans before it (unchanged, pinned by rule 15).
