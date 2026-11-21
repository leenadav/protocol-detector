# Chunk 03 (Tier 1): Go toolchain, minimum, vendoring, network (451 lines)

**Diff:** `git diff e927d44 ddc557d -- tools/go_ci.py tools/check_go_drift.py Makefile`. For the Makefile, read only L166–178.
**Commits:** c58fe65 (toolchain and minimum), 3e1f7f2 (vendor), 91113bc (build and vendor-check modes).

**What changed, and why**
- **Build compiler:** go.mod's `toolchain` line, else its `go` line (go.dev/doc/toolchain). See `module_versions` (go_ci L89–108). Refused: a `go` line above `toolchain`, two `toolchain` lines, or a malformed one.
- **Modes:**
  - `go`: the compiler must equal the scanner pin and the installed Go.
  - `minimum`: exactly the declared minimum must be installed (`decide`, L110–152).
  - `minimum-version`: tells setup-go what to install (L222–231).
- **Vendoring:** a `require` line with no `go/vendor/modules.txt` fails (`vendor_problems`, L154–160). With a vendor tree, the targets run with `GOFLAGS=-mod=vendor` (`go_env`, L162–170).
- **`build` / `vendor-check` modes (L173–209):**
  - `go-build` runs offline on the vendor tree.
  - `go-vendor-check` runs with the job's environment, which is the only one with `GOPROXY=https://proxy.golang.org` and checksum database access (ci.yml `go-vendor`).
- **`check_go_drift.py`:**
  - The same go.mod reading for the scanner and engine modules (L49–70).
  - It reads setup-go versions in every workflow.
  - The only setup-go version allowed that isn't a literal release is `MINIMUM_SETUP` (L39).
- **Makefile:** `GO_TOOLCHAIN` and `GO_MINIMUM` (L171–172) and the `go-check-minimum` target (L173).

**Risks to check**
1. **Implicit downloads:** can any Go job still download a toolchain or module implicitly? `GOPROXY=off` comes from the workflow env, and `go_env` copies that env, changing only `GOFLAGS`.
2. **`run_target` (L192–209):** for `vendor-check`, it passes `os.environ` unchanged. Is any secret or token present in that env? Expected: none; the job has no `GH_TOKEN`.
3. **`minimum_version`:** does it return only digits and dots in every branch, including a hostile `go.mod` such as `go 1.27.4 $(id)`? The self-test asserts `None` for that.
4. **Version-gap check:** is any compiler/minimum gap missed? Version comparison is numeric (`version_key`); `1.27` sorts below `1.27.0`.
5. **Silent skips:** is there a path that skips silently where it should fail? Without the targets, `build` skips; with a bad Go, it fails (`target_decision`); `vendor-check` fails when there are dependencies and no target.
6. **Drift check:** can `ANY_GO_VERSION` be bypassed by a `go-version` written in another form, such as a flow mapping? Rule 9 bans flow mappings.

**Already run (no need to redo)**
- **Self-tests:** `go_ci --self-test` (18 tree refusals, 5 minimum refusals, 15 report refusals, 5 end-to-end runs) and `check_go_drift --self-test`; negative controls against the old code failed.
- **Real toolchains with `GOPROXY=off`:** Go 1.27.4 and 1.27.0 locally.
  - Culvert tree: go-engine passes on 1.27.4 and go-minimum on 1.27.0, and each refuses the other's Go.
  - Vendored go-migration: `make go-check` passes with no downloads (parity 7404/7404).
- **Hosted:** probe ed123d0, run 43914606928 (go-minimum on 1.27.0, no download); probe 407bfcc, run 44388423818 (go-vendor, go-build, vendored go-engine).

**Out of scope:** the engine lane's own Makefile targets on `claude/go-migration` (`go-vendor-check`, `go-build`); the scanner build jobs (unchanged).
