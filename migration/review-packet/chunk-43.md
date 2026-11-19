# chunk-43: This lane's two edits to the CI workflow

Tier 1 (supply chain) · 34 changed lines of `ci.yml`, plus their generated lines in `tools/workflows.lock.json` · contracts: C16

**Exact scope**: `git show 34ea6b0 2907724 -- .github/workflows/ci.yml`. These two engine-lane commits exist only on this branch
(not on `main`), so the CI/CD lane's packet (`claude/cicd-next` `3d9a40e`, `docs/review-packet/`, range `e927d44..ddc557d`) does not
cover them; every other change to `.github/**` and the CI tools in `dbe20f3..50ce5c0` is the CI/CD lane's own history merged in,
and stays with that lane (mailbox #7).

## What changed and why

- `34ea6b0` (M10): a govulncheck step over the Go engine module (source mode, `go/go.mod` and `go/go.sum` as committed) in the
  vulnerability-audit job, with `GOPROXY=proxy.golang.org`, `GOSUMDB=sum.golang.org`, `GOTOOLCHAIN=local`, `-mod=readonly`.
- `2907724`: the Go engine job installs the hash-pinned decryption extra (`presentation/requirements-decryption.lock.txt`) so the
  reference side of `make parity-decrypt` can decrypt, and its comment lists the extra differentials. PR #30 carries the same
  install step on `main`.

## Questions to answer

1. govulncheck step: is the network limited to the Go proxy and checksum database, with no private or insecure module setting
   that could fetch unverified code?
2. Does `-mod=readonly` here still match the vendored tree (`go/vendor`, `76e467a`), or should this step use `-mod=vendor` so
   it audits exactly what is built? (On `main`, the CI/CD lane's `go_ci.py` sets `-mod=vendor` whenever `go/vendor` exists.)
3. Is the pip install hash-pinned (`--require-hashes`), with no unpinned transitive package?

## Already run (do not re-run)

- hosted ci run 44558819343 at `50ce5c0`: the vulnerability-audit job (govulncheck over the engine module) and the Go engine
  job both **success**; workflow lint (actionlint, zizmor) and workflow policy **success**.

## Read

- `.github/workflows/ci.yml`: the hunks of `git show 34ea6b0 2907724 -- .github/workflows/ci.yml` only.

## Out of scope

- `tools/workflows.lock.json` (generated; workflow policy job), and every other `.github/**` or CI tool change in the range:
  the CI/CD lane's packet and mailbox #7.
