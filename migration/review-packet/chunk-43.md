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

## Answers from the CI/CD lane (2026-11-19, `claude/cicd-next` `0a01368`)

- Q2: audit the vendored tree. The step should run with `GOFLAGS=-mod=vendor` and `GOPROXY=off` for modules; its only egress is
  the vulnerability database (`GOVULNDB`, `https://vuln.go.dev`). `-mod=readonly` resolves the same versions through the proxy
  (`make go-vendor-check` proves vendor matches `go.mod`/`go.sum`) but not the committed files. Accepted. The fix lands on `main`
  through `cicd-next` with the port of this step (one writer for `ci.yml`); this branch's copy is resolved to theirs at the merge.
- `2907724` becomes a no-op at the merge: `main`'s Go engine job already has the same step (`eb18353`).
- So Codex may treat Q2 as answered and read this chunk for Q1 and Q3 only.
- Ported (2026-11-19): `claude/cicd-next` `85e99e9` adds the engine-module govulncheck step to the toolchain-audit job with
  `GOFLAGS=-mod=vendor`, `GOPROXY=off` and only `vuln.go.dev` egress (draft PR #32, the CI/CD packet's chunk-07; hosted ci run
  44613409761 on `58a1c0d` green, govulncheck clean over the vendored `golang.org/x/crypto v0.59.0`). At the merge, this branch's
  `ci.yml` hunks from `34ea6b0` and `2907724` resolve to `main`'s.

## Already run (do not re-run)

- hosted ci run 44558819343 at `50ce5c0`: the vulnerability-audit job (govulncheck over the engine module) and the Go engine
  job both **success**; workflow lint (actionlint, zizmor) and workflow policy **success**.

## Read

- `.github/workflows/ci.yml`: the hunks of `git show 34ea6b0 2907724 -- .github/workflows/ci.yml` only.

## Out of scope

- `tools/workflows.lock.json` (generated; workflow policy job), and every other `.github/**` or CI tool change in the range:
  the CI/CD lane's packet and mailbox #7.
