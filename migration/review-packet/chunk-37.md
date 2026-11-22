# chunk-37: Policy engine

Tier 2 · about 674 changed lines of code · contracts: C10, C16

**Exact scope**: `git diff dbe20f3 50ce5c0 -- go/internal/policy/policy.go` (1 commits in `dbe20f3..50ce5c0` touch these files).

## What changed and why

Typed policy predicates (D04) over identity basis, decryption status and capture quality; policy documents are operator content.

## Questions to answer

1. Can a policy match on `authenticated` identity when the record only has a client assertion (D04, C10)?
2. Is an unknown predicate or operator a load error rather than a never-matching rule?

## Already run (do not re-run)

- `make go-check` (gofmt, vet, `go test -race ./...`, the fuzz smoke targets named here, every differential): `FuzzPolicyNeverPanics`
- local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; parity 7,430/7,430, 88/88 families parity-verified, adversarial 4,041 cases 0 failures, server parity 424 exchanges 0 mismatched
- hosted ci run 44558819343 at `50ce5c0`: job `Go engine` (135682138044, `make go-check` incl. parity) **success**; codeql run 44558818757 success; static analysis, security requirements, package build, supply chain, vulnerability audit (pip-audit, govulncheck) and workflow lint jobs success

## Read

- `go/internal/policy/policy.go`: whole file (674 lines, new)
- Supporting tests (read only to answer a question above): `go/internal/policy/policy_test.go`

## Out of scope

