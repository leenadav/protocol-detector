---
name: verify-go
description: Go engine check (gofmt, vet, race tests, fuzz smoke, lint and static analysis against the baseline, coverage floors, allocation and retained-byte budgets, shuffled determinism, licences). Run it before reporting done on any change under go/ or to the Go CI tools.
---

# verify-go

These are the local equivalents of the CI jobs `Go engine`, `go-lint`, `go-coverage`, `go-determinism` and
`Go dependency licences`. Run every step from the repository root. Each step must exit 0. Use
`set -o pipefail` whenever you pipe output, because `cmd | tail` hides a failure.

## Environment

Go runs offline on the pinned toolchain of `go/go.mod` (1.27.4) with the committed vendor tree:

```sh
export GOTOOLCHAIN=local GOPROXY=off GOWORK=off
go version   # must print go1.27.4; otherwise put the pinned Go first on PATH (and set GOROOT to it)
```

The lint, licence and API tools are pinned in `tools/golint/<tool>/go.mod` and `go.sum`. Build them once,
outside the repository and before any repository code runs, exactly as CI does (this is the only step that
downloads, through the proxy and the checksum database):

```sh
B="${TMPDIR:-/tmp}/golint"; mkdir -p "$B"; cp -r tools/golint/golangci-lint tools/golint/staticcheck \
  tools/golint/gosec tools/golint/go-licenses "$B/"
for t in golangci-lint staticcheck gosec go-licenses; do
  (cd "$B/$t" && GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GOFLAGS=-mod=readonly \
    GOBIN="$B/bin" go install tool) || echo "build of $t FAILED"
done
```

## Steps and healthy output

| # | Command | What it checks | Healthy output (as of `claude/go-migration` `cdb385b`) |
|---|---|---|---|
| 1 | `make go-check PYTHON=python3` | gofmt, `go vet`, `go test -race ./...`, every fuzz smoke target, `parity-go`, `parity-analyze`, `parity-decrypt`, the random differential suite, schema and the other Go gates | exit 0 (about 10 minutes); 66 test packages `ok`, the rest `[no test files]`; `go schema check: 200 captures; … 0 problems (seed 1)`; `adversarial: 4041 cases, 4040 honest, 1 known findings, 0 failures; Go matched the reference on 4041 of 4041`. The line `random differential FAILED: engines differ on random/tls/1/00000` is the planted self-check and is expected (see verify-parity) |
| 2 | `python3 -B tools/go_lint.py --bin "$B/bin"` | golangci-lint, staticcheck and gosec against `tools/golint/baseline.json` | `No finding beyond the baseline (194 accepted)` (golangci-lint 81, staticcheck 9, gosec 104) |
| 3 | `python3 -B tools/go_cover.py` | statement coverage with `-coverpkg=./...` against `tools/golint/coverage-floors.json` | `Module: 79.0% of 20144 statements (floor 78.0%)` and `Every floor holds` |
| 4 | `make bench-gate` | the per-flow budgets: allocations, retained bytes, report latency | `--- PASS` for `TestBenchGate_AllocationsPerFlow`, `TestBenchGate_RetainedBytesPerFinishedFlow` and `TestBenchGate_ReportLatencyPerFlow`, then `ok` |
| 5 | `python3 -B tools/go_deep.py determinism` | `go test -race -shuffle=on -count=2 ./...`: tests that depend on order or state | `37 package(s) passed twice in shuffled order with -race`, exit 0 (about 2.5 minutes) |
| 6 | `python3 -B tools/go_deep.py licenses --bin "$B/bin"` | every vendored module's licence (`forbidden`, `restricted`, `unknown` fail) | `golang.org/x/crypto` and `golang.org/x/sys/cpu` BSD-3-Clause, then `2 linked module(s); none forbidden, restricted or unidentified (the engine's own module, github.com/leenadav/protocol-detector/go, is excluded)` |

A changed count is fine when your change explains it. A new lint finding is fixed, never added to the
baseline to get green (`--write-baseline` is only for removing findings that are gone). A coverage floor is
raised when coverage rises and never lowered to pass. A budget failure in step 4 is a regression in the
change: find the allocation, do not loosen the budget.

The parsing budgets themselves (`errs.Exceeded`, `parsing.Budget`, `parsing.Malformed`) are exercised by the
`*StaysBounded` and `*NeverPanics` fuzz targets in step 1. A change to a parser of untrusted traffic also
needs a regression test that a malformed or oversized length returns the existing error, not a panic or a
positive result (AGENTS.md, Code Review Rule 1).

## Clean up

`go/bin/` and `build/` are untracked build output: `rm -rf go/bin build` before you commit, never commit them.
