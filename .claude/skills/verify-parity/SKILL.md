---
name: verify-parity
description: Python-vs-Go parity check (committed parity cases, family evidence and the seeded random differential suite). Run it before reporting done on any change that touches go/, migration/, the Python reference or the parity tooling.
---

# verify-parity

The Python reference is the oracle and the Go engine must agree with it on every committed case and on the
seeded random differential suite. Run every step from the repository root. Each step must exit 0. Use
`set -o pipefail` whenever you pipe output, because `cmd | tail` hides a failure.

## Environment

Go runs offline on the pinned toolchain of `go/go.mod` (1.27.4) with the committed vendor tree:

```sh
export GOTOOLCHAIN=local GOPROXY=off GOWORK=off
go version   # must print go1.27.4; otherwise put the pinned Go first on PATH (and set GOROOT to it)
```

## Steps and healthy output

| # | Command | Healthy output (counts as of `claude/go-migration` `cdb385b`) |
|---|---|---|
| 1 | `make parity PYTHON=python3` | `parity: compared 7430, matched 7430, mismatched 0, missing 0, extra 0, exempted 0, unsupported 0 (unlisted gaps: 0, stale gap entries: 0, claimed families without a match: 0)` |
| 2 | `make parity-go PYTHON=python3` | the same `parity:` line for the Go results, then `family statuses: 88 parity-verified of 88, 0 stated statuses differ from the evidence` |
| 3 | `make parity-random PYTHON=python3` | the self-check `random differential self-check: planted difference on random/tls/1/00000 caught`, then `Go matched the reference on 2000 of 2000, 0 allowed, 0 failures` |

Step 1 checks the committed cases against the Python reference. Step 2 replays them through the Go binary
(`protodetect replay`), compares the results exactly and checks every family's stated status in
`migration/CAPABILITIES.json` against that evidence. Step 3 is the differential suite: a self-test, a 300-case
run with one planted difference that must be caught (it prints `random differential FAILED: engines differ on random/tls/1/00000`, which is expected here; a self-check that catches nothing is a failure), and the
fixed CI run, seed 1 with 2,000 cases.

A changed count is fine when your change explains it (new cases, a new family). Any `mismatched`, `missing`,
`extra`, `unlisted gaps`, `stale gap entries` or `failures` above 0 is a failure.

## Longer runs and reproducing a failure

```sh
mkdir -p build    # make does not create it; the report write fails without it
make parity-random-long SEED=<seed> COUNT=25000 PYTHON=python3
```

Keep `COUNT` at 25,000 or less per run: one replay of 50,000 random cases exceeds `protodetect replay`'s
64 MiB cases budget. The nightly `parity-random` job runs 50,000 cases as two batches with one seed each and
prints the exact command that reproduces each batch. A failing seed reproduces exactly; the report is
`build/random-diff-<seed>.json`.

A mismatch is a bug to fix in Go (product Python is frozen, see `migration/STATUS.md`). It may be added to
`migration/parity/random_allow.json` only with a reason; an entry that stops mismatching fails the run.

## Clean up

`go/bin/` and `build/` are untracked build output: `rm -rf go/bin build` before you commit, never commit them.
