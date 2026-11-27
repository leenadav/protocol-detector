---
name: verify-parity
description: Go-vs-reference parity check (the frozen answers of the removed Python reference: committed parity cases, family evidence and the seeded random differential suite). Run it before reporting done on any change that touches go/, migration/ or the parity tooling.
---

# verify-parity

The Python reference was removed in PRO-403 (its last state is the tag `python-final`); its answers are frozen in
`migration/fixtures/cases.json` and `migration/fixtures/golden/`, and the Go engine must agree with them on every
committed case and on the seeded random differential suite. Run every step from the repository root. Each step
must exit 0. Use `set -o pipefail` whenever you pipe output, because `cmd | tail` hides a failure.

## Environment

Go runs offline on the pinned toolchain of `go/go.mod` (1.27.4) with the committed vendor tree:

```sh
export GOTOOLCHAIN=local GOPROXY=off GOWORK=off
go version   # must print go1.27.4; otherwise put the pinned Go first on PATH (and set GOROOT to it)
```

## Steps and healthy output

| # | Command | Healthy output (counts as of PRO-403, on `main` `5cb35d2` plus the removal) |
|---|---|---|
| 1 | `make parity-go PYTHON=python3` | `parity: compared 7474, matched 7474, mismatched 0, missing 0, extra 0, exempted 144, unsupported 0 (unlisted gaps: 0, stale gap entries: 0, claimed families without a match: 0)`, then `family statuses: 79 parity-verified of 88, 0 stated statuses differ from the evidence` |
| 2 | `make parity-random PYTHON=python3` | the self-check `random differential self-check: planted difference on random/tls/1/00000 caught`, then `Go matched the reference on 1882 of 2000, 118 approved divergences (SEC-HTTP-1 28, SEC-QUIC-3 90), 0 allowed, 0 failures` |
| 3 | `make golden-check PYTHON=python3` | every differential of `go-check-parity` replays its golden file with 0 differences, then `golden self-test: ok` and the boundary lock check |

Step 1 replays the committed cases through the Go binary (`protodetect replay`), compares the results exactly with
the frozen answers and checks every family's stated status in `migration/CAPABILITIES.json` against that evidence.
Step 2 is the differential suite: a self-test, a run on the golden file with one planted difference that must be
caught (it prints `random differential FAILED ... 1 failures`, which is expected there; a self-check that catches
nothing is a failure), and the replay of the frozen seed-1 run of 2,000 cases.

A changed count is fine when your change explains it (new cases, a new pinned divergence). Any `mismatched`,
`missing`, `extra`, `unlisted gaps`, `stale gap entries` or `failures` above 0 is a failure.

## Fresh random inputs

The reference can no longer answer new inputs. Fresh random openings are the Go-only property tests' job
(`go/internal/engine/openings_property_test.go`, no oracle): `make property-long CHECKS=50000 PROPERTY_SEED=<seed>`;
a failure prints the seed and a failfile that reproduce it.

A mismatch is a bug to fix in Go. A deliberate Go behaviour change is a pinned divergence with Lee's decision
recorded in `migration/STATUS.md`, never an edited answer; re-recording a golden file needs a checkout of
`python-final`.

## Clean up

`go/bin/` and `build/` are untracked build output: `rm -rf go/bin build` before you commit, never commit them.
