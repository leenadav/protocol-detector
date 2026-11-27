# Security review A17: the five open CI and supply-chain pull requests (PRO-523)

Reviewer: Security Reviewer (AppSec lane), read-only. Date: 2026-11-27. Base: `main` `5cb35d2`.
Earlier workflow reviews: A12 (PRO-185) and A13 (PRO-360). Each pull request was read at the head below with
`git diff 5cb35d2 <head>`, and every file it touches was read in full at that head.

| PR | Task | Head | Verdict |
|---|---|---|---|
| [#149](https://github.com/leenadav/protocol-detector/pull/149) release: Go binaries never silently skipped, version stamped | PRO-194 | `ca5d53afff5c1ed50e7fff776a6fd4ef53ed33b4` | no findings |
| [#155](https://github.com/leenadav/protocol-detector/pull/155) nightly-fuzz: gremlins mutation testing | PRO-176 | `3834660` | no findings (it also carries all of #149, see O-1) |
| [#157](https://github.com/leenadav/protocol-detector/pull/157) benchstat performance gate | PRO-268 | `c4d6fd0` | 1 finding: SEC-CI-A17-1 (P3) |
| [#158](https://github.com/leenadav/protocol-detector/pull/158) ci tools fail closed (A12 hardening) | PRO-187 | `e68f1f8` | no findings |
| [#159](https://github.com/leenadav/protocol-detector/pull/159) Dependabot security updates only | PRO-270 | `54d7d2b` | 1 finding: SEC-CI-A17-2 (P3) |

Totals: P0 0, P1 0, P2 0, P3 2. No pull request adds a write scope, a `pull_request_target` or `workflow_run`
trigger, an unpinned action, or untrusted event text expanded inside `run:`.

## Findings

### SEC-CI-A17-1 (P3): the hot-path benchmark gate passes when no hot benchmark was compared (#157)

- **Where:** `tools/go_bench.py` at `c4d6fd0`: `judge` lines 136 and 139, `missing_hot` line 158, `parse_csv`
  line 105, used at line 275.
- **What:** `missing_hot` only checks that each `HOT` pattern matches some benchmark name in the head's raw
  `go test -bench` output. It does not check that a hot benchmark was actually compared with the base. A hot
  benchmark that is present at only one side is reported as "gone at head" or "new at head: nothing to compare"
  with `failed=False`. When `parse_csv` recognises no table in benchstat's CSV (a format change in a benchstat
  bump, or a head benchmark that prints its own `pkg:` or other configuration line, which benchstat reads as a
  new configuration), `judge` returns no rows and the job prints "No hot-path regression".
- **Path:** a pull request renames `BenchmarkFlow`'s `tls` sub-benchmark to `tls2` and makes the TLS path twice
  as slow, with 50 more allocations. `^Flow/` still matches at head, so the presence check passes, and neither row
  fails. SSDLC.md item 44 says that "renaming or deleting one cannot switch the gate off". That holds for the
  pattern, but not for each benchmark the pattern covers.
- **Evidence** (scratch reproducer, run against `c4d6fd0`'s `tools/go_bench.py`):

  ```
  judge("detector", parse_csv(<base Flow/tls 1e-5 s, 89 allocs; head Flow/tls2 2e-5 s, 139 allocs>))
    -> [('Flow/tls', True, 'gone at head', False), ('Flow/tls2', True, 'new at head: nothing to compare', False)]
  missing_hot({"detector": {"Flow/tls2", "FlowBytewise/x"}, "internal/protocols/quicx": {"AssemblerDatagram/a"}}) -> []
  judge("detector", parse_csv("garbage\n,a,b\n")) -> []
  ```

- **Impact:** a performance regression on the per-flow hot path can merge without the gate seeing it. That is
  CPU amplification on the proxy path. The regression stays visible in the diff, so this weakens a detective
  control and is not a bypass of a security boundary. Hence P3.
- **Fix:** fail closed on comparison, not on naming. A hot benchmark present at the base must be compared at head:
  a hot row "gone at head" fails, unless `HOT` changes in the same diff. Every hot package that was measured on
  both sides must give at least one judged hot row with both a base and a head sample, or the job fails with
  "benchstat output not understood". Add both cases as negative self-tests.

### SEC-CI-A17-2 (P3): the Dependabot module list and the repository's go.mod files can drift apart (#159, with #157)

- **Where:** `.github/dependabot.yml` at `54d7d2b`, lines 41-51 (`directories:` of the gomod entry).
- **What:** the list is written by hand. #157 adds `tools/golint/benchstat/go.mod` (golang.org/x/perf at a
  2026-11-17 pseudo-version), which is not in #159's list, and no policy rule ties the list to the go.mod files
  in the tree. Whichever of #157 and #159 merges second leaves benchstat outside the configured security-update
  group. The same happens to every scanner module added later.
- **Evidence:** at `c4d6fd0`, `git ls-tree -r --name-only` lists `tools/golint/benchstat/go.mod`. #159's
  `directories:` has `/go`, `/go/oracle`, `/tools/scanners`, six `/tools/golint/*` and
  `/migration/mutation/gremlins`, and no benchstat. `tools/check_workflow_policy.py` has no rule that reads
  `dependabot.yml`.
- **Impact:** a CI-only build tool would get no grouped, prefixed security pull request, so a vulnerable
  benchstat or a future scanner relies on `osv-scan` and `toolchain-audit` alone. It is never shipped, so the
  impact is P3.
- **Fix:** add `/tools/golint/benchstat` to the list in whichever pull request merges second. Then add a
  workflow-policy rule: every committed go.mod outside `vendor/` (except `go/consumertest`, which has only the
  local module) must appear in the gomod `directories:`, and every `GO_LINT_MODS` entry must too. Give the rule
  a negative self-test.

## Observations (not findings)

- **O-1: #155 contains #149.** #155's head `3834660` merges `origin/claude/determined-mayer-cyjpa0` at `ca5d53a`,
  which is #149's head. #155's diff therefore includes all of #149 (`tools/build_go_release.py`,
  `docs/RELEASING.md`), so merging #155 also releases #149's change. The content is identical (`git diff ca5d53a
  3834660 -- tools/build_go_release.py docs/RELEASING.md` is empty), and this review covers it under #149. The
  two pull requests have one topic each only if #149 merges first (CLAUDE.md, "Big or mixed PRs").
- **O-2: the mutation gate trusts the baseline file.** In `migration/mutation/mutation.py` on main, a missing
  `baseline.json` gives an empty baseline, so `compare` reports nothing (line 116). The file is committed and
  the nightly job is not a required check, so there is no finding. It is worth a fail-closed check when the
  mutation job becomes a gate.
- **O-3: Culvert comparison not done.** The read-only Culvert clone named in the task
  (`/home/hermes/projects/ext/Culvert`) is not present in this reviewer's container. The comparison with
  Culvert's CI practice is therefore not part of this review.

## Checked and found sound

**#149 (release).**
- The publish job's scopes are unchanged (`contents`, `id-token` and `attestations: write` only there). The
  build job that now runs the built binary has `contents: read` only, holds no token and runs on a GitHub-hosted
  runner.
- `--version` comes from `protodetect.py version`. The build job checks it against `pyproject.toml` and the
  tag, and `build_go_release.py` checks it against `VERSION`
  (`^[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z.]+)?$`: no space, quote, `$` or `/`), so `-X main.version=` is a
  single argv word with no injection.
- `main.version` is a `var` at the head (`go/cmd/protodetect/main.go:34`), so `-X` takes effect.
- The reported-version check fails closed on a non-zero exit, a timeout (`TimeoutExpired` is a
  `SubprocessError`), an exec error, a wrong first or second word, and an unbuilt check target (the default line
  is FAILED).
- `go/go.mod` without `go/cmd/protodetect` now fails instead of skipping.
- Both builds get the same flags, so the double-build reproducibility comparison still holds.

**#155 (gremlins).**
- The job has `contents: read`, `persist-credentials: false`, the pinned harden-runner, checkout and setup-go
  SHAs, and `cache: false` (no Go cache to poison).
- The only networked step builds gremlins v0.6.0 from a `RUNNER_TEMP` copy of its pin module, with
  `-mod=readonly`, `GOSUMDB=sum.golang.org` and empty `GONOSUMDB`, `GOPRIVATE` and `GOINSECURE`. Every hash is
  checked against go.sum and the checksum database, and the step runs before any repository code.
- `go mod download` of a go.mod and go.sum copy fetches only and executes nothing. The later steps run with
  `GOPROXY=off`.
- The triggers are `schedule` and `workflow_dispatch`. No pull request runs the job, and the dispatch inputs are
  not used by the mutation job.
- The `mutation-results` artifact is written only and read by nothing. The baseline is the committed
  `migration/mutation/baseline.json`, so there is no artifact or cache path that could poison it.
- Policy rule 15 pins the first four steps, `contents: read` and the 30-minute timeout, with negative
  self-tests. The workflow lock is updated.

**#157 (benchstat).**
- The job inherits the workflow's `contents: read`, with no job-level grant. Checkout uses
  `persist-credentials: false`, and the job adds no secret and no write scope.
- benchstat is built outside the checkout before repository code runs (rule 15 entry), and its go.mod is locked
  (rule 16, `GO_LINT_MODS`).
- `BASE_SHA` and `HEAD_SHA` reach the tool through `env:`, never interpolated in `run:`, and are used as argv
  (`git rev-parse --verify <sha>^{commit}`, `git merge-base`).
- Baselines are re-measured from the merge base in each run, with no cache or artifact carried between pull
  request and main runs, so there is nothing to poison.
- These failures fail the job: an undiffable range (it measures), a missing head or base, `git worktree`, a
  benchstat exit, and a head build or run error. Only base-side problems are downgraded to notes, and a pull
  request cannot influence them.
- The job is in the `ci gate` needs.

**#158 (fail closed).**
- `contract_check.cli_presence`: a CLI removed at the head is breaking and needs the `api-break` label.
- `go_api.judge_report` fails on any non-zero apidiff exit, on text outside the report sections, on an empty
  report when the exports' package sets differ, and on an unreadable export zip.
- `go_lint` keys gosec findings under `internal/protocols/` and `internal/decrypt/` by enclosing function. An
  unreadable source becomes `[in package scope]`, which does not match a keyed baseline entry and so fails.
- The re-keyed baseline shrinks from 193 to 192 findings (gosec 103 to 102: the fingerprint G115 that is no
  longer reported). No count went up, and the scanner lock moves with it.

**#159 (Dependabot).**
- `open-pull-requests-limit: 0` on every entry turns version updates off. Each ecosystem has one
  `applies-to: security-updates` group, and the prefix is `deps(security)`.
- No workflow, tool or setting auto-merges, approves or labels Dependabot pull requests (no `auto-merge`
  anywhere in `.github/`).
- Dependabot pull requests run the ordinary `pull_request` CI: a read-only token, and the same required gates.
- Actions stay SHA-pinned, and rule 7 and `supply-chain-drift` apply to Dependabot's rewrites.
- The vendored `/go` module is listed, and the review steps in SSDLC.md require the `vendor/` update.
- `presentation/requirements-decryption.lock.txt` (the shipped decryption extra) is left out on purpose,
  because Dependabot's pip updater would flatten the uv universal lock. It stays covered by `osv-scan`, which
  scans every lockfile.
