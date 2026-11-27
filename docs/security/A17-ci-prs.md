# A17: security review of the five open CI and supply-chain pull requests (PRO-523)

Reviewer: Security Reviewer (AppSec), read-only. Date: 2026-11-27. Base: `origin/main` `5cb35d29e6392b1d96d75c3f569baa378a0efe68`.
Earlier workflow reviews: A12 (PRO-185), A13 (PRO-360). Nothing in the reviewed branches was changed by this review.

| PR | Topic | Head reviewed | Verdict |
|---|---|---|---|
| [#149](https://github.com/leenadav/protocol-detector/pull/149) | release: Go binaries never silently skipped, release version stamped (PRO-194) | `ca5d53a` | no findings |
| [#155](https://github.com/leenadav/protocol-detector/pull/155) | nightly-fuzz: gremlins mutation testing (PRO-176) | `3834660` | no findings (one scope note) |
| [#157](https://github.com/leenadav/protocol-detector/pull/157) | benchstat performance gate (PRO-268) | `c4d6fd0` | finding SEC-CI-1 (P3, shared with #159) |
| [#158](https://github.com/leenadav/protocol-detector/pull/158) | ci tools fail closed (A12 hardening, PRO-187) | `e68f1f8` | finding SEC-CI-2 (P3) |
| [#159](https://github.com/leenadav/protocol-detector/pull/159) | Dependabot security updates only (PRO-270) | `54d7d2b` | finding SEC-CI-1 (P3, shared with #157) |

Counts: P0 0, P1 0, P2 0, P3 2.

Method: `git diff origin/main...<head>` for each PR, the touched files read whole at the PR head, the workflow
triggers and permissions traced, and unit-level reproducers in a scratch directory (never committed). The KidCarmi/Culvert
clone named in the task (`/home/hermes/projects/ext/Culvert`) is not present on the machine that ran this review, so
no Culvert comparison was made.

## Findings

### SEC-CI-1 (P3): `tools/golint/benchstat/go.mod` gets no Dependabot security updates

- Where: `.github/dependabot.yml` (PR #159 head `54d7d2b`), the `gomod` entry's `directories` list; the module is added
  by PR #157 (`tools/golint/benchstat/go.mod`, head `c4d6fd0`).
- Reasoning: #159 lists every Go module tracked on `main` today (`/go`, `/go/oracle`, `/tools/scanners`, six
  `/tools/golint/*`, `/migration/mutation/gremlins`). #157 adds a seventh scanner module, `tools/golint/benchstat`
  (golang.org/x/perf, github.com/aclements/go-moremath), that runs in the required `go-bench` job. Neither PR knows of
  the other, so whichever merges second leaves benchstat outside Dependabot: an advisory against x/perf or its
  dependencies opens no security update PR.
- Evidence: `git ls-tree -r --name-only pr157 | grep golint/.*/go.mod` lists `tools/golint/benchstat/go.mod`;
  the #159 `directories` list has no `/tools/golint/benchstat`.
- Impact: low. The `osv-scan` job still reports a known advisory for every tracked lockfile (go.sum included), so the gap
  is a missing automated fix PR, not a missing detection. The tool runs only in CI with a read-only token.
- Fix: add `- /tools/golint/benchstat` to the `gomod` `directories` in whichever of #157 and #159 merges second (or in a
  follow-up). A policy check that every tracked `go.mod` other than `go/consumertest` is listed in `dependabot.yml`
  would keep the next scanner module from repeating it.

### SEC-CI-2 (P3): gosec function keys end a function at any column-0 `}`, including inside a raw string

- Where: `tools/go_lint.py` `enclosing_function` (PR #158 head `e68f1f8`), the line
  `elif current and text.startswith("}"):`.
- Reasoning: SEC-CI-A12-3 is fixed by keying gosec findings under `internal/protocols/` and `internal/decrypt/` by their
  enclosing function. The scanner is line based: any line that starts with `}` ends the current function. gofmt does
  not re-indent the inside of a raw (backtick) string, so a multi-line raw string with a `}` in column 0 ends the
  function early, and a finding after it is keyed `[in package scope]`. It is then compared with the file's package-scope
  baseline entries instead of the function's.
- Reproducer (scratch only), run against the #158 copy of `go_lint.py`:

  ```
  src = "package p\n\nfunc Parse(b []byte) uint16 {\n\tconst help = `usage:\n}\n`\n\treturn uint16(len(b))\n}\n"
  enclosing_function(src, 7)                          -> None
  gosec_scope("internal/protocols/x/x.go", "7", ...)  -> " [in package scope]"
  ```

- Impact: low. A new finding is hidden only when the same file already has a baseline entry with the same rule and
  message at package scope (today: G101 in `internal/protocols/framed/database.go`, G501 in
  `internal/protocols/fingerprint/fingerprint.go`) and one of those is fixed at the same time. A reviewer would see the
  raw string in the diff. Everywhere else a mis-keyed finding is a new key and fails the job (fail closed).
- Fix: skip the inside of raw strings when scanning (track an odd count of backticks outside comments and `"..."`
  strings), or key from gosec's own position with `go/ast` via a small vendored helper. Add the reproducer above to the
  self-test as a negative case.

## Checked and found sound

### #149 release version and missing main package (`tools/build_go_release.py`, `docs/RELEASING.md`)

- The version reaches `-ldflags` only after `VERSION` (`^[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z.]+)?$`) matched in
  `main()`: no space, quote or slash, so it cannot add a linker flag or move an output path. The workflow also checks it
  against `pyproject.toml` and the tag before the build.
- `go/cmd/protodetect/main.go` declares `var version = "0.0.0-m4"`, so `-X main.version` applies. The linux/amd64 binary
  is run as `protodetect version` with a 60 s timeout, and the release fails unless the second word is exactly the
  version (a fixed `const`, a prefix such as `1.2.30`, a non-zero exit and an unrunnable binary all fail). The other
  targets get the same flag, and the double-build comparison still runs on every target.
- `tree_state` fails the release when `go/go.mod` exists without `go/cmd/protodetect` (A12's silent skip is gone); only
  a commit with no `go/go.mod` skips.
- The binary runs in the `build` job (`contents: read`). The `publish` job (`contents: write`, `id-token: write`,
  `attestations: write`) is unchanged, runs only on `push` of a tag, and checks out nothing.

### #155 nightly mutation job (`.github/workflows/nightly-fuzz.yml`, `tools/check_workflow_policy.py`)

- Triggers are `schedule` and `workflow_dispatch` only (no `pull_request_target`, no `workflow_run`); dispatch needs
  write access to the repository. The job is `contents: read`, `timeout-minutes: 30`, `persist-credentials: false`.
- Every action is pinned by full SHA and matches `tools/workflows.lock.json`; harden-runner comes first.
- The one networked step builds gremlins from `RUNNER_TEMP` copies of `migration/mutation/gremlins/go.mod`, `go.sum` and
  `tools.go`, with `GOFLAGS=-mod=readonly`, `GOSUMDB=sum.golang.org` and empty `GONOSUMDB`/`GOPRIVATE`/`GOINSECURE`, so
  every module hash is checked against go.sum and the checksum database before any repository code runs. The later step
  is `GOPROXY=off`; `mutation.py` builds with `-mod=vendor`.
- No cache and no downloaded artifact: the efficacy baseline is the committed `migration/mutation/baseline.json`, and
  the uploaded results are trend data that nothing reads back, so there is nothing to poison across runs.
- `make mutation` with `MUTATION_BIN` set to a missing file has no rule to make it and fails; `mutation.py` deletes a
  stale report before each package, fails on a gremlins error, and fails when a baseline package has no result or no
  covered mutant (fail closed). The new policy rule (`check_mutation_build`) pins the step prefix, permissions and
  timeout, and its self-test covers each relaxation.
- Inputs `iterations`, `go_budget`, `random_seed` and `random_count` are not used by the new job.
- Scope note (not a security finding): the #155 head merges #149's branch (`claude/determined-mayer-cyjpa0`), so its
  diff also carries `tools/build_go_release.py` and `docs/RELEASING.md`. Merging #155 first lands #149's change
  unreviewed as part of #155's review; the review above covers both.

### #157 benchstat gate (`.github/workflows/ci.yml` `go-bench`, `tools/go_bench.py`)

- `ci.yml` runs on `push` to `main`, `pull_request`, `schedule` and `workflow_dispatch`: a fork PR runs with a read-only
  token and no secrets. The job inherits workflow-level `contents: read`, checks out with `persist-credentials: false`
  and `fetch-depth: 0`, and is added to the final gate's `needs`.
- `BASE_SHA` and `HEAD_SHA` come from `github.event.pull_request.*.sha` through `env:`, never expanded inside `run:`;
  the tool passes them to `git rev-parse --verify ...^{commit}` and `git merge-base` as argv, no shell.
- benchstat is built like the other scanners (RUNNER_TEMP copy, `-mod=readonly`, checksum database), pinned in
  `tools/golint/benchstat/go.sum` and locked by rule 16 in `tools/scanner_config.lock.json`; the policy self-test
  rejects a build inside the checkout.
- No benchmark baseline is stored or cached: both sides are measured in the same job from `git worktree` checkouts of
  the merge base and the head, so a PR cannot poison the comparison of a later run.
- Fail closed: a diff git cannot produce measures; a head test binary that does not build, a failed head run, a
  benchstat error and a `HOT` pattern with no benchmark at head all fail. Only a base without `go/go.mod` or a diff
  outside `go/`, the tool and its module skips.

### #158 fail-closed CI tools (`tools/contract_check.py`, `tools/go_api.py`, `tools/go_lint.py`, baseline)

- SEC-CI-A12-1: `cli_presence` makes a CLI present at the base and missing at the head a breaking change, which
  `go_api.decide` fails without the `api-break` label (self-tested).
- SEC-CI-A12-2: `judge_report` fails on any non-zero exit, on output with no report section, and on an empty report
  when the two exports hold different package sets. Checked against apidiff's source at the pinned
  `golang.org/x/exp v0.0.0-20261113113407-e3970619a1a4` (`cmd/apidiff/main.go`): it exits 0 after printing its report
  and 1 (`die`) or 2 (usage) on failure, so an incompatible change does not by itself make the gate error.
  `export_packages` fails on an unreadable export.
- SEC-CI-A12-3: fixed for the common case; the residual is SEC-CI-2. The baseline rewrite only adds `[in F]` suffixes
  and regroups counts by function (quicx: 4 `int -> uint64` = 2 + 2, 6 `uint64 -> int` = 2 + 4); one entry is removed
  (`internal/protocols/fingerprint/fingerprint.go` G115 `rune -> byte`), which shrinks the baseline and cannot hide a
  finding. The baseline is locked by rule 16, so the change is reviewed.
- No workflow or token change in this PR.

### #159 Dependabot (`.github/dependabot.yml`)

- `open-pull-requests-limit: 0` on every entry turns version updates off; security updates keep their own limit. Each
  group sets `applies-to: security-updates`, one group per ecosystem.
- No auto-merge: no workflow in `.github/workflows/` approves or merges Dependabot PRs, and no `pull_request_target`
  or `workflow_run` trigger exists anywhere in the tree. A Dependabot PR runs `ci.yml` as an ordinary `pull_request`.
- Actions updates rewrite the pinned SHA; the workflow policy lock and rule 16's scanner lock make any such PR fail
  until a reviewed lock update, so an update cannot slip a new action or scanner version in unreviewed.
- `presentation/requirements-decryption.lock.txt` (cryptography, cffi) stays outside Dependabot on purpose (a uv
  universal lock); `osv-scan` still scans it, so an advisory is reported, and the regeneration is the engine lane's.
- The file changes no repository setting; enabling Dependabot alerts and security updates stays Lee's decision.
