# CLAUDE.md

@AGENTS.md

AGENTS.md (imported above) holds the review priorities, the Code Review Rules, the scope limits and the lane
rules. This file adds only what a Claude Code session needs to work here.

## Commands (from the repository root)

| Command | What it runs | Healthy output ends with |
|---|---|---|
| `make check PYTHON=python3` | The full local gate: ruff, all tests, pins, workflow policy, docs counts, manifest, content, parity, … | `parity: compared 6584, matched 6584, mismatched 0, …` and exit 0 |
| `python3 -B tools/run_tests_strict.py` | The test suite, where a skip fails the run unless allow-listed | `838 tests discovered, 838 run, 0 skipped` / `strict test run: ok` |
| `make lint` | `ruff check .` | `All checks passed!` |
| `make workflow-policy PYTHON=python3` | Workflow policy rules, the lock and the self-tests of the CI tools | `workflow policy: ok (8 workflow files)` |
| `make content` / `make content-pack` | Content lock and release history; the exported pack | `content ok: release … digest …` / `content pack ok: …` |
| `python3 -B tools/content_gate.py` | The CI content-pack gate | no `FAILED` line and exit 0; on `main` today: "No Go content pack on this commit" |
| `cd go && GOTOOLCHAIN=local GOPROXY=off go test ./...` | Go tests, on the pinned Go of `go/go.mod` | every package `ok` or `[no test files]` |
| `make go-check` | gofmt, vet, `go test -race`, fuzz smoke, `make parity-go` | exit 0 |

The counts above are those of `main` at the time of writing. A changed count is fine when the change explains it.

## Conventions that matter

- Python 3.9 syntax, standard library only in the engine and in `tools/`. Each tool has a `--self-test`.
- Workflows: every action pinned to a full SHA, `contents: read`, and no `if:` or shell conditionals in `ci.yml`
  (the decision goes in a tool). After any workflow edit, run
  `python3 -B tools/check_workflow_policy.py --write-workflow-lock`.
- Go runs offline: `GOPROXY=off`, `GOTOOLCHAIN=local`, dependencies vendored.
- Check exit codes: use `set -o pipefail`, because `cmd | tail` hides a failure.
- Commit messages say why. PR bodies give what changed, verification with numbers, risk and what is out of scope.

## Things Claude gets wrong

- **Editing the Python reference.** Product Python is frozen. The only exceptions are the Lee-approved list in
  `migration/STATUS.md` ("Frozen-Python exceptions"); otherwise make the change in Go.
- **Skipping or weakening a failing test**, or adding `--allow-skip`, to get green. Find the cause and fix it.
  The only skip allowed is a quarantine of an intermittent test (below). Never disable a security check.
- **Rewriting history.** No force-push, rebase or amend of a pushed commit, and no tags. Merge the base branch in
  instead.
- **Big or mixed PRs.** One topic per PR, reviewable in about 15 minutes, cut from current `origin/main`. Lee
  merges; agents never merge, approve or comment on PRs.
- **Pushing to a merged PR's branch.** Those commits never reach `main`. Check the PR state first, and cut a new
  branch otherwise.
- **Re-running a red job until it passes.** Diagnose it. A test that fails twice intermittently is quarantined
  with an issue link and a deadline (AGENTS.md, "Flaky tests and verify skills"), never retried.
- **Reporting done without the verify skills.** Run `.claude/skills/verify-*` for what the change touches.
- **Editing the other lane's files.** Engine owns `go/`, `migration/` and product code; CI/CD owns `.github/`,
  its `tools/` and the locks. Send the other lane a patch instead.

## Guardrail hooks (PRO-75)

`.claude/settings.json` runs `.claude/hooks/guard.py` before every Bash, file-writing and GitHub MCP call, in the
terminal and in cloud sessions alike. It blocks force-push, pushes to `main`, tags, rebase or `reset --hard` of a
shared `claude/*` branch this session did not create, `gh pr merge` / approve / close, settings, secret and release
changes, and likely secrets in a write or a command (`go/**/testdata/` allowed). A block prints the reason and the
approval route: ask Hermes, never work around it. A false positive is a fix to `guard.py` with a test
(`python3 -B .claude/hooks/guard.py --self-test`, also run by `make workflow-policy` and ci `workflow-lint`).

## Skills to use

Project skills in `.claude/skills/` (MIT, upstream and changes in `.claude/skills/THIRD_PARTY.md`):

- **Debugging:** `systematic-debugging` before any fix; its `root-cause-tracing` and `defense-in-depth` for bugs deep in a call chain.
- **New behaviour or a bug fix:** `test-driven-development` (a failing test first; `writing-good-tests` for test anti-patterns).
- **Done claims:** `verification-before-completion` before DONE, a push or a PR: run the gate and quote its numbers.
- **Review findings (Codex, Hermes, bots):** `receiving-code-review`: verify each claim against the code before changing it.
- **Go tests, performance, errors:** `golang-testing`, `golang-performance`, `golang-error-handling` (listed once a `.go` file is open); the
  repository rules above win (offline Go, vendored dependencies, `parsing.Budget` / `parsing.Malformed`).

## Keeping this file useful

When an agent makes the same mistake twice, the fix goes into this file ("Things Claude gets wrong"), in the same
PR as the fix or in the next one. Keep it under one page.
