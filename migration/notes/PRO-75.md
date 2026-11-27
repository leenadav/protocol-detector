---
task: PRO-75
lane: platform
date: 2026-11-27
title: Claude Code PreToolUse guardrail hooks for force-push, main, merges, settings changes and secrets
prs:
shas: e179654a0933a3dbe093eb4ebc62817755f44bc7, 6204d9bf5e4a7a2d5f296db821c2643026049919
---
The forbidden-action rules lived only in instructions. `.claude/settings.json` now runs `.claude/hooks/guard.py` before every Bash, Write, Edit, MultiEdit, NotebookEdit and GitHub MCP call; exit 2 blocks it with the reason and the approval route. It blocks force-push (any spelling, `+refspec`), pushes to main (named, HEAD or current branch), tag and mirror pushes, rebase/pull --rebase/reset --hard of a shared `claude/*` branch on origin the session did not create, `gh pr merge`/approve/close, repo, secret, variable, release and ruleset changes (`gh`, `gh api` REST and GraphQL, MCP), and likely secrets (key headers, gh?_/github_pat_/sk-ant-/AKIA, high-entropy `*_TOKEN`/`*_KEY` literals; `go/**/testdata/` allowed). Commands are tokenized, so quoted text passes and nested ones block. Verified live in this cloud session: the hook blocked its own test file on a false positive, since fixed; CodeQL empty-except on the branch record fixed fail-safe with a test. Gates: guard 30/30, make check exit 0 (909 tests, parity 7474/7474), strict 909 run 0 skipped, workflow policy ok. Open: aliases, scripts and other interpreters are out of reach by design.
