# Third-party skills in .claude/skills

Copied, not referenced: plugins declared in `.claude/settings.json` do not load in Anthropic-hosted cloud
sessions (PRO-200 smoke check on `1542a34`: "No plugins installed"), while project skills in `.claude/skills/` do.
Only MIT-licensed skills are copied (Hermes, PRO-200). Each skill folder carries its upstream LICENSE.

| Skill | Upstream | Commit | Version | Licence |
|---|---|---|---|---|
| systematic-debugging (with root-cause-tracing.md, defense-in-depth.md, condition-based-waiting.md) | github.com/obra/superpowers `skills/` | `22f0b463e7a5e579904dd6211a520321035526f7` | 7.0.2 | MIT, (c) 2025 Jesse Vincent |
| test-driven-development (with writing-good-tests.md, formerly testing-anti-patterns) | same | same | 7.0.2 | MIT, (c) 2025 Jesse Vincent |
| verification-before-completion | same | same | 7.0.2 | MIT, (c) 2025 Jesse Vincent |
| receiving-code-review | same | same | 7.0.2 | MIT, (c) 2025 Jesse Vincent |
| golang-testing | github.com/samber/cc-skills-golang `skills/` | `d68d80aec298e1b74b37c2a472c002b5217248b3` | 1.4.0 (plugin 2.0.1) | MIT, (c) 2026 Samuel Berthe |
| golang-performance | same | same | 1.3.2 | MIT, (c) 2026 Samuel Berthe |
| golang-error-handling | same | same | 1.3.1 | MIT, (c) 2026 Samuel Berthe |

## Changes from upstream

- Markdown only. Not copied: superpowers' plugin manifest and SessionStart hook (it injected an "always invoke a
  skill" instruction into every session), `find-polluter.sh` and `condition-based-waiting-example.ts` (named in
  root-cause-tracing.md and condition-based-waiting.md), samber's `evals/` and `assets/`.
- The three samber `SKILL.md` files lose two frontmatter keys: `allowed-tools`, which would pre-approve tools such as
  `Bash(git:*)`, `WebFetch` and `Edit` while the skill is active, and `metadata`, whose install hints use unpinned
  `go install ...@latest` (this repository builds Go offline). Every other file is byte-identical to upstream.
- Not taken: the rest of superpowers (brainstorming, worktrees, finishing-a-development-branch, which offers a local
  merge), Trail of Bits' skills (CC-BY-SA 4.0, share-alike; a separate request if they are needed).

To update: copy the same files from a newer upstream commit, re-apply the two frontmatter removals, and update the
commit column.
