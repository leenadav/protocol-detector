# Per-task notes

Each task records itself here, in a file of its own, instead of editing a shared ledger (Lee, PRO-347,
2026-11-24). Two pull requests that each add a notes file touch different paths, so they never conflict.
`tools/build_ledgers.py` builds the generated "Recent work" sections of every lane brief (`migration/LANE-BRIEF.md`,
`docs/LANE-BRIEF-platform.md`, `docs/integration/LANE-BRIEF-culvert.md`, `research/LANE-BRIEF.md`) and of
`migration/STATUS.md` (all lanes), and the README/REVIEW-SCOPE test counts, from these files after merge.

## Format

`migration/notes/PRO-<n>.md`, one per Paperclip task:

```markdown
---
task: PRO-347
lane: platform
date: 2026-11-24
title: Shared ledgers generated from per-task notes
prs: 119
shas: 0123abc, 4567def
---
One paragraph: what changed and why, the evidence (gates with numbers), and what is left open.
```

- `task` matches the file name; `lane` is one of engine, platform, app-research, research-lab, culvert, qa, docs,
  security, hermes, deputy; `date` is `YYYY-MM-DD`; `title` at most 120 characters.
- `prs` and `shas` are optional comma-separated lists. The pull request that merged the note is read from git log,
  so leave `prs` empty when the number is not known yet. List the SHAs frozen for Codex in `shas`.
- The summary is one paragraph (no blank line), at most 1,200 characters, with no HTML comment markers.
- A later fix round on the same task edits its own note; nothing else edits it.

## Rules

- Never edit a section between the `BEGIN GENERATED` and `END GENERATED` markers. CI (`ledgers` job,
  `python3 -B tools/build_ledgers.py --check`) fails on a hand edit and prints the command that rebuilds them.
- A pull request does not run `--write`: its own note shows up as "behind" in CI, which passes, and the section is
  refreshed on `main` afterwards (the nightly `ledgers` workflow reports the exact patch).
- Preview locally with `python3 -B tools/build_ledgers.py --diff` (a full clone: `git fetch --unshallow`).
