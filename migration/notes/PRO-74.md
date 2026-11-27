---
task: PRO-74
lane: platform
date: 2026-11-27
title: REVIEW.md: one review policy for Codex, Claude and agent reviewers
---
Adds REVIEW.md at the repository root, per the "AI in the PR review loop" play of Anthropic's AI-native SDLC playbook: three separate passes (bugs, security, compliance with the task and the AGENTS.md/CLAUDE.md rules), Important (P0/P1) versus Nit with at most 5 nits, the Codex automatic review posting Important only, and what not to report (generated files and locks, vendored go/vendor including x/crypto, anything a CI gate already enforces, intended limits, untouched pre-existing code). AGENTS.md "Review priorities" and "Code Review Rules" moved there unchanged in substance (rule 3 now names migration/STATUS.md on main); AGENTS.md keeps a short "Review guidelines" section that sends every reviewer to REVIEW.md, and REVIEW.md sends reviewers to REVIEW-SCOPE.md for the release focus, so each rule has one home. CLAUDE.md, SSDLC.md, docs/RULES.md and the platform lane brief point to the new file. Documentation only; no code, workflow or test change.
