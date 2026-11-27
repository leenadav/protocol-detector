# Project rulebook

One place to look up every rule the project works by. Hebrew summary for the CEO: [RULES-HE.md](RULES-HE.md).

**How to read this file**

- Each rule has a source. A source is either a file in this repository (linked) or a decision recorded as
  `Lee, <date>`. Rules that are already documented elsewhere are summarised in one or two lines and linked; the
  full text stays in the linked file.
- `Lee, 2026-11-xx` means a decision of Lee Nadav (CEO) recorded by Hermes in the task PRO-230. That task lists
  the date as `2026-11-xx`; the exact date is **to be confirmed by Hermes** and filled in here. Dates that are
  given exactly are written as such.
- A rule with no source in the repository is marked *(not in repo)*. Its only source is the Lee decision above.
- Where two sources disagree, the conflict is listed in [section 7](#7-open-conflicts) and is **not** resolved here.
- Scope: docs only. This file records rules, it does not change them. No secrets, tokens, addresses or hostnames
  of private machines appear here.

## 1. Product scope

- **Goal.** A low-latency protocol and application detection Go library, embedded in the Culvert SWG/proxy. The
  host owns sockets, TLS, policy and forwarding; the detector does no I/O. *Source: Lee, 2026-11-xx.* Overview:
  [ARCHITECTURE.md](../ARCHITECTURE.md), [GO-ARCHITECTURE.md](GO-ARCHITECTURE.md).
- **Detection only in Culvert.** The detector's verdict is not enforced by the detector itself. *Source: Lee,
  2026-11-xx.* Proxy integration is the Culvert Integration lane's work ([AGENTS.md](../AGENTS.md), "Intended limits").
- **Evidence, not identity.** SNI, ALPN, port and fingerprints are evidence, never authenticated identity; a
  TLS ClientHello is an offer. *Source: Lee, 2026-11-xx; [REVIEW.md](../REVIEW.md), "Pass 2: security".*
- **Inputs.** IPv4 and synthetic test inputs. No external or user traffic is captured, and captured traffic is
  never committed. *Source: [AGENTS.md](../AGENTS.md) (header); [CONTRIBUTING.md](../CONTRIBUTING.md), "Before you start"; Lee, 2026-11-xx.*
- **Upstream Culvert is never pushed to**: no push, PR, merge or release on KidCarmi/Culvert. *Source: Lee, 2026-11-xx.*

## 2. Python and Go

- **Python is the frozen behavioural reference.** Edits are allowed only if Lee approved them and the edit is in
  the list in [migration/STATUS.md](../migration/STATUS.md) ("Frozen-Python exceptions"). *Source: Lee, 2026-11-xx;
  [AGENTS.md](../AGENTS.md) rule 3.* The two lists differ: see [section 7](#7-open-conflicts).
- **Go migration merged.** PR #40 (`claude/go-migration`) merged to `main` as merge commit `82552df`, 2026-11-22.
  *Source: git history of `main`.*
- **New protocol families are Go-only.** They are tested with research's synthetic vectors, not with Python
  parity. *Source: Lee, 2026-11-xx.*
- **Open question, not decided.** Whether to retire Python entirely and use golden files instead of a live
  reference. *Decision owner: Lee.* *Source: Lee, 2026-11-xx.*
- **Go runs offline.** `GOPROXY=off`, `GOTOOLCHAIN=local`, dependencies vendored. *Source: [CLAUDE.md](../CLAUDE.md), "Conventions that matter".*

## 3. Changes, PRs and merging

- **Many small PRs.** One concern per PR, reviewable in about 15 minutes. *Source: Lee, 2026-11-xx; [CONTRIBUTING.md](../CONTRIBUTING.md), "Pull requests"; [CLAUDE.md](../CLAUDE.md), "Big or mixed PRs".*
- **Every merge to main is a click by Lee**, except the auto-merge rule below. *Source: Lee, 2026-11-xx.* See [section 7](#7-open-conflicts), item 1.
- **Auto-merge without a click.** Allowed only when all of these hold: the PR is approved; the check `ci gate (all jobs)` is green; and every changed file is either Markdown (and not under `.github/`, `.claude/`, nor `CLAUDE.md` or `AGENTS.md`) or `research/` data (with no `.py`, `.sh` or `.go` file). *Source: Lee, 2026-11-22.*
- **Merge commits only.** No rebase, no force-push, no squash of others' work. Stacked PRs are retargeted to `main` when their base lands. *Source: Lee, 2026-11-xx; [CLAUDE.md](../CLAUDE.md), "Rewriting history"; [docs/LANE-BRIEF-platform.md](LANE-BRIEF-platform.md) ("never rebase").*
- **Commits are authored as Lee Nadav.** *Source: Lee, 2026-11-xx.*
- **Merge gate.** No open P0 or P1 security finding, and every check green. *Source: Lee, 2026-11-xx.*
- **One-time exception for #40 (2026-11-22).** Only P0 blocked. The P1 (SEC-HTTP-1) also exists in the Python
  reference, and Culvert only detects. *Source: Lee, 2026-11-22.* This exception ends with #40.
- **Review threads are resolved before merging.** The `main` ruleset requires it. Lanes do not comment on GitHub; Hermes resolves the threads. *Source: Lee, 2026-11-xx; [SSDLC.md](../SSDLC.md), "Codex review comments".*
- **Never weaken a check.** A deleted, skipped or relaxed test, or a lowered threshold, is sent back. Quarantine of an intermittent test is the only allowed skip, with a deadline ([AGENTS.md](../AGENTS.md), "Flaky tests and verify skills"). *Source: Lee, 2026-11-xx; [CLAUDE.md](../CLAUDE.md), "Things Claude gets wrong".*

## 4. Security findings

- **Severity sets priority.** P0 and P1 are critical, P2 high, P3 low; routing is automatic. *Source: Lee, 2026-11-xx.* Codex automatic review flags only P0/P1 ([REVIEW.md](../REVIEW.md), "Code Review Rules"). The automatic routing itself is *(not in repo)*.
- **A critical issue must start within 1 hour, or it is escalated.** *Source: Lee, 2026-11-xx.* *(not in repo)*
- **Small P3 fixes in one lane are batched** into one task and one PR. *Source: Lee, 2026-11-xx.*
- **Every fix comes with a test that fails first.** *Source: Lee, 2026-11-xx; [CLAUDE.md](../CLAUDE.md), "Skills to use" (`test-driven-development`).*
- **Security issues go through [SECURITY.md](../SECURITY.md), not public issues.** *Source: [CONTRIBUTING.md](../CONTRIBUTING.md), last paragraph.*

## 5. Research and catalogue

- **Non-commercial datasets are not used.** *Source: Lee, 2026-11-xx.*
- **nDPI (LGPL) is for comparison only** and is never copied. *Source: Lee, 2026-11-xx.*
- **Licences.** Tools used only in tests may have any OSI licence. GPL and LGPL code never enters the product. A Go module with a forbidden, restricted or unidentified licence fails the build ([SSDLC.md](../SSDLC.md), `go-licenses`). *Source: Lee, 2026-11-xx.*
- **Estimate long fetches first.** Before any fetch expected to take over 15 minutes, measure and estimate it. Over 1 hour: find a faster source. *Source: Lee, 2026-11-xx. (not in repo)*
- **Content releases are versioned and dated.** A catalogue edit always arrives as a new `Release` in `HISTORY` with dates and a note. Old releases are not edited. *Source: [docs/CONTENT-GOVERNANCE.md](CONTENT-GOVERNANCE.md); [AGENTS.md](../AGENTS.md) rule 2.*
- **Release notes for content** are in [RELEASE-NOTES-CONTENT.md](RELEASE-NOTES-CONTENT.md) and are derived from the diff between releases, never invented. *Source: Docs lane standing rules (issued by Hermes); the release history in [docs/CONTENT-GOVERNANCE.md](CONTENT-GOVERNANCE.md).*

## 6. How the agents work

- **The board is the only channel for messages.** GitHub is not used for messages. *Source: Lee, 2026-11-xx.* See [section 7](#7-open-conflicts), item 3.
- **Organisation.** Lee (CEO) > Hermes (CTO) > Deputy (an automation with no model) > Team Lead (Sonnet) > workers. After the merge the Team Lead splits into Engineering and Research leads. *Source: Lee, 2026-11-xx.*
- **Every run ends with one status.** One of `DONE`, `BLOCKED`, `DECISION` or `QUEUE-EMPTY`. `DECISION` is only for Lee's product, legal, cost or security choices. Waiting on a job is not `BLOCKED`: end the run with `WAIT-FOR-PID` or `WAIT-FOR`. *Source: Lee, 2026-11-xx.*
- **A DONE report on a fix carries** the full commit SHA, the PR number and the test counts. *Source: Lee, 2026-11-xx.*
- **Codex reviews run one at a time**, by risk tier, and stop at 85% of the weekly quota. At most three rounds per task. *Source: Lee, 2026-11-xx; [AGENTS.md](../AGENTS.md), "Codex review-and-repair workflow" (three rounds); [SSDLC.md](../SSDLC.md), CI/CD review loop.*
- **Quota saver mode** starts at 55% of the weekly Claude quota: non-critical lanes pause and resume after the reset. *Source: Lee, 2026-11-xx. (not in repo)*
- **Budgets.** Free options first. Paid API only for Claude, with hard caps. *Source: Lee, 2026-11-xx. (not in repo)*
- **Forbidden without Lee's explicit approval:** merging PRs, deploying, force-push, rebase or history rewrite, changing `main`, closing PRs, GitHub comments, pushing to the upstream Culvert repo, changing repository settings or branch protection, creating tags or releases. Agents never handle credentials. *Source: Paperclip standing rules for all lanes (issued by Hermes); [AGENTS.md](../AGENTS.md), "Intended limits" (merge and deployment out of scope without Lee's decision).*
- **Knowledge lives in the repository.** A new session reads the lane brief first ([docs/LANE-BRIEF-platform.md](LANE-BRIEF-platform.md), [migration/LANE-BRIEF.md](../migration/LANE-BRIEF.md)) and records its decisions in repo docs, not in chat. *Source: Paperclip standing rules; the lane briefs.*

## 7. Open conflicts

Not resolved here. Each item needs a decision by Lee (or Hermes, where noted).

1. **Who merges.** [CLAUDE.md](../CLAUDE.md) says "Lee merges; agents never merge", and [AGENTS.md](../AGENTS.md) "Intended limits" keeps a merge out of scope without Lee's decision. The 2026-11-22 auto-merge rule (section 3) allows a merge without a click for Markdown-only and `research/` data PRs. The two are not reconciled in the files. *Owner: Lee.*
2. **Which Python changes are exempt.** [AGENTS.md](../AGENTS.md) rule 3 names four exceptions: launchers, the case generator, CoAP, and C11 with the numeric version compare in `content.py`. [migration/STATUS.md](../migration/STATUS.md) "Frozen-Python exceptions" lists 11 rows, which also cover the per-carrier port tables, the Go backend default for offline and live analysis, the reused-tuple and generation-counter changes in `coordinator.py` and `events.py`, and the content releases 2026.11.1 to 2026.11.9. The STATUS list is the one that section 2 points to. *Owner: Lee (which list is the authority); Docs to align AGENTS.md after that.* The STATUS heading also still says "on this branch" (`claude/go-migration`), which is no longer accurate after the merge.
3. **Channels.** The rule "GitHub is not used for messages" (section 6) conflicts with the process in [AGENTS.md](../AGENTS.md) "Codex review-and-repair workflow", which uses GitHub issues #2 and #7 as review mailboxes and asks lanes to post `CODEX_REVIEW_REQUEST` comments on pull requests. [SSDLC.md](../SSDLC.md) also refers to Codex comments on pull requests. *Owner: Lee.*
4. **Product language and runtime.** [CONTRIBUTING.md](../CONTRIBUTING.md) and the header of [AGENTS.md](../AGENTS.md) describe a Python 3.9 product with no runtime dependencies. Section 1 describes a Go library, and the migration is merged. Both files are stale in this respect; which statement the product now carries is for Lee to confirm before the files are changed. *Owner: Lee.*

## How to add a rule

Hermes posts each new rule as a comment on the standing issue **"חוקי הפרויקט — עדכונים"**, with the date and the person who set it. Docs folds the new rules into this file and into [RULES-HE.md](RULES-HE.md), one PR per batch. A rule without a dated source (`Lee, <date>` or a repository file) is not added.
