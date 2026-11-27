# Code review policy

This file is the single source of truth for how a pull request in this repository is reviewed. It applies to
every reviewer: the Codex automatic review on GitHub (P0/P1 only), Claude Code reviews and `/code-review`, the
QA Reviewer (Codex) mailbox rounds, the Security Reviewer, and Hermes's review stage on the board.
`AGENTS.md` ("Review guidelines") and `CLAUDE.md` point here; neither repeats these rules.

Source: the "AI in the PR review loop" play of Anthropic's *The AI-native SDLC playbook* (Aug 2026,
claude.com/resources/articles/the-ai-native-sdlc-playbook): the reviewer gets an explicit policy, runs separate
passes, reports few and important findings, and leaves to CI what CI already enforces.

## Before you start

1. Read the task the pull request names: its body links a Paperclip issue (`PRO-<n>`) and states what changed,
   the verification, the risk and what is out of scope. That is the plan pass 3 checks against.
2. Read what the pull request changes: `git diff <base>...<head>`. A fix round is reviewed as the fix diff only
   (`git diff <reviewed head> <fix head> -- <files of the finding>`), never as a re-review of the whole change.
3. For coverage and focus, read `REVIEW-SCOPE.md` (the current release's review focus and the families it
   covers), `PROTOCOLS.md` and `ARCHITECTURE.md`. For a review packet, read its `INDEX.md` and `EXCLUDE.md`
   (`migration/review-packet/` for the engine, `docs/review-packet/` for CI/CD).

## Three passes

Run them separately, in this order. Each pass looks only for its own kind of problem.

### Pass 1: bugs (correctness)

Report reproducible correctness bugs, with file/line, the triggering input or sequence, the observable
consequence and the severity. Identify missing regression tests. A passing suite is not proof of correctness.

- A positive classification must satisfy its documented structural profile. Trace malformed lengths, truncated
  inputs, ambiguity, explicit hints and fragmentation. Hints select candidates; they never establish identity.
- Reassembly feeds each contiguous byte once. Conflicting retained overlaps invalidate classification before new
  bytes are admitted. Check wraparound, gaps, FIN/timeout/loss ordering, and both traffic directions.
- The Go engine is judged against the Python reference: a Go change that moves a verdict without a matching
  parity case or approved reference change is a bug.

### Pass 2: security

- Parsing and reassembly respect the configured byte, count and depth budgets. Trace attacker-controlled CPU and
  allocation amplification, not only average performance. Do not recommend optimizing a hot path without
  preserving its error semantics.
- No payload, credential or opaque identifier is emitted as application identity. TLS ClientHello metadata is
  an offer, not authenticated application identity.
- Apply the Code Review Rules below for parsers, content packs and CI.

### Pass 3: compliance with the task and the repository rules

- The change does what the task asked, and nothing outside it: one topic, no unrelated files, no placeholder or
  TODO left for this task.
- It keeps the rules of `AGENTS.md` and `CLAUDE.md`: the Python reference stays frozen (rule 3 below); no test
  is skipped, weakened or deleted to get green (the only skip is a dated quarantine, `AGENTS.md`, "Flaky tests and
  verify skills"); no security check is disabled; a lane edits only its own files; no history rewrite.
- A behaviour change comes with a test that fails without it.

## Code Review Rules

Each rule names what to flag, why, and the safe path. A finding under these rules is Important.

1. **Parsers of untrusted traffic** (`go/`, `protocol_engine/`, `protocol_adapters/`).
   - Flag: an allocation, slice or read sized by a length or count field before it
     is checked against the bytes present and the configured budget; a panic,
     index error or uncaught exception on malformed or truncated input; a loop or
     recursion with no byte, count, depth or work limit.
   - Why: every byte is attacker-controlled, so these become memory or CPU
     amplification, or a crash of the classifier.
   - Safe path: bound the read first, then return the existing errors. In Go that
     is `errs.Exceeded` / `parsing.Budget` and `parsing.Malformed`; in Python,
     `BudgetError` and `ParseError` (`protocol_engine/parsers.py`). A failure must
     never become a positive result.
2. **Content packs** (`protocol_engine/content.py`, `content_lock.json`,
   `go/internal/content/`, `migration/fixtures/content.json`).
   - Flag: anything that weakens digest verification (or any signature check
     added later); a rollback that stops reproducing an earlier release's
     published digest (C11); version ordering that is not numeric per component
     (2026.11.9 sorts before 2026.11.10).
   - Why: records pin a content release, and a silent digest or ordering change
     breaks that pin or makes an older pack look newer.
   - Safe path: keep `make content` and `tools/content_gate.py` passing. Change
     a release only by adding a new version.
3. **The Python reference** (product code outside `go/` and `migration/`).
   - Flag: any edit not in the Lee-approved list. That list is "Frozen-Python
     exceptions" in `migration/STATUS.md`: the launchers, the parity case
     generator, the CoAP profile, and the C11 and numeric version compare in
     `content.py`, among the others it records.
   - Why: Go is judged against the Python reference, so an unapproved change
     moves the parity target.
   - Safe path: make the change in Go, or get Lee's approval and record it in that list.
4. **CI** (`.github/`, `tools/workflows.lock.json`).
   - Flag: an action not pinned to a full commit SHA; a token permission
     broadened beyond today's set (workflow level `contents: read`; job grants
     only where `tools/check_workflow_policy.py` allows them, writes only in the
     CodeQL upload and the `publish-release.yml` publish job);
     `pull_request_target`; untrusted event text expanded inside `run:`.
   - Why: these hand repository write access or secrets to code from a pull request.
   - Safe path: `make workflow-policy` and its lock. A change the policy cannot
     express goes to the CI/CD lane.

## Severity: Important or Nit

- **Important** (P0/P1): a reproducible bug in pass 1, any pass-2 security problem, a Code Review Rules
  violation, or a pass-3 breach (scope creep, an unapproved Python edit, a weakened or skipped test, a disabled
  check, an expired quarantine). P0 is a crash, a wrong positive classification, a budget bypass, an identity
  leak or a token or secret exposure; P1 is any other Important finding. Each one gives file/line, the
  triggering input or sequence, the consequence, and the missing test.
- **Nit**: a real but minor issue that does not change behaviour or safety: an unclear name, a misleading
  comment, a missing edge-case test for a path that is already safe, a small simplification.
- **At most 5 nits per review.** Keep the five that matter most and drop the rest. Never label a nit Important
  to get it read.
- The Codex automatic review on GitHub posts Important (P0/P1) findings only, no nits.
- A review with no Important finding says so in one line. That closes the round; it is not an approval or a
  merge decision (only Lee merges).

## What not to report

- **Generated files**: `tools/workflows.lock.json`, `tools/scanner_config.lock.json`,
  `migration/fixtures/**`, `go/internal/content/pack.json` and `history.json`,
  `protocol_engine/content_lock.json`, `migration/CAPABILITIES.json`, `presentation/SOURCE.json`, `**/testdata/**`,
  and every section between `BEGIN GENERATED` and `END GENERATED` markers. Review the generator and its gate
  instead (`migration/review-packet/EXCLUDE.md` names the gate for each).
- **Vendored code**: `go/vendor/**` (`golang.org/x/crypto`, `x/sys`, `pgregory.net/rapid`), vendored unchanged and
  checked by `make go-vendor-check`, the CI `go-vendor` job and govulncheck. Report a vendoring change only if
  `go/go.mod` or `go/vendor/modules.txt` adds or upgrades a module without saying why.
- **What CI already enforces**: lint, formatting and static analysis (ruff, bandit, gofmt, go vet, golangci-lint, staticcheck and gosec
  against `tools/golint/baseline.json`), action pins and
  workflow policy (`make workflow-policy`), documentation counts (`tools/check_docs_counts.py`), the content lock,
  parity, coverage floors, allocation budgets, licences, CodeQL, osv-scan, pip-audit and govulncheck, the gitleaks secret scan and the
  ledgers check. A red required check speaks for itself; report it only when a change hides or weakens it.
- **Style and taste**: wording, ordering and formatting choices that break no rule.
- **Intended limits** (`AGENTS.md`, "Intended limits", and the exclusions in `PROTOCOLS.md`): a profile that
  leaves out a documented feature, IPv6 transport, a full TCP stack. Report a contradiction between the code and
  its stated contract, not the exclusion itself.
- **Pre-existing problems** the pull request does not touch. Name one at most, marked pre-existing, when it
  is Important; it does not block this change.
