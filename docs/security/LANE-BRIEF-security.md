# Lane brief: Security Reviewer (AppSec)

Read-only lane. It finds, proves and verifies; the owning lanes fix (Engine: `go/`, `protocol_engine/`,
`protocol_adapters/`; Platform & CI: `.github/`, `tools/`). Findings are recorded here and in the audit documents
next to this file, with the reproducing test when there is one.

## Open audits

| Task | Document | Base | State |
|---|---|---|---|
| PRO-477 limits and counters | `LIMITS-AUDIT-PRO-477.md` | `main` `6c6d4dd` | 10 gaps (SEC-LIM-1..10), skip-marked reproducers; fix tasks asked of Engine |
| PRO-523 A17 CI and supply-chain PRs #149 #155 #157 #158 #159 | `A17-ci-prs.md` | `main` `5cb35d2` | P0 0, P1 0, P2 0, P3 2 (SEC-CI-1, SEC-CI-2); P3 only, no FIX tasks required |

## Fix verification

| ID | Fixed by | Verdict |
|---|---|---|
| SEC-LIM-1..10 | pending | NOT FIXED (reproducers skip with the id) |
| SEC-CI-1, SEC-CI-2 | pending (Platform & CI, optional: P3) | NOT FIXED |

A fix is verified when its `TestLimitGap*` test fails with "now reports its limit", the marker is removed in
the same change, and the plain assertion passes.
