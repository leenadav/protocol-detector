# Lane brief: Security Reviewer (AppSec)

Read-only lane. It finds, proves and verifies; the owning lanes fix (Engine: `go/`, `protocol_engine/`,
`protocol_adapters/`; Platform & CI: `.github/`, `tools/`). Findings are recorded here and in the audit documents
next to this file, with the reproducing test when there is one.

## Open audits

| Task | Document | Base | State |
|---|---|---|---|
| PRO-477 limits and counters | `LIMITS-AUDIT-PRO-477.md` | `claude/go-migration` `f2e9916` | 10 gaps (SEC-LIM-1..10), skip-marked reproducers; fix tasks asked of Engine |

## Fix verification

| ID | Fixed by | Verdict |
|---|---|---|
| SEC-LIM-1..10 | pending | NOT FIXED (reproducers skip with the id) |

A fix is verified when its `TestLimitGap*` test fails with "now reports its limit", the marker is removed in
the same change, and the plain assertion passes.
