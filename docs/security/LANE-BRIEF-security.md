# Lane brief: Security Reviewer (AppSec)

This lane finds, proves and verifies; the owning lanes fix (Engine: `go/`, `protocol_engine/`,
`protocol_adapters/`; Platform & CI: `.github/`, `tools/`). "Read-only" means no fixes to another lane's code
(CTO answer PRO-499). Audit documents next to this file and skip-marked reproducers are this lane's own output.

## Open audits

| Task | Document | Base | State |
|---|---|---|---|
| PRO-477 limits and counters | `LIMITS-AUDIT-PRO-477.md` | `main` `6c6d4dd` | SEC-LIM-1, -2, -6 fixed; 3, 4, 5, 7, 8, 9, 10 still skip |
| PRO-497 A14, 26/11 merge train | `A14-MERGE-TRAIN-PRO-497.md` | `main` `5cb35d2` | 5 fixes verified; SEC-SESS-2 (P2), SEC-SESS-3, SEC-KEY-2, SEC-LIM-11 (P3) |

## Fix verification

| ID | Fixed by | Verdict |
|---|---|---|
| SEC-LIM-1, -2, -6 | PRO-448 (#148), PRO-481 (#156) | FIXED (plain assertions) |
| SEC-LIM-3, -4, -5, -7, -8, -9, -10 | none visible | NOT FIXED (reproducers skip with the id) |
| SEC-SESS-1 | #124 | FIXED for unsettled states; residuals SEC-SESS-2, -3 |
| SEC-KEY-1 residual | #144, #150 | FIXED; residual SEC-KEY-2 |
| SEC-QUIC-1 sticky exhausted | #145 | FIXED |
| SEC-SESS-2, SEC-SESS-3 | pending | NOT FIXED (`analyzer.TestSecGap*` skip with the id) |
| SEC-KEY-2, SEC-LIM-11 | pending | NOT FIXED (code reading, no reproducer) |

A fix is verified when its `TestLimitGap*` or `TestSecGap*` test fails with "now reports its limit" / "is fixed",
the marker is removed in the same change, and the plain assertion passes.

## Frozen SHAs for Codex

| Task | Branch | SHA |
|---|---|---|
| PRO-497 | `claude/security-PRO-497-a14` | `962396d27761c38c5eac13eefe4cb4b4db06ea93` (report and reproducers) |
