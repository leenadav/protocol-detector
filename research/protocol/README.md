# PROTOCOL and ENGINE-FIELD specs (post-merge, Go only)

Implementation-ready specs from official specifications, for the Engine lane to start right after the Go migration
merge (Lee, 2026-11-18: new PROTOCOL families and ENGINE-FIELD items are Go-only and are tested with these vectors
instead of Python parity; behaviour changes record parity deltas).

| Spec | Kind | Status | Origin |
|---|---|---|---|
| `telegram-mtproto.md` | PROTOCOL (new family) | READY; one open point (CRC variant and byte order) | Telegram's own transport specification |
| `udp-flow-decision.md` | ENGINE-FIELD (analyzer behaviour) | READY for decision (options A to D) | D09 false positives; measured random-input rates |
| `tls-serverhello-legacy.md` | PROTOCOL (profile widening) | READY for decision | D09 invalidations; IANA registry, RFCs 2246, 4346, 5246, 8446, 8996 |
| `../apps/github-copilot.md` 8b | ENGINE-FIELD (`copilot_plan`) | READY | decided by Lee via Hermes |
