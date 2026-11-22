---
name: verify-content-pack
description: Content-pack check (lock and digest, application/host/risk ids, release history and rollback digests, Python/Go content parity). Run it before reporting done on any change to content, content_lock.json, protocol_engine/content.py, go/internal/content/ or migration/fixtures/content.json.
---

# verify-content-pack

Records pin a content release by version and digest, so a silent digest change, a broken rollback or a
duplicate id is a correctness bug (AGENTS.md, Code Review Rule 2). Run every step from the repository root.
Each step must exit 0. Use `set -o pipefail` whenever you pipe output.

## Steps and healthy output

| # | Command | Healthy output (as of `claude/go-migration` `cdb385b`) |
|---|---|---|
| 1 | `make content PYTHON=python3` | `content ok: release 2026.11.9 (2026-11-19, reviewed 2026-11-19) digest cdaa5993077d101a; 11 releases, 442 host entries` |
| 2 | `make content-pack PYTHON=python3` | `content pack ok: release 2026.11.9 digest cdaa5993077d101a (544 applications, 442 host entries, 41 risks)` and `content history ok: earlier releases 2025.10.0, 2026.11.0 … 2026.11.8` |
| 3 | `GOTOOLCHAIN=local GOPROXY=off GOWORK=off python3 -B tools/content_gate.py` | no `FAILED` line, `identifiers: no duplicate or conflicting id`, `Go content parity \`go test -count=1 ./internal/content/...\`: exit 0`, and exit 0 |

Step 1 verifies `content_lock.json` against the content and the release history. Step 2 exports the pack and
checks that every earlier release still reproduces its published digest (the C11 rollback rule). Step 3 is the
CI `content pack` job: lock, history, ids and the Go loader's parity with the Python one. Step 3 needs the
pinned Go (`go version` prints go1.27.4) for its Go part; on a commit with no Go content pack it says
"No Go content pack on this commit" instead, which is healthy there.

## What a failure means

- A digest mismatch: content changed without a new release. Change a release only by adding a new version;
  never edit a published one or its digest.
- A history failure: an earlier release no longer reproduces its digest, or versions are out of numeric order
  (`2026.11.9` sorts before `2026.11.10`; compare per component, never as strings).
- A duplicate or conflicting id: two entries claim the same application, host or risk.
- Never weaken digest verification or the gate to get green.
