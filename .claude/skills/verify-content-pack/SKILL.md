---
name: verify-content-pack
description: Content-pack check (lock and digest, application/host/risk ids, release history and rollback digests, the Python-free batch round trip). Run it before reporting done on any change to content, go/internal/content/ (pack.json, history.json, lock.json), tools/content_pack.py or migration/fixtures/content.json.
---

# verify-content-pack

Records pin a content release by version and digest, so a silent digest change, a broken rollback or a
duplicate id is a correctness bug (AGENTS.md, Code Review Rule 2). Run every step from the repository root.
Each step must exit 0. Use `set -o pipefail` whenever you pipe output.

## Steps and healthy output

| # | Command | Healthy output (PRO-411, release 2026.11.9) |
|---|---|---|
| 1 | `make content PYTHON=python3` | `content ok: release 2026.11.9 digest cdaa5993077d101a (544 applications, 442 host entries, 41 risks); 11 releases in go/internal/content/lock.json`, then (while the Python reference exists) `python content reference ok: ...` |
| 2 | `make content-pack PYTHON=python3` | `content pack ok: ...`, `content_pack self-test: ok (...)` and `content batch e2e: ok, 2026.11.9 -> 2026.12.0 (+3 applications) without protocol_engine/ or protocol_adapters/` with every step `exit 0` |
| 3 | `GOTOOLCHAIN=local GOPROXY=off GOWORK=off python3 -B tools/content_gate.py` | no `FAILED` line, `identifiers: no duplicate or conflicting id`, `Go content tests \`go test -count=1 ./internal/content/...\`: exit 0`, and exit 0 |

Since PRO-411 the Go side's files are the content source (`go/internal/content/pack.json`, `history.json`,
`lock.json`; docs/CONTENT-BATCHES.md), written only by `tools/content_pack.py`. Step 1 validates them and
recomputes every digest without the Python engine (and checks the frozen Python reference against its own lock
while it exists). Step 2 also adds the example batch in a Python-free copy of the tree and runs the content
checks and the Go content tests there; it needs the pinned Go (`go version` prints go1.27.4). Step 3 is the CI
`content pack` job.

## What a failure means

- A digest mismatch: content changed without a new release. Change a release only by adding a new version;
  never edit a published one or its digest.
- A history failure: an earlier release no longer reproduces its digest, or versions are out of numeric order
  (`2026.11.9` sorts before `2026.11.10`; compare per component, never as strings).
- A duplicate or conflicting id: two entries claim the same application, host or risk.
- Never weaken digest verification or the gate to get green.
