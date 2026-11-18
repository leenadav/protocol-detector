# Draft pull request: Go engine as the default backend (`claude/go-migration` → `main`)

Draft text only. The pull request is opened when Lee authorizes it; nothing here opens or merges it. The
merge-readiness checklist and the conflicts with `main` are in `migration/MERGE-READINESS.md`.

---

## Summary

The detector's engine now runs in Go, with the Python implementation kept as the reference and the
fallback. Every committed parity case (7,410) gives the same answer in both engines, records included, and all
88 protocol families meet the computed `parity-verified` rule. Go is the default backend wherever its binary
is installed; `--backend python` or `PROTODETECT_BACKEND=python` selects the reference.

## What changes

- **Go engine** (`go/`): reassembly and session tracking, every stream and datagram family, QUIC, DTLS, HTTP/2
  with HPACK, continuation, fingerprints, certificates, heuristics, signatures, App-ID and session records,
  key-log TLS decryption, offline `analyze`, live capture, the live control plane and the dashboard service.
- **Adapters and presentation**: backend selection, Go by default; the launcher starts `protodetect serve`.
- **Differential harness** (`migration/parity/`): committed cases with the reference's answers, replay
  through Go, family verification, adversarial suite, capture-level and control-plane differentials.
- **Content**: release 2026.11.5 (name-based entries from the research lane, batches A, B and B2: Microsoft 365,
  Copilot, Anthropic, Dropbox, Webex, OneDrive, Google Workspace, and the DeepSeek, Perplexity, Mistral and xAI
  API hosts apart from their chat apps); earlier releases reproduce the digests they were published with (C11).
- **Dependencies**: `golang.org/x/crypto` (key-log TLS decryption) is vendored in `go/vendor`; every Go build and
  test runs with `-mod=vendor`, so CI needs no module download (`GOPROXY=off`); `make go-vendor-check` fails when
  the vendor tree is out of sync with `go.mod`/`go.sum`.
- **Reference changes, each a recorded decision**: the CoAP profile held to RFC 7252 (F-ADV-1, both engines),
  the port-table cache keyed by port list, the content-digest rule for earlier releases.

## Evidence

| Gate | Result at the head |
|---|---|
| `make parity-go` | 7,410 of 7,410 cases match, 0 gaps, 0 approved deltas; 88 of 88 families parity-verified |
| parity-analyze, parity-decrypt, parity-live, parity-live-decrypt, schema-go, parity-control, parity-server | 0 differences |
| `make adversarial` | 4,041 cases, Go equals the reference on all; 1 known finding (F-ADV-1) |
| `make bench-gate` | allocations and retained bytes within budget; p99 per flow reported |
| `make check` | 856 Python tests and the repository gates |
| Go fuzzing | 25 targets in `make go-check` |

Benchmarks are local CPU work, not production end-to-end latency.

## Review

Frozen snapshots for Codex: `61fd45a`, `fdb90e2`, `68fb867`, `58a4701`, `9e51389`, `6b280a6`, `024163f`,
`12e1ed0`, `d1b63ee`, `baa07b9`, `aaa5a7e`, `93cbf2a`, `76e467a`, `6ab434d`, `7dcabb7` (migration/STATUS.md lists what each contains). No snapshot is approved
until a `CODEX_REVIEW_RESULT` names it.

## Known limits and open items

- D09: the first measurement on ISCX VPN-nonVPN 2016 (internal research evaluation only) is in
  `research/d09-iscx-vpn2016.md`; its findings (UDP OpenVPN and CoAP over-permissiveness, the TLS 1.2 cipher
  policy that invalidates identified sessions, and others) are post-merge, Go-only items in
  `migration/POST-MERGE-BACKLOG.md`.
- F-ADV-1: 0.030% of seeded random datagrams still pass as CoAP (from 0.200%); structurally conforming.
- Merge mechanics: 7 files conflict with `main` (CI workflow, Makefile, README, REVIEW-SCOPE, SSDLC and two
  generated files); MERGE-READINESS.md gives the plan for each, including `-mod=vendor` for main's
  `go-check-minimum`.
- Signature patterns outside RE2 and an external `--content` pack with `--content-version` are still answered
  by the reference.
- IPv6 transport and proxy integration remain out of scope.

## Merging

A merge commit, no rebase or force-push; conflicts as listed in MERGE-READINESS.md. After the merge the
fixtures are regenerated from the merged reference and every gate is re-run. No deployment follows from the
merge.
