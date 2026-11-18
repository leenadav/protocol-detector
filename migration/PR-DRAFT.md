# Draft pull request: Go engine as the default backend (`claude/go-migration` → `main`)

Draft text only. The pull request is opened when Lee authorizes it; nothing here opens or merges it. The
merge-readiness checklist and the conflicts with `main` are in `migration/MERGE-READINESS.md`.

---

## Summary

The detector's engine now runs in Go, with the Python implementation kept as the reference and the
fallback. Every committed parity case (7,404) gives the same answer in both engines, records included, and all
88 protocol families meet the computed `parity-verified` rule. Go is the default backend wherever its binary
is installed; `--backend python` or `PROTODETECT_BACKEND=python` selects the reference.

## What changes

- **Go engine** (`go/`): reassembly and session tracking, every stream and datagram family, QUIC, DTLS, HTTP/2
  with HPACK, continuation, fingerprints, certificates, heuristics, signatures, App-ID and session records,
  key-log TLS decryption, offline `analyze`, live capture, the live control plane and the dashboard service.
- **Adapters and presentation**: backend selection, Go by default; the launcher starts `protodetect serve`.
- **Differential harness** (`migration/parity/`): committed cases with the reference's answers, replay
  through Go, family verification, adversarial suite, capture-level and control-plane differentials.
- **Content**: release 2026.11.3 (name-based entries from the research lane); earlier releases reproduce the
  digests they were published with (C11).
- **Reference changes, each a recorded decision**: the CoAP profile held to RFC 7252 (F-ADV-1, both engines),
  the port-table cache keyed by port list, the content-digest rule for earlier releases.

## Evidence

| Gate | Result at the head |
|---|---|
| `make parity-go` | 7,404 of 7,404 cases match, 0 gaps, 0 approved deltas; 88 of 88 families parity-verified |
| parity-analyze, parity-decrypt, parity-live, parity-live-decrypt, schema-go, parity-control, parity-server | 0 differences |
| `make adversarial` | 4,041 cases, Go equals the reference on all; 1 known finding (F-ADV-1) |
| `make bench-gate` | allocations and retained bytes within budget; p99 per flow reported |
| `make check` | 856 Python tests and the repository gates |
| Go fuzzing | 25 targets in `make go-check` |

Benchmarks are local CPU work, not production end-to-end latency.

## Review

Frozen snapshots for Codex: `61fd45a`, `fdb90e2`, `68fb867`, `58a4701`, `9e51389`, `6b280a6`, `024163f`,
`12e1ed0`, `d1b63ee`, `baa07b9`, `aaa5a7e`, `93cbf2a` (migration/STATUS.md lists what each contains). No snapshot is approved
until a `CODEX_REVIEW_RESULT` names it.

## Known limits and open items

- D09 (independent labelled corpus) is blocked on input: a release blocker, not claimed here.
- F-ADV-1: 0.030% of seeded random datagrams still pass as CoAP (from 0.200%); structurally conforming.
- `go/go.mod` requires `golang.org/x/crypto`; main's Go jobs run with `GOPROXY=off`. To be settled before the
  merge (MERGE-READINESS.md).
- Signature patterns outside RE2 and an external `--content` pack with `--content-version` are still answered
  by the reference.
- IPv6 transport and proxy integration remain out of scope.

## Merging

A merge commit, no rebase or force-push; conflicts as listed in MERGE-READINESS.md. After the merge the
fixtures are regenerated from the merged reference and every gate is re-run. No deployment follows from the
merge.
