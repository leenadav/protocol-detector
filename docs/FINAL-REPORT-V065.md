# Final report: the v0.65 architecture and security plan

Scope: every stage of docs/ARCHITECTURE-REVIEW-V065-EN.md (A01–A16) plus the port of the separately
published Mac v0.59 work, executed continuously under Lee's authorization relayed on 2026-11-06. Every
checkpoint is a pushed branch; each branch builds on the previous one, so `claude/v066-smarthome` is the
tip that contains everything. The detailed finding map with commands and remaining gaps is
docs/PROGRESS-V065.md; this report is the consolidated view.

## Checkpoints

| stage | branch | head | scope |
|---|---|---|---|
| 0 | `claude/v065-stage0` | `048c16a` | baseline record and reproductions (A02, A04, A07) |
| 1a | `claude/v065-stage1a` | `b07a9e5` | presentation under lint, fragile test fixed, `make presentation-test` |
| 1b | `claude/v065-stage1b` | `e7d84ce` | one engine source, `protocol_adapters` package, product packaging, build manifest |
| 1c | `claude/v065-stage1c` | `19e7219` | canonical CI runs the presentation suite; A04 shutdown-wiring regression |
| 2 | `claude/v065-stage2` | `9e3bceb` | versioned event envelope, bounded log with cursors, named retractions, replayable reducer |
| 3 | `claude/v065-stage3` | `87e7b58` | SessionCoordinator: one lifecycle owner, StreamDelta exactly-once deltas |
| 4 | `claude/v065-stage4` | `2417214` | incremental TLS decryption, retained reassembly tier, append-only key log, lazy allocation, aggregate budgets, typed states |
| 5 | `claude/v065-stage5` | `53a1c97` | layered App-ID view, identity basis and claims, one session view |
| 6 | `claude/v065-stage6` | `da26f8b` | bounded jobs and handler pool, side-effect-free status, run-scoped heartbeat, frontend store with run identity, browser tests |
| 7 | `claude/v065-stage7` | `22b1ffc` | signature indexes with benchmarks, protocol descriptors and inventory check, telemetry, corpus report |
| 8 | `claude/v065-stage8` | `81b1594` | key lifetime and canaries, path/privilege/API security tests, build identity, soak, installed-artifact check, release gate |
| v0.66 | `claude/v066-smarthome` | `a06f747` | Mac v0.59 smart-home LAN families and mDNS repairs as a distinct version |

## Findings

All sixteen findings are implemented and verified against their acceptance criteria; the honest limits are
listed with each in docs/PROGRESS-V065.md and summarized here.

- **A01** one source: engine and adapters in one package, the application imports it, a clean install runs
  replay, frontend contract and decryption from the wheel (stage 8 installed check). Limit: the application
  directory is shipped beside the wheel, not as a second distribution.
- **A02** incremental decryption: 0 records re-authenticated across unchanged status reads (was 5 full
  decryptions), key log read once (was 5×); late keys wake only waiting connections.
- **A03/A04** one owner: the coordinator owns reassembly deltas and lifecycle on every path; a no-FIN
  connection is finalized at stop on the decryption path (was never).
- **A05/A13** layered view with identity basis (`authenticated_plaintext`, `structural`,
  `configured_rule`, `client_assertion`, `none`) and claims; logs, table, drawer and export agree.
- **A06** versioned envelopes, revisions, named retractions, replay equals live.
- **A07** lazy Stream allocation (0 bytes per direction at creation, was 512 KiB), aggregate retention
  budget with counted rejections, bounded work slices, CPU limits in workers.
- **A08** bounded job runner and handler pool, 503/429 instead of queueing, side-effect-free status,
  run-scoped heartbeat, idempotent stop, server-enforced lifetime.
- **A09** typed decryption states and reason codes; a failed connection publishes nothing further; conflicts
  after FIN still retract.
- **A10** key provider lifetime and release, path authorization (regular file, owner, no symlink/FIFO/
  device), canaries over every output channel, no privilege changes, Host/Origin/token matrix. Limit: no
  memory zeroization promise; the token model is single-user.
- **A11** name and exact-value signature indexes, equivalence-tested, benchmarked at 100/1,000/4,096.
- **A12** protocol descriptors derived from the tables with a build-time inventory check and a standard
  per-family test template.
- **A14** one frontend store with run identity; a late response for an older run is dropped; refresh
  resumes; nothing in localStorage; hostile strings never execute (real-browser tests).
- **A15** counters and histograms across the component boundaries, time-to-verdict and stage timings,
  labelled-corpus report by family and input class, synthetic soak.
- **A16** whole-build digest in the manifest, health and launcher reuse check, key-log guards (make check +
  gitleaks rule), installed-artifact check, release gate. Limit: SBOM/attestation are produced by the
  release workflow owned by the CI/CD lane (notified to include the decryption lock).

## Verification record (final head `a06f747`)

Claude-executed in the cloud container (Linux, Python 3.13.16 and 3.9.25, Node 22 with Playwright and
bundled Chromium); synthetic in-memory traffic only; GitHub Actions does not start jobs on this repository
(account spending limit), so no Actions result is claimed.

| check | result |
|---|---|
| engine suite (`python3 -B -m unittest discover -q`) | 719 tests OK |
| presentation suite (`make presentation-test`) | 59 tests OK, browser tests included |
| `make check` (ruff, tests, pins, policy lint, coverage matrix, docs counts, manifest, presentation, inventory, key logs) | OK |
| Python 3.9 on the new modules (coordinator, events, layers, signature index, descriptors, template, v0.66) | OK |
| fuzz (`tools/fuzz_fixtures.py`, seeds 66–75) | ok, 22,900–23,800 cases each |
| behaviour diff vs v0.65 `1d1db29` | stages 1a–8: no differences; v0.66: 60 inputs, all explained in docs/BEHAVIOUR-DIFF-V066.md |
| security requirements (`tools/check_security_requirements.py`) | 70 rows, 0 failures |
| inventory (`tools/check_inventory.py`) | 88 families, 135 stream and 81 datagram fixtures |
| corpus (`tools/corpus_report.py`) | TP 1593, FN 0 |
| soak (`tools/soak.py`) | within budgets (docs/SOAK-V065.md) |
| installed artifact (`tools/installed_check.py`) | ok: wheel installed with the hash-pinned extra, engine from site-packages, presentation suite green |
| gitleaks 8.24.3 local | only the two known `__pycache__` false positives (untracked) |

## Coordination and process

- Commits as Lee Nadav with the session trailers; no PR was created; nothing merged, deployed or changed in
  repository settings; no secrets, captures or key logs committed.
- The CI/CD lane (session owner of `.github/workflows`) was told about the stage-1c presentation step, the
  shared `.gitleaks.toml` rule, the `make check` additions and the SBOM lock request; no workflow was edited
  by the engine lane after 1c.
- One `CODEX_REVIEW_REQUEST` for the whole range is posted on the engine mailbox (issue #2) for the final
  head; checkpoint reviews by Codex covered stage 1a (b07a9e5) earlier.

## What remains outside this plan

Packaging the application directory as its own distribution; SBOM/attestation changes in the release
workflow (CI/CD lane); any production capacity or latency claim (needs agreed hardware and SLOs); a
multi-user management plane (would need real authentication); sampled tracing.
