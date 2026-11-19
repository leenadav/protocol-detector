# Codex review packet: `claude/go-migration`

Documentation only (Lee approved, relayed by Hermes 2026-11-19). The aim is the smallest review that does not weaken it.

| | |
|---|---|
| Reviewed base | `dbe20f3` (`dbe20f30377dd9627391040827dd8c0c3d636ac5`), the last full independent review (issue #2 comment 6877159227, R1-R7) |
| Frozen review head | `50ce5c0` (`50ce5c0c3f8885c06ad25fda9474e931f767c1f7`); later commits are documentation (this packet) |
| Already reviewed inside the range | `e57d294..7afc8f6` (digest delta, no code finding); `framed/ldap.go` is byte-identical to `b0beb3a`, reviewed in 6946510458 (confirm the blob, skip it); `framed/gss.go` entry points inspected there too |
| Every frozen SHA | listed in `migration/STATUS.md` ("Frozen milestone SHAs"); all lie in `dbe20f3..50ce5c0` and are covered by the chunks below |
| Size | Tier 1: 30 chunks (chunk-43 is 34 lines), about 19063 changed lines; Tier 2: 13 chunks, about 7698; Tier 3: no review |
| CI/CD lane | its own packet: `claude/cicd-next` `3d9a40e`, `docs/review-packet/` (range `e927d44..ddc557d`, the lane's 9 commits, 5 chunks). It owns `.github/**`, `tools/workflows.lock.json` and the CI tools (`go_ci.py`, `check_go_drift.py`, `content_gate.py`, `merge_readiness.py`, `go_fuzz_long.py`, `perf_history.py`, `build_go_release.py`, `release_provenance.py`, `check_workflow_policy.py`); this packet leaves them out, except chunk-43 |
| Earlier CI/CD history in this range | the CI/CD lane checked every one of its 92 commits before `e927d44` against the 73 heads named in the 57 `CODEX_REVIEW_RESULT`s on issue #7 (`git merge-base --is-ancestor`). All are inside a reviewed snapshot except `b97adc8` (Dependabot pins, now its chunk-06) and `7e7835c` (a 5-line wording fix Codex asked for, its Tier 3). Being inside a reviewed snapshot does not prove every line was read; see its INDEX.md, "Coverage of earlier history" (`claude/cicd-next` `0a01368`) |

How to use it: take the chunks in the order below, one usage window at a time. Each brief is at most a page: what changed and why, questions to answer, what already ran (do not re-run it), the exact files and line ranges, and what is out of scope. Read the diff with the brief's exact command. Supporting tests are optional reading.

**Fix rounds**: a finding is fixed in a later commit, and its re-review is that fix diff only (`git diff <reviewed head> <fix head> -- <files>`), never the whole chunk again (rule recorded in `REVIEW-SCOPE.md`).

## Tiers

- **Tier 1, Codex must review**: code that parses untrusted traffic or captures, the Go engine on the Culvert/proxy path, crypto and key handling, the content-pack loader and its integrity checks, the parity/replay harness logic, and contract changes.
- **Tier 2, lower depth**: CLI, launcher, dashboard service, live control plane, presentation glue, test harnesses.
- **Tier 3, no Codex review**: covered by automated gates; see the table at the end and `EXCLUDE.md`.

## Suggested order and usage windows

Windows of up to about 2,200 changed lines (Tier 1 first, the most critical first). Roughly 10-14 tokens per changed line to read, so a window is about 25-30k tokens of diff plus the briefs.

- **Window 1** (about 2041 lines, tier 1): chunk-11, chunk-12, chunk-01
- **Window 2** (about 1925 lines, tier 1): chunk-03, chunk-20, chunk-21
- **Window 3** (about 1896 lines, tier 1): chunk-24, chunk-25, chunk-04
- **Window 4** (about 1574 lines, tier 1): chunk-05, chunk-02
- **Window 5** (about 1966 lines, tier 1): chunk-14, chunk-10, chunk-06
- **Window 6** (about 2005 lines, tier 1): chunk-07, chunk-09, chunk-08
- **Window 7** (about 1960 lines, tier 1): chunk-13, chunk-22, chunk-23
- **Window 8** (about 2125 lines, tier 1): chunk-16, chunk-17, chunk-18, chunk-19
- **Window 9** (about 2170 lines, tier 1): chunk-15, chunk-26, chunk-27
- **Window 10** (plus chunk-43, 34 lines: this lane's two `ci.yml` edits, which neither packet's range otherwise covers) (about 1401 lines, tier 1): chunk-28, chunk-29
- **Window 11** (about 1715 lines, tier 2): chunk-39, chunk-40, chunk-41
- **Window 12** (about 1865 lines, tier 2): chunk-30, chunk-31, chunk-35
- **Window 13** (about 1953 lines, tier 2): chunk-38, chunk-36, chunk-33
- **Window 14** (about 2165 lines, tier 2): chunk-34, chunk-32, chunk-37, chunk-42

## Chunks

| Order | Chunk | Tier | Lines | Commits | Title | Why this priority |
|---|---|---|---|---|---|---|
| 1 | [chunk-11](chunk-11.md) | 1 | 701 | 17 | Stream inspector (engine/inspector.go) | every TCP byte on the proxy path passes here |
| 2 | [chunk-12](chunk-12.md) | 1 | 693 | 12 | Session analyzer (analyzer/analyzer.go) | session state, retirement and records for every flow |
| 3 | [chunk-01](chunk-01.md) | 1 | 647 | 6 | TLS, DTLS and certificate-continuation parsing (tlsx) | most common identification; nested lengths |
| 4 | [chunk-03](chunk-03.md) | 1 | 610 | 3 | QUIC Initial validation and CRYPTO assembly (quicx) | crypto on untrusted datagrams, CRYPTO assembly |
| 5 | [chunk-20](chunk-20.md) | 1 | 764 | 1 | TLS record decryption (decrypt/connection.go) | decryption of TLS records with key-log secrets |
| 6 | [chunk-21](chunk-21.md) | 1 | 551 | 4 | Key schedule and key-log capture | key derivation and secret handling |
| 7 | [chunk-24](chunk-24.md) | 1 | 785 | 14 | Content-pack loader, digests and C11 rollback (both engines) | integrity of the content that names applications |
| 8 | [chunk-25](chunk-25.md) | 1 | 491 | 20 | Parity comparator, family verification, reference fixes | the gate every other claim relies on |
| 9 | [chunk-04](chunk-04.md) | 1 | 620 | 5 | HPACK and HTTP/1 request line (hpack, textroute/http.go) |  |
| 10 | [chunk-05](chunk-05.md) | 1 | 753 | 5 | HTTP/2 route and SSH posture (textroute/http2.go, ssh.go) |  |
| 11 | [chunk-02](chunk-02.md) | 1 | 821 | 1 | X.509 leaf profile (x509x) |  |
| 12 | [chunk-14](chunk-14.md) | 1 | 708 | 5 | Capture and JSON input decoders (capture, ojson/bytes, pyjson) |  |
| 13 | [chunk-10](chunk-10.md) | 1 | 581 | 11 | TPKT/RDP, datagram dispatch, budgets and contracts |  |
| 14 | [chunk-06](chunk-06.md) | 1 | 677 | 3 | Continuation, heuristics and fingerprints |  |
| 15 | [chunk-07](chunk-07.md) | 1 | 732 | 6 | SMB1/SMB2 negotiation and small framed changes |  |
| 16 | [chunk-09](chunk-09.md) | 1 | 677 | 3 | LDAP and IKEv2 |  |
| 17 | [chunk-08](chunk-08.md) | 1 | 596 | 3 | GSS/SPNEGO token classifier |  |
| 18 | [chunk-13](chunk-13.md) | 1 | 559 | 14 | Session tracker, App-ID, session ids, replay |  |
| 19 | [chunk-22](chunk-22.md) | 1 | 605 | 4 | Key-log coordinator and live key-log tailing |  |
| 20 | [chunk-23](chunk-23.md) | 1 | 796 | 3 | Decryptor and the live decryption run |  |
| 21 | [chunk-16](chunk-16.md) | 1 | 578 | 2 | Signature patterns, part 1: the re._parser port |  |
| 22 | [chunk-17](chunk-17.md) | 1 | 574 | 2 | Signature patterns, part 2: compiling to RE2 |  |
| 23 | [chunk-18](chunk-18.md) | 1 | 481 | 2 | Signature documents, part 1: conditions and evaluation |  |
| 24 | [chunk-19](chunk-19.md) | 1 | 492 | 2 | Signature documents, part 2: loading and the set digest |  |
| 25 | [chunk-15](chunk-15.md) | 1 | 595 | 2 | ojson parser (control-plane JSON) |  |
| 26 | [chunk-26](chunk-26.md) | 1 | 819 | 10 | Case generator (parity/cases.py) |  |
| 27 | [chunk-27](chunk-27.md) | 1 | 756 | 7 | Capture-level differentials: analyze and decrypt |  |
| 28 | [chunk-28](chunk-28.md) | 1 | 688 | 4 | Control-plane and dashboard differentials |  |
| 29 | [chunk-29](chunk-29.md) | 1 | 713 | 5 | Live, schema and adversarial differentials |  |
| 29a | [chunk-43](chunk-43.md) | 1 | 34 | 2 | This lane's two edits to the CI workflow | supply chain; not in the CI/CD packet's range |
| 30 | [chunk-39](chunk-39.md) | 2 | 706 | 1 | Dashboard service: HTTP server |  |
| 31 | [chunk-40](chunk-40.md) | 2 | 601 | 1 | Dashboard service: connections and Python-text compatibility |  |
| 32 | [chunk-41](chunk-41.md) | 2 | 408 | 51 | Launcher, presentation glue, adapters and the Makefile |  |
| 33 | [chunk-30](chunk-30.md) | 2 | 563 | 10 | CLI commands, part 1 |  |
| 34 | [chunk-31](chunk-31.md) | 2 | 618 | 5 | CLI commands, part 2: live and serve |  |
| 35 | [chunk-35](chunk-35.md) | 2 | 684 | 3 | Job runner and live control state |  |
| 36 | [chunk-38](chunk-38.md) | 2 | 561 | 2 | Live control process and service worker |  |
| 37 | [chunk-36](chunk-36.md) | 2 | 716 | 1 | Event log and reducer |  |
| 38 | [chunk-33](chunk-33.md) | 2 | 676 | 4 | Live monitor and its outputs |  |
| 39 | [chunk-34](chunk-34.md) | 2 | 453 | 4 | Live run loop, job buffers and test frames |  |
| 40 | [chunk-32](chunk-32.md) | 2 | 638 | 4 | Offline analyze pipeline and telemetry |  |
| 41 | [chunk-37](chunk-37.md) | 2 | 674 | 1 | Policy engine |  |
| 42 | [chunk-42](chunk-42.md) | 2 | 400 | 2 | Benchmark and load harness |  |

Two chunks are single files slightly above the 800-line target (chunk-02 `x509.go`, 821; chunk-26 `cases.py`, 819); splitting them would cut a function in half. Exact file lists: each brief's "Exact scope" command, and `chunks.tsv` in this directory (generated from the same table).

## Tier 3: no Codex review, and the gate that covers each

| Group | Paths | Covering gate |
|---|---|---|
| docs and plans | `*.md` outside `migration/review-packet/`, `docs/**`, `migration/STATUS.md`, `migration/CONTRACTS.md`, ADRs | `tools/check_docs_counts.py` (counts), `make check`; read when a brief points at a section |
| research-derived content data | `protocol_engine/host_apps.py` entries, `protocol_engine/content.py` `HISTORY`/`_PRIOR_HOST_STATE`/`_RELEASED_COMPONENTS` tables, `protocol_engine/content_lock.json` | `make content` (`tools/check_content.py`: lock, history, C11), `make content-pack`, CI `content-pack` job, `test_content.py`; each entry is sourced in `research/apps/*.md` |
| generated content artefacts | `go/internal/content/pack.json`, `go/internal/content/history.json`, `migration/fixtures/content.json` | `make content-pack` (pack equals the export; history equals `migration/content_history.py`), Go `internal/content` tests |
| generated parity fixtures | `migration/fixtures/cases.json`, `migration/CAPABILITIES.json` | `make parity`, `make parity-go`, `make capabilities`, `verify_families.py --check` |
| generated test corpora | `go/internal/protocols/x509x/testdata/leaves.json`, other `testdata/**` | the package tests and fuzz targets that read them |
| vendored modules | `go/vendor/**`, `go/go.sum` | `make go-vendor-check` (re-vendor and diff), govulncheck in CI |
| build manifest | `presentation/SOURCE.json` | `tools/build_manifest.py --check` |
| Go unit tests and test data | `go/**/*_test.go` | they run in `make go-check`; each brief names the ones that answer its questions |
| Python unit tests | `test_*.py`, `presentation/tests/**` | `make check` on 3.9/3.11/3.13 in CI |
| CI/CD lane files | `.github/**`, `tools/workflows.lock.json`, `tools/go_ci.py`, `tools/check_go_drift.py`, `tools/check_workflow_*.py`, `tools/check_release_*.py`, `tools/check_product_sbom.py`, `tools/codeql_gate.py`, `tools/release_audit.py`, `tools/run_tests_strict.py`, `tools/scanner*`, `tools/scanners/**`, `tools/ui-test-deps/**` | the CI/CD lane's own packet (PR #30, merged into `main` as `7146ce1`); workflow lint, workflow policy, codeql |
| build metadata | `pyproject.toml`, `requirements-dev.txt`, `.gitignore`, `.pre-commit-config.yaml` | package build job (sdist, wheel, clean install), pip-audit in hash mode |
| Python test vectors | `protocol_adapters/protocol_fixtures.py` | `make check`, `make parity` (the vectors feed committed cases) |

## Evidence already produced (shared by all briefs)

- Local, 2026-11-19 at `50ce5c0`: `make go-check` and `make check` exit 0; `make parity-go` 7,430 of 7,430; 88 of 88 families parity-verified; `make adversarial` 4,041 cases, 0 failures; `make parity-server` 424 exchanges, 0 mismatched; every capture-level differential 0 differences.
- Hosted `ci` run 44558819343 at `50ce5c0`: Go engine job (135682138044) success; static analysis, security requirements, package build, supply chain, vulnerability audit and workflow lint success. The three tests jobs and the presentation job fail only in the presentation step: `GoServiceTests` is skipped without a built Go binary and the strict runner fails skips. The CI change that builds the binary first is in PR #30 (now on `main`), not on this branch. `codeql` run 44558818757 success.
- Author-reported, not independent validation (AGENTS.md).
