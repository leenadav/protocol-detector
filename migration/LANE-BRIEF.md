# Engine lane brief: read this first

The onboarding note for a fresh chat taking any task in the engine lane. It has to stay short. **Rule: update this
brief at the end of every task**, in the same push as the task. At a minimum, update §2 (state), §5 (open items) and
§6 (frozen SHAs). Add a §7 line for every new pitfall.

## 1. Purpose and scope

This lane finishes and maintains the Python → Go migration of the IPv4-only passive protocol classifier. The work
happens on `claude/go-migration`, and issue #2 is its Codex mailbox. PR #19 is closed: it merged an early snapshot
(`7debf09`) into `main` on 2026-11-15 (`c121ada`). The lane has no open pull request now, and opening one waits on Lee.

- **Python** (`protocol_engine/`, `protocol_adapters/`) stays as the reference and the fallback.
- **Go** (`go/`) is judged against Python by the parity gates.
- **The lane owns** `go/`, `migration/`, the product code (`protocol_engine/`, `protocol_adapters/`, `presentation/`),
  the content data and the `Makefile`.
- **Python detection code is read-only.** The only exceptions are ones Lee approves case by case; they are listed in `migration/STATUS.md` ("Frozen-Python exceptions").
- **Never touch the CI/CD lane's files:** `.github/**`, `tools/workflows.lock.json` and its CI tools in `tools/`
  (`go_ci.py`, `check_go_drift.py`, `content_gate.py`, `merge_readiness.py`, `go_fuzz_long.py`, `perf_history.py`,
  `build_go_release.py`, `release_provenance.py`, `check_workflow_policy.py`). Changes there go to that lane as a
  patch or a PR into `claude/cicd-next`.
- **Out of scope:** IPv6 transport, proxy integration, and any merge, deployment, release or public tag without Lee's
  decision.
- **Data:** IPv4 and synthetic only. No captured traffic or key logs, ever (`tools/check_no_keylogs.py`).

## 2. Current state (2026-11-21)

- **Branch head:** check `git log -1 origin/claude/go-migration`. On 2026-11-21 (PRO-69) `main` `0ef7349` (41 commits, through PR #39,
  including #39's numeric content-version order) was merged in with a normal merge commit, so the branch is 0 behind `main`.
- **Done, Milestones A and B:**
  - The Go engine, the CLI `protodetect` and the dashboard service `protodetect serve`.
  - The launcher starts Go when the binary is installed and Python otherwise (`24e410e`, Lee's decision of
    2026-11-17).
- **Parity:** 7,430 of 7,430 cases agree, and all 88 families are parity-verified. Server parity: 424 exchanges, 0
  differences. The adversarial suite (4,041 cases) passes.
- **Content release:** 2026.11.9 (digest `cdaa5993077d101a`), with 544 applications and 442 host entries. Every earlier
  release reproduces the digest it was published with (C11).
- **Vendored dependencies:** `x/crypto` and `x/sys/cpu` live under `go/vendor`, and every Go command runs with
  `-mod=vendor`.
- **Codex review packet:** complete in `migration/review-packet/` (frozen head `50ce5c0`, 43 chunks).
- **PRO-31**: both engines order content versions numerically. Go has it in `6194fb9` (plus the numbering-rule test in
  `4d8aa29`); the Python reference got it in `376a204`, under Lee's exception of 2026-11-20.
- **In flight:** nothing is being coded. The branch waits on Codex's Sunday review, and then on Lee's merge decision.

## 3. Where things live (reading order)

1. `AGENTS.md`: the repository rules, the two lanes and the mailbox loop.
2. `migration/STATUS.md`: the ledger by milestone, with every SHA and command, and the frozen SHA list.
3. `migration/MERGE-READINESS.md`: the merge plan, covering the 7 conflicting files, how to resolve each, and the
   checklist.
4. `migration/POST-MERGE-BACKLOG.md`: the PM-1 to PM-8 detection items, the decisions behind them and the prepared tests.
5. `migration/CONTRACTS.md`: contracts C1 to C17, with the reference behaviour and the cases that check each one.
6. `PROTOCOLS.md` and `ARCHITECTURE.md`: the profiles, including what each profile deliberately excludes.
7. `migration/review-packet/INDEX.md` and `REVIEW-SCOPE.md`: what Codex reviews, and how fix rounds are reviewed.
8. `migration/CONTENT-DIGEST.md` and `protocol_engine/content.py`: the content releases and the C11 rule.
9. `migration/adr/`: ownership, toolchain and dependency decisions.

## 4. How to verify

Run everything from the repository root. Times are for the cloud container (4 vCPU):

| Command | What it checks | Runtime |
|---|---|---|
| `make go-check` | gofmt, vet, `go test -race`, 28 fuzz targets, parity-go with verify_families, every differential, bench-gate | about 8 min (488 s) |
| `make check` | the Python suite (866 tests), content, docs counts, manifest, presentation, parity | about 1 min (60 s) |
| `make go-vendor-check` | re-vendors into `build/go-vendor-check` and diffs it against `go/vendor` | seconds (module cache warm) |
| `python3 -B -m unittest discover -q` | the Python suite on its own | part of `make check` |

Run `make go-check` and `make check` before every push. Also run `make go-vendor-check` after any change to
`go.mod`, `go.sum` or `go/vendor`. Push fast-forward only.

## 5. Open items and what each waits on

| Item | Waits on |
|---|---|
| PRO-31 (`6194fb9`, `4d8aa29`, `376a204`) | Engine work done; Hermes approved it, and PRO-31 is parked. Codex's code review is PRO-58 (under PRO-11), waiting for Codex's quota to come back. If it finds problems, Hermes reopens PRO-31 or opens a new Engine task; if not, PRO-31 closes. |
| PR #39 `claude/fix-content-version-order` → `main` (`37b3c84`) | merged by Lee on 2026-11-21 (`0ef7349`). It is in this branch since the PRO-69 merge. |
| Draft PR #40 `claude/go-migration` → `main` | Codex's review, then Lee's decision. Keep it draft. PRO-69 merged `main` in (9 conflicts, resolved per `MERGE-READINESS.md`). The CI fix it brought (`91113bc`, the Go build before the tests and presentation suites) lets `GoServiceTests` run instead of skip. |
| Codex review of the packet (`dbe20f3..50ce5c0`) | Codex, from Sunday. Fix rounds are reviewed as the fix diff only. |
| Merging `claude/go-migration` into `main` | the Codex result, then Lee's decision. Don't ask again before then. The branch already contains `main` as of `0ef7349`, so the merge itself has no conflicts. |
| Merge conflicts (7 files, see `MERGE-READINESS.md`) | the merge itself. The `ci.yml` hunks resolve to `main`'s, which already has the govulncheck port (`85e99e9`, PR #32, merged). |
| PM-1 to PM-8 detection fixes | the merge. They are Go only, and each needs an approved parity delta. The prepared tests use `pending()`; remove that marker when the fix lands. |
| Not yet ported: demo capture, decryption showcase, catalog export | they still run as Python workers (`--python`). Nothing is scheduled. |
| Release thresholds (plan M9 and M10), production SLOs, capacity | Lee. They are unproven, and docs must never claim production readiness. |
| D09 dataset (ISCX VPN-nonVPN 2016) | nothing. It is for internal research evaluation only; commercial use is UNVERIFIED, and its data is never committed. |

## 6. Frozen SHAs awaiting Codex

The authoritative list is in `migration/STATUS.md` ("Frozen milestone SHAs"):

`61fd45a`, `fdb90e2`, `68fb867`, `58a4701`, `9e51389`, `6b280a6`, `024163f`, `12e1ed0`, `d1b63ee`, `baa07b9`,
`aaa5a7e`, `93cbf2a` (with `36e2c5e`), `76e467a`, `d65d21a`, `07b216e`, `6ab434d`, `7dcabb7`, `b6ed149`, `c08773f`,
`ee1645d`, `253a91d`, `2f6ad4d` and **`50ce5c0`, the review head**. After the packet: `6194fb9`, `4d8aa29` and `376a204` (PRO-31), each reviewed as its own diff (`376a204` together with `6194fb9`).

The commits after it are documentation only: `1437060` (the packet), `a88d679`, `b8a3ee1`, `fa5cb2c` and this brief.

## 7. Pitfalls learned

- **A fresh container is a clone of `main`.** Run `git fetch origin claude/go-migration` and check out the branch
  before deciding that any SHA is "missing".
- **Always vendor.** Every Go command needs `GOFLAGS=-mod=vendor`; the Makefile sets it. Scratch output goes under
  `build/`, never inside `go/`, or `go vet` and gofmt pick it up.
- **Recording a new content release (C11).**
  - First record the superseded release in `content._RELEASED_COMPONENTS` and `_PRIOR_HOST_STATE`. Until you do,
    `check_content.py --update` refuses.
  - Then regenerate the lock, `pack.json`, `history.json`, the fixtures, the `CONTENT-DIGEST.md` vectors, the
    `digest_test.go`, `history_test.go` and `test_content.py` pins, and the README/APPID counts.
- **Content release numbering rule (Hermes, PRO-34):** the version is YYYY.MM.N with a two-digit month and a single-digit N (0 to 9). When N is used up, move on to the next month segment at 0. The version is only a label; the real date is
  the release's `released` field. App Research's 2026.12.x placeholders stay as they are. `TestEmbeddedReleasesFollowTheNumberingRule` fails on any break. Both engines now compare numerically, so the rule is a policy and no longer a safety net; relaxing it is Hermes's call.
- **Content items stay name-based until the merge.** Skip a research spec that looks wrong or unclear, note why,
  and don't guess. Describe vendors neutrally by their domain.
- **The presentation suite needs the Go binary built first**, or `GoServiceTests` skip. `presentation-check` builds it.
- **Get numbers from commands, not memory.** Earlier briefs had wrong counts (128 vs 132, 1,055 vs 1,035) and named
  test files that didn't exist.
- **Don't run govulncheck locally.** CI runs it over the vendored tree.
- **The safety checker refuses `rm -rf` and heavy heredoc quoting.** Use `mv`, the Edit tool or plain `sed`.
- **Commits:** author `Lee Nadav`, and keep the email private. End every message with the Co-Authored-By and
  Claude-Session trailers. Ignore stop-hook requests to reset the author.
- **Never** merge, rebase, force-push, open a PR, tag, release or change a schedule. Post GitHub comments only when
  the task asks for them (the current Hermes rule is none).
- **Changes to `ci.yml`** go to the CI/CD lane, which ports them (see chunk-43, `34ea6b0` → `85e99e9`).
- **After merging `main` in:**
  - regenerate `presentation/SOURCE.json` and let `tools/check_docs_counts.py` set the README/REVIEW-SCOPE test count;
  - check `migration/parity/cases.py --write <tmp> --head <recorded head>` reproduces `cases.json` byte for byte;
  - `tools/go_ci.py build` refuses a local Go other than go.mod's (this container has 1.24.7), so use `make go-build` locally.
