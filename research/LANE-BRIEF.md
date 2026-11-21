# Lane brief: application research (read this first)

Updated 2026-11-21 (PRO-92: batch M, live rounds 3 and 4 merged, batch N from PRO-121). **Rule: update this brief at the end of every task**, then run the gates, push, and report the SHA.

## 1. Purpose and scope

The lane researches how applications show up on the wire (server names, ports, protocol facts), for the passive
protocol detector that is embedded in the Culvert SWG in visibility-only mode. Outputs: specs, synthetic test vectors,
and content-pack patches for the Engine lane.

- **Owns**: `research/` on branch `claude/app-research` only. Commits are authored as Lee Nadav and pushed
  fast-forward only (no merge, rebase or force-push).
- **Never touches**: product code, tests, fixtures, workflows, `go/`, `migration/`, `.github/`, or other branches.
  Product changes go to the Engine lane as patches in `research/patches/` via Hermes.
- **Reporting**: in chat to Hermes. No GitHub issues or comments, and no settings changes.
- **Main integration** (Lee, 2026-11-20, PRO-43): topic PRs to `main` that touch `research/` only. Each branches from
  `origin/main` under `claude/research-*` and checks out its paths from `claude/app-research`. PRs are ready for review,
  one topic each, small enough to review in about 15 minutes, and must pass `ci gate (all jobs)`. This lane never merges,
  closes, comments on or approves a PR: Lee merges after Hermes reviews. `d09-iscx-vpn2016.md` stays off main while CIC
  commercial use is `UNVERIFIED`. Routine
  research and format questions are decided here; only product, legal or licensing questions go to Lee or Hermes.
- **Sources**: primary only (RFCs, IANA, vendor docs and feeds). Nothing is copied from nDPI, Wireshark, Suricata,
  Snort or OpenAppID. Unsourced claims are marked `UNVERIFIED`, unreadable sources `SOURCE BLOCKED`. Never guess.

## 2. Current state

- Branch head: see `git log -1` (this brief is updated in each task's own commit).
- 79 specs in `research/apps/` (registry `research/apps.json`), all retrofitted to method v2 (sections 9 to 11).
- Content patches A, B, B2 and C are implemented by Engine (releases 2026.11.3 to 2026.11.6). D, E, F, G, H, I, R, L,
  J, K, M and N are proposed and **not yet implemented** (placeholder releases up to `2026.12.9`; J = vendor pages for rows 12 to 18, PRO-35; K = dependency pass 2, PRO-36;
  M = six enterprise apps from vendor network pages, PRO-92; N = Sophos, DocuSign, Twilio, Snowflake, PRO-121).
- D09 (ISCX VPN-nonVPN 2016) has been measured twice: per-family, per-application, and email server names.
- Live verification rounds 1 to 4 are in (run by Hermes): of 444 spec names, 301 live (137 with a certificate naming an organisation),
  20 suffixes verified by probe, 88 apexes with no address and no probe, 22 TLS failures (not removal), 2 NXDOMAIN, 61 CDN-fronted,
  3 ECH-capable, 30 offer h3; 11 (batch N) await round 5.
- In flight, run by Hermes on the server: live round 5 and the ranking run.

## 3. Where things live (reading order)

1. `research/README.md`: method, source policy, confidence scale (N3/N2/N1/S/U, plus the L and O inputs), spec format.
2. `research/backlog.md`: the queue (READY/PARTIAL/BLOCKED/IN-PROGRESS/DONE), decisions, retrofit summary, ranking.
3. `research/patches/README.md`: every patch with its base, release, digests and checks, plus the Engine amendments.
4. `research/apps/*.md`: one spec per app; `research/apps.json` maps specs to ids and web URLs.
5. `research/d09-iscx-vpn2016.md` and `research/datasets.md` (licences, LEE-1, ranking sources).
6. `research/protocol/`: post-merge PROTOCOL and ENGINE-FIELD specs (`app-attributes.md`, `window-overflow.md`, UDP rule, TLS widening, Telegram).
7. `research/tools/`: `retrofit_specs.py`, `live_verify.py`, `observe_web.js`, `recheck_sources.py`, `rank_domains.py`.
   Their inputs and outputs are `live-hosts*.txt`, `live-results-*.tsv` (a later round overrides an earlier one per name), `web-urls.txt`, `observations/`,
   `source-state.json` and `app-domains.json`.
8. `research/blocked-urls.md` and `research/allowlist-requests.md`: unreadable pages and network requests.

## 4. How to verify (gates)

Run them from the repository root. The scratch checkout below goes in this session's scratchpad.

```bash
python3 -B -m unittest discover -q
```
(about 30 s; expect `OK` on this branch, which has no product changes.)

```bash
git worktree add --detach "$SCRATCH/gm" c08773fc8da8d210c8e66d67190f883e608d7bb4 && cd "$SCRATCH/gm" && for p in d e f g h i; do git apply ~-/research/patches/batch-$p-name-based.patch; done && git apply ~-/research/patches/batch-r-retrofit.patch ~-/research/patches/batch-l-live-results.patch ~-/research/patches/batch-j-relayed-rows-12-18.patch ~-/research/patches/batch-k-dependency-pass2.patch ~-/research/patches/batch-m-name-based.patch ~-/research/patches/batch-n-name-based.patch && python3 -B tools/check_content.py --update
```
(a few seconds; expect `release 2026.12.9 digest 80ecb5542510f862 (462 host entries)`.)

```bash
python3 -B research/tools/retrofit_specs.py "$SCRATCH/gm" research/observations/pass1-2026-11-19.json,research/observations/pass2-2026-11-20.tsv
```
(under 1 s; expect `"specs": 79`, `"vectors": 1153`, `"fail": []` and 4 `gaps`. Add `--write` to regenerate the spec sections.)

Per-patch content checks, run in the scratch checkout and taking about 2 minutes: `make content content-pack`,
`python3 -B migration/parity/compare.py --backend python`, `make parity-go`, and the unit tests there. The only
expected failure is the pinned host count in `test_content.py`, which the Engine lane updates.

## 5. Open items and what each waits on

| Item | Waits on |
|---|---|
| Patches D to I, L, J, K, M, N (and R) | the Engine lane, via Hermes (post-review); patch F needs `prisma-access` dropped first (both its names are NXDOMAIN) |
| Main-integration PRs #42 to #53 (PRO-43) | #42, #43, #52, #53 merged; the rest open, CI gate green; Lee merges after Hermes review (this lane never merges or comments) |
| Batches M and N to `main` | not opened: Hermes schedules them after review (PRO-92) |
| Patch R | decided 2026-11-21 (round 2): `copilot.com` only; stack R, L, J, K rebuilt |
| Live rounds 1 to 5 | 1 to 4 done and merged into section 9 (`live-results-2026-11-20*.tsv`, `live-results-2026-11-21-r3.tsv` 69 names, `-r4.tsv` 66 names; relayed in full PRO-117/PRO-121): every name cited by the batch M and earlier specs has a result. Round 5 (`live-hosts-r5.txt`, 12 names, batch N) waits on a Hermes run |
| Dependency pass 2 | done (2026-11-20, `observations/pass2-2026-11-20.tsv`, patch K); next run adds the 4 batch J URLs |
| Ranking (CrUX, Majestic Million) | licences PASS LEE-1 (2026-11-20, `datasets.md`); waits on the Hermes server run of `rank_domains.py` (Majestic CSV; CrUX via BigQuery) |
| Window-overflow item (`protocol/window-overflow.md`) | decided (Hermes, PRO-30, 2026-11-20); Engine implements post-merge, Go only, with an approved parity delta |
| Content version ordering | Engine: numeric comparison plus a regression test, then renumber the placeholders |
| Blocked vendor pages | WhatsApp and Hugging Face (no official page known). Rows 19 to 23, 28 and 29 (ServiceNow, Workday, CrowdStrike, SentinelOne, Cisco Secure Client, Egnyte, GlobalProtect) stay blocked (sign-in, bot challenge or JavaScript-only, per Research Lab, PRO-108). Rows 24 to 27 resolved in batch N; DocuSign's domain list is still incomplete |
| Culvert field data for prioritisation | not available yet (placeholder in the backlog) |

## 6. Frozen SHAs awaiting Codex

None. This lane does not use the Codex mailbox (Lee, via Hermes: no GitHub communication). Its output is reviewed by
the Engine lane when a patch is implemented. The frozen bases it depends on are `claude/go-migration`
`c08773fc8da8d210c8e66d67190f883e608d7bb4` (the base of the D-to-N stack) and `2fd94529e29020eba4096e890567655b78185d1e`
(the first D09 build).

## 7. Pitfalls learned

- The egress proxy **re-terminates TLS**, and direct DNS is **not permitted** (one query was sent; the next was denied).
  Live DNS and TLS run on the Hermes server; never work around either.
- The allowlist is capped at about 130 hosts: further additions are rejected. Server-side runs replace them. Pages behind
  bot challenges are never bypassed; they go to `blocked-urls.md`.
- Content versions compare **as strings**: `2026.11.10` sorts before `2026.11.9` and breaks rollback. Hence the
  `2026.12.x` placeholders.
- C11: record the previous release's components (`_RELEASED_COMPONENTS`) before locking a new one. An entry cannot be
  emptied or deleted: the parity case generator indexes `domains[0]`, and rollback cannot restore a deleted entry.
- A certificate proves a vendor owns a name only when its subject organisation names the vendor; domain-validated
  certificates (Let's Encrypt, Google Trust, Amazon) prove the name only.
- "No address" is **not dead**: many catalog names are bare suffixes. Only NXDOMAIN (RFC 8020) supports removal.
- CI runs `ruff check .` over the whole repository (including `research/tools`) and gitleaks over full history: run
  both before a PR (pinned ruff from `requirements-dev.txt`; gitleaks built from `tools/scanners`).
- Look-alike vectors must be built on the registrable part (`xanydesk.com`, not `xnet.anydesk.com`).
- Only the **text of an answer** reaches this lane. Paperclip comment ids, attached documents and paths on the Hermes server
  (`/home/hermes/...`) do not: data must be pasted into the answer body (TSV in chunks of at most 25 rows, header first),
  or committed to a branch this lane can fetch. A relay can be cut off: check row counts against the stated total.
- Compute every number before writing it; read back paraphrases against the source. Earlier slips (invented counts, an
  overstated licence) were caught this way.
- D09 data: one archive at a time, delete it afterwards, and commit aggregates only. `NonVPN-PCAPs-02.zip` needs
  `unzip -p` (Deflate64).
- Tag hosts of consumer apps (pixels, analytics) load on unrelated pages: move them to a vendor-level id (decision 4).
  Main-site names they also call (`www.linkedin.com`) stay a residual false positive.
- A hyphenated look-alike is its own registrable domain: `browser-intake-datadoghq.eu` is not under `datadoghq.eu`. Check
  each documented name with `attribution_for_host` before assuming a suffix covers it.
- Shared CDN, sign-in and telemetry hosts are dependencies, never the app. Observed-only names enter the catalog only
  at `O`, and only with certificate or official-page ownership.
