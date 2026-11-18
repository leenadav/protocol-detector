# Name-based patches for the Engine lane

Apply in order: A, then B, then (if confirmed) B2. Each patch's pinned-test notes (see batch A) apply
again with the new release values.

Each patch touches only the content source (`protocol_engine/host_apps.py`, `protocol_engine/content.py`) on
`claude/go-migration`. The generated files are rebuilt with the repository's own tools, not hand-edited.
This lane wrote and tested the patches in a scratch worktree; no branch other than `claude/app-research`
was changed.

## Batch A: `batch-a-name-based.patch`

- **Base**: `claude/go-migration` `6b280a610c08370e2b26a85544471ff21701637f` (`git apply --check`: clean).
- **Release**: proposes content release `2026.11.3` (dated 2026-11-18; the Engine lane sets the final dates
  and review text) with `_PRIOR_HOST_STATE["2026.11.2"]`, so `--content-version 2026.11.2` still rolls back.
- **Items**: microsoft-365, microsoft-copilot, github-copilot (names only), anthropic-claude (decided
  `anthropic-api` split), google-gemini (`notebook.google.com`), dropbox (domains, web fronts, `docsend`,
  `dropbox-sign`). The specs in `research/apps/` give each entry's primary source.
- **New application ids**: `ms-exchange-online-protection`, `anthropic-api`, `docsend`. Host entries
  431 → 434; applications 533 → 536.

### Regeneration after applying (the repository's own commands)

```bash
python3 -B tools/check_content.py --update
```

```bash
python3 -B tools/export_content.py --write migration/fixtures/content.json
```

```bash
cp migration/fixtures/content.json go/internal/content/pack.json
```

```bash
python3 -B migration/content_history.py --write go/internal/content/history.json
```

```bash
python3 -B migration/parity/cases.py --write migration/fixtures/cases.json
```

### Results in scratch (2026-11-18)

| Check | Result |
|---|---|
| `make content content-pack` | ok: release 2026.11.3, digest `d01a416cc693a7c1`, 536 applications, 434 host entries |
| Rollback | `history.json` release 2026.11.2 host catalog equals the original 2026.11.2 pack's host catalog exactly (host component `82e1abd2…`, unchanged) |
| Synthetic name vectors (all ten specs) | 47 vectors through `attribution_for_host`, 0 mismatches |
| `migration/parity/compare.py --backend python` | 7336 compared, 7336 matched |
| `make parity-go` | 7336 compared, 7336 matched; 79 of 88 families parity-verified |
| Regenerated cases vs committed | 939 cases differ only in `content.version`; 5 `tls-last-domain` cases change because the entries' last domain changed; the host-catalog sample shifted by 59 added and 41 removed `session/host-catalog/*` cases (the generator samples by position) |

### Pinned values the Engine lane must update (not done here: tests are product code)

- `test_content.py` `RollbackTests`: `len(new) == 431` → 434.
- `go/internal/content/digest_test.go`: `releaseVersion`, `releaseDigest`, `releasePackDigest` → the 2026.11.3 values.
- `go/internal/content/history_test.go`: the last release becomes `2026.11.3`. The pinned digests of the
  earlier releases change (see the observation below). 2026.11.2 keeps 431 hosts.

**Observation for the Engine lane (not a patch issue):** the historical release digests recomputed into
`history.json` move whenever the application catalog changes, even though each earlier release's host
catalog is reproduced exactly:

| Release | committed digest | after batch A |
|---|---|---|
| 2025.10.0 | `5d38359bcadf2419` | `86cc2f5ee272670d` |
| 2026.11.0 | `e4ba10037ef25ee7` | `db2714ad250a7919` |
| 2026.11.1 | `45ad7b6b7d7a027e` | `89ff08935bdf6a13` |

The cause is that `application_catalog` is current-only (CONTENT-GOVERNANCE.md, "Rollback": the application
catalog does not roll back), yet it is a component of every historical release digest. A record pinned to
`2026.11.1` with digest `45ad…` would no longer match a rollback to `2026.11.1`. This contradicts the
pinning contract (C11) and should be judged by the Engine lane. It occurs with any catalog change that adds
an application, not only with this batch.

## Batch B: `batch-b-name-based.patch` (applies on top of batch A)

- **Base**: `claude/go-migration` `6b280a6` with batch A applied. The chain A → B → B2 was checked with `git apply`: all three apply cleanly in order.
- **Release**: proposes `2026.11.4` with `_PRIOR_HOST_STATE["2026.11.3"]`.
- **Items**: google-workspace (`googledrive.com`, `sheets.`/`slides.google.com`, the two Drive data-export hosts → `google-drive`);
  onedrive-drive-personal-business (`skydrive.live.com`, `photos.live.com`, `storage.msn.com` → `ms-onedrive`, whose
  description becomes "consumer"); webex (`ciscospark.com`, `webexapis.com`, `webexcontent.com`, `ciscosparkcontent.com`);
  openai (web fronts `help.openai.com` → `openai-chatgpt`, `developers.openai.com` → `openai-platform`).
- No new application ids; host entries stay at 434.

| Check (scratch, 2026-11-18) | Result |
|---|---|
| `make content content-pack` | ok: release 2026.11.4, digest `4ee5fb4322c50c0c`, 536 applications, 434 host entries |
| Rollback to 2026.11.3 | the host catalog equals the batch-A pack's exactly |
| Name vectors | 26 batch-B vectors, 0 mismatches; the 47 batch-A vectors still pass |
| Python and Go parity (regenerated cases) | 7338 compared, 7338 matched, both backends |

## Batch B2: `batch-b2-api-split.patch` (on top of B; **pending Hermes's confirmation**)

Extends the decided Anthropic rule (own API id, consistent with OpenAI) to four more vendors whose API
documentation names an API host: `deepseek-api` (`api.deepseek.com`), `perplexity-api` (`api.perplexity.ai`),
`mistral-api` (`api.mistral.ai`), `xai-api` (`api.x.ai`, which covers `us.api.x.ai`). It proposes
release `2026.11.5`; the new entries' prior state is `None`.

| Check (scratch, 2026-11-18) | Result |
|---|---|
| `make content content-pack` | ok: release 2026.11.5, digest `84532ce4dea4dd22`, 540 applications, 438 host entries |
| Name vectors | 11 B2 vectors and the 47 batch-A vectors, 0 mismatches |
| Python and Go parity (regenerated cases) | 7342 compared, 7342 matched, both backends |

If B2 is not confirmed, skip it: B does not depend on it.

## Status of A, B and B2

Implemented by the Engine lane on `claude/go-migration`: A as content 2026.11.3 (`baa07b9`), B as 2026.11.4
(`6ab434d`), B2 as 2026.11.5 (`7dcabb7`). All were verified in the pack at `47b2743`, except
`notebook.google.com`, which the Engine lane left out of A (now in C). The C11 rollback-digest finding was fixed in
`d1b63ee`: earlier releases keep their published digests.

## Batch C: `batch-c-name-based.patch`

- **Base**: `claude/go-migration` `47b2743ea7d4cdcecb385e46737f00164e6089f3` (current head, 2026-11-18).
- **Release**: proposes `2026.11.6` with `_PRIOR_HOST_STATE["2026.11.5"]`, and records 2026.11.5 in
  `_RELEASED_COMPONENTS` exactly as `content_lock.json` states it (the C11 rule requires that before a new release locks).
- **Items**: `notebook.google.com` (re-sourced); Dropbox `www.` web-front variants; ngrok `ngrok-agent.com` and
  `update.equinox.io`; Cloudflare One Client exact API hosts on `cloudflare.com`; Atlassian `atl-paas.net`, `ss-inf.net`,
  `jira.com`, `teamworkgraph.com`; WeTransfer `we.tl` and six exact S3 bucket hosts. No new application ids.

| Check (scratch, 2026-11-18) | Result |
|---|---|
| `make content content-pack` | ok: release 2026.11.6, digest `d425b8adc87db36d`, 540 applications, 438 host entries |
| Rollback to 2026.11.5 | the host catalog equals the head pack's; release digest `39150de086799d99` equals the published one; all earlier release digests unchanged |
| Name vectors | 31, 0 mismatches |
| Python and Go parity (regenerated cases) | 7418 compared, 7418 matched, both backends; 88 of 88 families parity-verified |
| `test_content.py` | 12 tests OK |
| Go `internal/content` tests | fail only on pinned values: `digest_test.go` `releaseVersion`/`releaseDigest`/`releasePackDigest` → `2026.11.6` / `d425b8adc87db36d` / `db8378c3128f7c51a6cd91e6920e60e3ea29b1b8c0a5b99afe7e942e57102d75`; `history_test.go` gains `2026.11.5` (`39150de086799d99`, 438 hosts) and 2026.11.6 as last |
