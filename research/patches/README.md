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

## Batch D: `batch-d-name-based.patch` (applies on top of batch C)

- **Base**: `claude/go-migration` `bc65e50` with batch C applied and locked (C's release 2026.11.6, digest
  `d425b8adc87db36d`, the same as on the earlier base). The chain C → D on `bc65e50` was checked with `git apply`.
- **Release**: proposes `2026.11.7`, with `_PRIOR_HOST_STATE["2026.11.6"]` and 2026.11.6 recorded in
  `_RELEASED_COMPONENTS` from C's lock (`host_catalog` `f463fce8…`).
- **New application ids**: `ms-defender-endpoint`, `ms-intune`, `icloud-private-relay`. Host entries 438 → 441;
  applications 540 → 543.
- **Extended entries**: `icloud`, `cursor`, `1password`, `gitlab`, `docker-hub`, `okta`, `notion`, `goto-meeting`,
  `zscaler`, `figma`, `netskope`.

| Check (scratch, 2026-11-19) | Result |
|---|---|
| `make content content-pack` | ok: release 2026.11.7, digest `b2ccbc7842dcffcc`, 543 applications, 441 host entries |
| Earlier release digests | all unchanged (2026.11.6 stays `d425b8adc87db36d`) |
| Name vectors | 45, 0 mismatches |
| Python and Go parity (regenerated cases) | 7427 compared, 7427 matched, both backends; 88 of 88 families |
| Pinned values to update | `test_content.py` host count 438 → 441; Go `digest_test.go` → `2026.11.7` / `b2ccbc7842dcffcc` / `b2250e213c8d7a61e3585d3969a58c42a0fad242bcbb0fe94e2576f803082e24`; `history_test.go` gains 2026.11.6 (`d425b8adc87db36d`, 438 hosts) |

## Batch E: `batch-e-name-based.patch` (applies on top of batch D)

- **Base**: `bc65e50` + C + D (each locked in turn); chain C → D → E checked with `git apply`. Release `2026.11.8`, with
  `_PRIOR_HOST_STATE["2026.11.7"]` and 2026.11.7 recorded in `_RELEASED_COMPONENTS` from D's lock.
- **Items**: Chrome Remote Desktop (`remotedesktop-pa.googleapis.com`, exact), Bitwarden (`bitwarden.net`,
  `bitwarden.eu`, `btwrdn.com`, `btwrdn.co`). No new ids; host entries stay at 441.

| Check (scratch, 2026-11-19) | Result |
|---|---|
| `make content content-pack` | ok: release 2026.11.8, digest `804f727352bc61e0` |
| Earlier release digests | unchanged (2026.11.7 stays `b2ccbc7842dcffcc`) |
| Name vectors | 8, 0 mismatches |
| Python and Go parity | 7429/7429, both backends |
| Go pinned values | `digest_test.go` → `2026.11.8` / `804f727352bc61e0` / `9a429d97705aca652fb8d456e6d4cae423fcae905008b08de61fa0cddfc84052`; `history_test.go` gains 2026.11.7 (`b2ccbc7842dcffcc`, 441 hosts) |

## Rebase onto `c08773f` (2026-11-19): D, E and F

The Engine lane implemented batch C as content 2026.11.6 (`b6ed149`) with its own release text, so D, E and F were
rebuilt on `claude/go-migration` `c08773f`. Each script now inserts its release at the end of `HISTORY` instead of
anchoring on the previous release's text. **Apply in order D → E → F on `c08773f`** (checked with `git apply`).

| Release | Batch | Digest (identical to the earlier build on `bc65e50`) |
|---|---|---|
| 2026.11.7 | D | `b2ccbc7842dcffcc` |
| 2026.11.8 | E | `804f727352bc61e0` |
| 2026.11.9 | F | `4a2fb63069bd33e5` |

Checks on the rebased state (scratch): content gates ok; earlier release digests unchanged against `c08773f`;
Python and Go parity 7434/7434, 88 of 88 families. Pinned values after F: `test_content.py` host count 438 → 444;
Go `digest_test.go` → `2026.11.9` / `4a2fb63069bd33e5` / `8137a3317ade8c38ad024c7108cd98557e200c222345b4dd5c95962311b3210d`;
`history_test.go` gains 2026.11.6 to 2026.11.8.

## Batch F: `batch-f-name-based.patch` (after E)

New ids `prisma-access` (`epm.gpcloudservice.com`, `filter.paloaltonetworks.com`), `jetbrains-ai` (`api.jetbrains.ai`),
`loom` (`loom.com`, `loom-media-production.s3-accelerate.amazonaws.com`). Release 2026.11.9. 11 vectors, 0 mismatches.

## Batch G: `batch-g-name-based.patch` (after F)

Pages relayed by Hermes (2026-11-19), plus the Gemini API reference read by this lane. Base: `c08773f` plus D, E
and F (apply D → E → F → G; `git apply --check` clean on F).

- New ids: `logmein-resolve` (`gotoresolve.com`, `gotoresolveuserfiles.com`, `helpdesk.me`,
  `gtre-remoteexecution-userfiles-prod-eu.azureedge.net`) and `google-gemini-api` (`generativelanguage.googleapis.com`).
- Extended: `signal` (+`signal.group`, `signal.link`, `signal.me`, `signal.tube`), `splashtop` (+`api.splashtop.eu`,
  `api.splashtop.nr`, `api.splashtop.cn`, `relay.splashtop.cn`), `miro` (+`miro-apps.com`, `mirostatic.com`,
  `onlinewhiteboard.com`, `realtimeboard.com`, `webwhiteboard.com`), `canva` (+`canvacode.com`, `canva-apps.com`,
  `canva.link`, `canva.ai`), `duo-security` (web front `www.duo.com`).
- Release: placeholder **`2026.12.1`**, not `2026.11.10`: `content.py` orders versions as strings, so `2026.11.10`
  sorts before `2026.11.9` and breaks rollback (see `backlog.md`, batch G version note). `_PRIOR_HOST_STATE["2026.11.9"]`
  and `_RELEASED_COMPONENTS["2026.11.9"]` are included.

| Check | Result |
|---|---|
| `make content content-pack` | ok: release 2026.12.1, digest `0a516c639a61b39f`, 548 applications, 446 host entries |
| Pack file | `go/internal/content/pack.json` sha256 `2a8b6f9e649ea4d031397d682e6a1c6f3683247840d6c9c3c5e9c767e6ddf7a2` |
| Rollback | `history.json` release 2026.11.9 host catalog equals the batch F pack's host catalog exactly |
| Synthetic name vectors | 40 through `attribution_for_host`, all as expected |
| `migration/parity/compare.py --backend python` | 7441 compared, 7441 matched |
| `make parity-go` | 7441 matched; 88 of 88 families parity-verified |
| `python3 -B -m unittest discover -q` | 856 tests, 1 expected failure: pinned host count in `test_content.py` (438 → 446 after D to G) |

Pinned values for the Engine lane: `test_content.py` host count 446; Go `digest_test.go` release values for the
final version number; `history_test.go` last release.

## Batch H: `batch-h-name-based.patch` (after G)

Base: `c08773f` plus D, E, F and G (apply D → E → F → G → H). Release placeholder **`2026.12.2`** (same version note
as G), with `_PRIOR_HOST_STATE["2026.12.1"]` and `_RELEASED_COMPONENTS["2026.12.1"]`.

- New id: `citrix-cloud` (`cloud.com`, `citrix.com`, `citrixworkspacesapi.net`, `citrixnetworkapi.net`, `nssvc.net`,
  `xendesktop.net`, `netscalergateway.net`, exact `discovery.cem.cloud.us` and four `*-vus-storage-endpoint.azureedge.net`
  hosts; web fronts `citrix.com`, `www.citrix.com`).
- Extended: `ms-update` (+`do.dsp.mp.microsoft.com`, `tsfe.trafficshaping.dsp.mp.microsoft.com`, `emdl.ws.microsoft.com`),
  `adobe-cloud` (+14 Adobe-hosted domains), `postman` (+`postman.co`, `pstmn.io`).

| Check | Result |
|---|---|
| `make content content-pack` | ok: release 2026.12.2, digest `49b988a98a739ec0`, 549 applications, 447 host entries |
| Pack file | `go/internal/content/pack.json` sha256 `978d1640ff62569803c926e93940f1178e21b59bb40726c14b7e97cdb1d067d6` |
| Rollback | `history.json` release 2026.12.1 host catalog equals the batch G pack's host catalog exactly |
| Synthetic name vectors | 33 through `attribution_for_host`, all as expected |
| `migration/parity/compare.py --backend python` | 7445 compared, 7445 matched |
| `make parity-go` | 7445 matched; 88 of 88 families parity-verified |
| `python3 -B -m unittest discover -q` | 1 expected failure: pinned host count in `test_content.py` (438 → 447 after D to H) |

## Batch I: `batch-i-name-based.patch` (after H)

Base: `c08773f` plus D to H (apply D → E → F → G → H → I). Placeholder release **`2026.12.3`**, with
`_PRIOR_HOST_STATE["2026.12.2"]` and `_RELEASED_COMPONENTS["2026.12.2"]`.

- New ids: `ms-virtual-desktop` (`wvd.microsoft.com`, `wvd.azure.us`, `windows.cloud.microsoft`, `windows.static.microsoft`,
  `infra.windows365.microsoft.com`, `infra.windows365.microsoft.us`, exact `wvdportalstorageblob.blob.core.windows.net`) and
  `amazon-workspaces` (`amazonworkspaces.com`, `highlander.aws.a2z.com`).

| Check | Result |
|---|---|
| `make content content-pack` | ok: release 2026.12.3, digest `8174ed45fd771e40`, 551 applications, 449 host entries |
| Pack file | `go/internal/content/pack.json` sha256 `afcccc04450e184fa098a6bb8b6bd472e7ccd225ac18e9430c00113b8a1db906` |
| Rollback | `history.json` release 2026.12.2 host catalog equals the batch H pack's host catalog exactly |
| Synthetic name vectors | 18 through `attribution_for_host`, all as expected |
| `migration/parity/compare.py --backend python` | 7449 compared, 7449 matched |
| `make parity-go` | 7449 matched; 88 of 88 families parity-verified |
| `python3 -B -m unittest discover -q` | 856 tests, 1 expected failure: pinned host count (438 → 449 after D to I) |

## Retrofit batch R: `batch-r-retrofit.patch` (after I)

Method v2 retrofit (dependency mapping, 2026-11-19). **Status 2026-11-21: DECIDED** from live round 2 (certificate organisation, Hermes decision 3), and the patch is **rebuilt
with `copilot.com` only**: its certificate's subject organisation is Microsoft Corporation. `boxcdn.net` and `gitlab.net` are
dropped: their names serve domain-validated certificates (no organisation, 1 SAN), so ownership is not shown. L, J and K were
regenerated on the new R with the same generators. Their content is unchanged except that Box and GitLab no longer gain those
domains; all digests below are the rebuilt ones. Every release still rolls back exactly, and parity is 7467/7467 on K.

- `ms-copilot` + `copilot.com` (`copilot.microsoft.com` redirects there);
- ~~`box` + `boxcdn.net`~~: dropped (domain-validated certificate; ownership not shown);
- ~~`gitlab` + `gitlab.net`~~: dropped (domain-validated certificates; ownership not shown).

| Check | Result |
|---|---|
| `make content content-pack` | ok: release 2026.12.4, digest `bc82ac28b06298dd`, 551 applications, 449 host entries (rebuilt 2026-11-21, copilot.com only) |
| Pack file | sha256 `2cb1c2fa112d6441e3e81b7c8eb783d7640bea5c154fcc85a9a00230c6db2ada` |
| Rollback | release 2026.12.3 host catalog equals the batch I pack exactly |
| Vectors | as rebuilt: `copilot.com` → `ms-copilot`; `cdn01.boxcdn.net` and `*.gitlab.net` unmapped (known gaps); all v2 vectors pass (`tools/retrofit_specs.py`) |
| Parity | 7449/7449 Python and Go; 88/88 families |
| Unit tests | 1 expected failure: pinned host count (438 → 449) |

## Batch L: `batch-l-live-results.patch` (after R; Hermes's live verification 2026-11-20 and decisions 4 and 5)

Source: `research/live-results-2026-11-20.tsv` (live-verified by Hermes from an unproxied vantage, 2026-11-20).
Placeholder release **`2026.12.5`**, with `_PRIOR_HOST_STATE["2026.12.4"]` and `_RELEASED_COMPONENTS["2026.12.4"]`.
If R is held, L applies on I after the R hunks are dropped and its prior state is re-keyed by the Engine lane (it
touches different entries).

- `ms-base` + `cdn.office.net` (decision 4: shared Microsoft asset CDN; `teams.cdn.office.net` stays `ms-teams`);
- `google-play` loses `play.google.com`, which falls to `google-base` (decision 4); `play.googleapis.com` stays;
- `ms-update` loses `emdl.ws.microsoft.com` (NXDOMAIN; it falls to `ms-base`);
- `gmail` + `googlemail.com` (decision 5 result; Gmail Help 10313; N2).

| Check | Result |
|---|---|
| `make content content-pack` | ok: release 2026.12.5, digest `97f96e3e98c3a1ab`, 551 applications, 449 host entries (rebuilt 2026-11-21 on the new R) |
| Pack file | sha256 `2f7bc2bbbed13d7d8bf04605078aaa08a1b4d0d2f3e8f1b7d7be51078adf605f` |
| Rollback | release 2026.12.4 host catalog equals the batch R pack exactly |
| Vectors | 13 targeted (all as expected) + 399 method-v2 vectors across specs, all pass |
| Parity | 7448/7448 Python and Go; 88/88 families |
| Unit tests | 1 expected failure: pinned host count (438 → 449) |

**Amendment to batch F (for the Engine lane):** drop the `prisma-access` entry (and its `_PRIOR_HOST_STATE["2026.11.8"]`
line) before applying F. Both of its names are NXDOMAIN (RFC 8020: nothing below them exists), and the catalog cannot
hold an empty or deleted entry (the parity case generator indexes the first domain, and rollback cannot restore a
deleted entry).

## Batch J: `batch-j-relayed-rows-12-18.patch` (after L)

Rows 12 to 18 of `blocked-urls.md`, read by Research Lab from the Hermes server, 2026-11-20 (PRO-29). Placeholder release
**`2026.12.6`**, with `_PRIOR_HOST_STATE["2026.12.5"]` and `_RELEASED_COMPONENTS["2026.12.5"]`. Apply in the order D → E → F → G →
H → I → R → L → J. If R stays on hold, the Engine lane re-keys the prior states; J touches none of R's entries.

- New id: `jamf-pro` (`jamfcloud.com`, `jamf.com`, exact `sentry.pub.jamf.build`; web fronts `jamf.com`, `www.jamf.com`).
- Extended: `opendns` (+`umbrella.com`; description "Cisco Umbrella and OpenDNS resolver, roaming client and dashboard"),
  `parsec` (+`parsecusercontent.com`), `asana` (+`asana.plus`, `asanausercontent.com`, `app.asana-gov.com`, six exact S3 bucket
  hosts), `atera` (+`atera.pubnubapi.com` and two exact `atera-agent-heartbeat*.servicebus.windows.net` hosts), `salesforce` (+22
  domains), `grammarly` (+`grammarly.net`).

| Check | Result |
|---|---|
| `make content content-pack` | ok: release 2026.12.6, digest `c7df2b97e8fc8a01`, 552 applications, 450 host entries (rebuilt 2026-11-21) |
| Pack file | sha256 `74163f02998688cf3c09f114fc216908cbde6e404335aa0799c3bf21aefea720` |
| Rollback | release 2026.12.5 host catalog equals the batch L pack exactly |
| Vectors | 53 targeted (all as expected); method-v2 vectors per spec in section 6 |
| Parity | 7455/7455 Python and Go; 88/88 families |
| Unit tests | 856 tests; 1 expected failure: pinned host count (438 → 450) |

## Batch K: `batch-k-dependency-pass2.patch` (after J)

Dependency mapping pass 2 (Hermes server, direct, 2026-11-20) and Hermes's decision 4. Placeholder release **`2026.12.7`**, with
`_PRIOR_HOST_STATE["2026.12.6"]` and `_RELEASED_COMPONENTS["2026.12.6"]`. Apply after J.

- New vendor-level ids: `meta-base` (`connect.facebook.net`), `x-base` (`t.co`, `analytics.twitter.com`), `linkedin-base`
  (`ads.linkedin.com`, `snap.licdn.com`), `reddit-base` (`redditstatic.com`, `alb.reddit.com`, `pixel-config.reddit.com`),
  `quora-base` (`a.quora.com`, `q.quora.com`), `tiktok-base` (`analytics.tiktok.com`), `spotify-base` (`pixels.spotify.com`).
- `twitter` loses `t.co`; `reddit` loses `redditstatic.com`; `ms-base` gains `bat.bing.com`, `c.bing.com`, `bat.bing.net` and
  `static.microsoft` (`.microsoft` is managed by Microsoft Corporation per the IANA root zone database).

| Check | Result |
|---|---|
| `make content content-pack` | ok: release 2026.12.7, digest `be0114651a7bca30`, 559 applications, 457 host entries (rebuilt 2026-11-21) |
| Pack file | sha256 `23779661f466b9a8aa8339604d2a86f4d36ee2f120b2e5f95e67923cf4b88771` |
| Rollback | release 2026.12.6 host catalog equals the batch J pack exactly |
| Vectors | 35 targeted (all as expected); 1,109 method-v2 vectors across 69 specs, all pass |
| Parity | 7467/7467 Python and Go; 88/88 families |
| Unit tests | 856 tests; 1 expected failure: pinned host count (438 → 457) |


## Batch M: `batch-m-name-based.patch` (after K)

Vendor network pages read in this session on 2026-11-21 (PRO-92): Datadog, Microsoft Learn (Power BI, Power Platform, Power
Apps, Power Automate, Azure portal), AWS (Amazon Q Developer) and Apple (enterprise networks). Placeholder release
**`2026.12.8`**, with `_PRIOR_HOST_STATE["2026.12.7"]` and `_RELEASED_COMPONENTS["2026.12.7"]`. Apply after K.

- New ids: `ms-power-platform` (8 names, `dynamics.com` at N2), `azure-portal` (7 names, `management.azure.com` at N2),
  `apple-device-management` (16 exact names and the two portal suffixes), `amazon-q-developer` (8 exact names), and the
  vendor-level `datadog-base` (9 browser RUM intake domains, decision 4).
- `datadog` gains `ddog-gov.com`; `power-bi` gains `analysis.windows.net`, `pbidedicated.windows.net`, the three
  `fabric.microsoft.com` SQL subtrees and `powerquery.microsoft.com`.

| Check | Result |
|---|---|
| `make content content-pack` | ok: release 2026.12.8, digest `79f36d67c88c72b5`, 564 applications, 462 host entries (2026-11-21) |
| Pack file | sha256 `7debfae7fc2144269a55112ffcf1e7a811adece96c2c5f47c114524ac24b6831` |
| Rollback | release 2026.12.7 host catalog equals the batch K pack exactly |
| Vectors | 47 targeted names (all as expected); 1,137 method-v2 vectors across 75 specs, all pass |
| Parity | 7479/7479 Python and Go; 88/88 families |
| Unit tests | 856 tests; 1 expected failure: pinned host count (438 → 462) |

## Batch N: `batch-n-name-based.patch` (after M)

Rows 24 to 27 of `blocked-urls.md`, read by Research Lab from the Hermes server (PRO-108) and relayed in full on 2026-11-21
(PRO-121). Placeholder release **`2026.12.9`**, with `_PRIOR_HOST_STATE["2026.12.8"]` and `_RELEASED_COMPONENTS["2026.12.8"]`.
Apply after M.

- `sophos` gains `sophosxl.com`, `sophosxl.net`, `sophosupd.com`, `sophosupd.net` and `hitmanpro.com` (N2).
- `docusign` gains the exact vendor-named CDN host `docucdn-a.akamaihd.net`.
- `ms-telemetry` gains `dc.services.visualstudio.com` (Application Insights telemetry, listed as such by Power BI and as
  non-Sophos by Sophos), which today falls to `visual-studio` by its `visualstudio.com` suffix.
- Twilio and Snowflake: verified, no change.

| Check | Result |
|---|---|
| `make content content-pack` | ok: release 2026.12.9, digest `80ecb5542510f862`, 564 applications, 462 host entries (2026-11-21) |
| Pack file | sha256 `68e5aa2596b4c5ef90d993fad33be015cc34c1af764d2dace074e99e3bcab5ed` |
| Rollback | release 2026.12.8 host catalog equals the batch M pack exactly |
| Vectors | 22 targeted names (all as expected); 1,153 method-v2 vectors across 79 specs, all pass |
| Parity | 7480/7480 Python and Go; 88/88 families |
| Unit tests | 856 tests; 1 expected failure: pinned host count (438 → 462) |

## Batch O: `batch-o-name-based.patch` (after N)

Datto RMM, N-able and FortiClient network pages read by Research Lab from the Hermes server (PRO-95), relayed on
2026-11-22 (PRO-106). Placeholder release **`2026.13.0`**: `2026.12.10` would sort before `2026.12.9` as a string, so the
next string-ordered placeholder is used (not a real month; the Engine lane renumbers after its numeric-ordering fix). With
`_PRIOR_HOST_STATE["2026.12.9"]` and `_RELEASED_COMPONENTS["2026.12.9"]`. Apply after N.

- `datto-rmm` (new, after `atera`): `centrastage.net`, `rmm.datto.com`; risk 4 with the `atera` characteristics.
- `n-able` (new, after `datto-rmm`): `n-able.com`, `system-monitor.com`, `systemmonitor.eu.com`, `logicnow.com`,
  `logicnow.us`, `remote.management`, `beanywhere.com`, `keybox.solarwindsmsp.com`, `swi-rc.cdn-sw.net`,
  `cloudbackup.management`; web fronts `n-able.com`, `www.n-able.com`; risk 4 with the `atera` characteristics.
- `forticlient` (new, after `sophos`): 11 exact names under `forticloud.com` and `fortinet.net`; risk 2.

| Check | Result |
|---|---|
| `make content content-pack` | ok: release 2026.13.0, digest `0914c0281fbc029d`, 567 applications, 465 host entries (2026-11-22) |
| Pack file | sha256 `067b68647797a497e7341e694eb79903cb20d808460db48616bebcfe736668ac` |
| Rollback | release 2026.12.9 host catalog equals the batch N pack exactly |
| Vectors | 16 targeted names (all as expected); 1,159 method-v2 vectors across 79 specs, all pass |
| Parity | 7488/7488 Python and Go; 88/88 families |
| Unit tests | 856 tests; 1 expected failure: pinned host count (438 → 465) |

## Batch P: `batch-p-name-based.patch` (after O)

HubSpot's "SSL and domain security in HubSpot" (knowledge.hubspot.com, last updated 2026-11-19), read in this session on
2026-11-22 (PRO-158). Placeholder release **`2026.13.1`**, with `_PRIOR_HOST_STATE["2026.13.0"]` and
`_RELEASED_COMPONENTS["2026.13.0"]`. Apply after O.

- `hubspot-base` (new vendor-level id, after `hubspot`, decision 4): 32 HubSpot tag, form, chat, CTA, cookie-banner, file and
  video domains plus three exact `hubspot-no-cache-*-prod.s3.amazonaws.com` hosts. `hubspot` is unchanged.
- BeyondTrust Remote Support Cloud was verified with no change (all names under `beyondtrustcloud.com`).

| Check | Result |
|---|---|
| `make content content-pack` | ok: release 2026.13.1, digest `8d149a328ed6e0c8`, 568 applications, 466 host entries (2026-11-22) |
| Pack file | sha256 `db856c1c24c9a7cba7fe062f9521db06a1f8a7c787c698efd067a1ec8e4b582d` |
| Rollback | release 2026.13.0 host catalog equals the batch O pack exactly |
| Vectors | 16 targeted names (all as expected); 1,171 method-v2 vectors across 81 specs, all pass |
| Parity | 7490/7490 Python and Go; 88/88 families |
| Unit tests | 856 tests; 1 expected failure: pinned host count (438 → 466) |

## Batch Q: `batch-q-relayed-rows-30-44.patch` (after P)

Vendor network pages for `blocked-urls.md` rows 30 to 44, read by Research Lab from the Hermes server on 2026-11-22
(PRO-168) and relayed verbatim in `research/relay/pro-168-rows-30-44.md` on `hermes/research-data-pro168` at `f721a8c`
(PRO-182); specs PRO-169. Placeholder release **`2026.13.2`**, with `_PRIOR_HOST_STATE["2026.13.1"]` and
`_RELEASED_COMPONENTS["2026.13.1"]`. Apply after P.

- `manageengine-endpoint-central` (new, before `forticlient`): 54 exact names under the `manageengine.*` regional domains
  (`desktopcentral`, `endpointcentral-agent[p]N`, `patchdb`, `patchdatabase`); risk 3, `transfers-files`. Zoho-hosted names
  stay with `zoho` or no application.
- `new-relic-base` (new vendor-level id, before `new-relic`, decision 4): `bam.nr-data.net`, `bam-cell.nr-data.net`,
  `bam.eu01.nr-data.net`, `bam.jp.nr-data.net`, `js-agent.newrelic.com`. `new-relic` is unchanged.
- `ringcentral` extended (17 names), `keeper` (6), `8x8` (6), `freshworks` (5), `intercom` (19).
- Kaseya VSA and PagerDuty verified with no change.

| Check | Result |
|---|---|
| `make content content-pack` | ok: release 2026.13.2, digest `fcd1792507af3311`, 570 applications, 468 host entries (2026-11-24) |
| Pack file | sha256 `3d68a1931383233a8fa71cfab6c7ecfe419136c91047cf8bf3efedae34f3606c` |
| Rollback | release 2026.13.1 host catalog equals the batch P pack exactly |
| Vectors | 67 targeted names (all as expected); 1,216 method-v2 vectors across 90 specs, all pass |
| Parity | 7496/7496 Python and Go; 88/88 families |
| Unit tests | 856 tests; 1 expected failure: pinned host count (438 → 468) |
