# Content release notes

Release notes for the detection content packs (server-name catalog, application catalog, and their release history). Every entry is derived from the repository: the release list is `HISTORY` in `protocol_engine/content.py`, the per-release catalogs are `go/internal/content/pack.json` (current, and one snapshot per release commit) and `go/internal/content/history.json` (earlier release host catalogs). Nothing here is a claim about production readiness or detection accuracy; see the review status of each release below.

## Where each release lives

- `main` (head `2b97e2d`): releases `2025.10.0` and `2026.11.0` only (`HISTORY` in `protocol_engine/content.py`).
- `claude/go-migration` (head `93937a3` at the time of writing): releases `2026.11.1` through `2026.11.9`. These are **not on `main`**. `main` does not contain these releases until the Go branch is merged.

| Version | Released | Only on | Pack snapshot | Applications | Server-name entries |
|---|---|---|---|---|---|
| 2026.11.9 | 2026-11-19 | `claude/go-migration` | `2f6ad4d` | 544 | 442 |
| 2026.11.8 | 2026-11-19 | `claude/go-migration` | `253a91d` | 543 | 441 |
| 2026.11.7 | 2026-11-19 | `claude/go-migration` | `ee1645d` | 543 | 441 |
| 2026.11.6 | 2026-11-18 | `claude/go-migration` | `b6ed149` | 540 | 438 |
| 2026.11.5 | 2026-11-18 | `claude/go-migration` | `7dcabb7` | 540 | 438 |
| 2026.11.4 | 2026-11-18 | `claude/go-migration` | `6ab434d` | 536 | 434 |
| 2026.11.3 | 2026-11-18 | `claude/go-migration` | `baa07b9` | 536 | 434 |
| 2026.11.2 | 2026-11-15 | `claude/go-migration` | `3b0ddf9` | 533 | 431 |
| 2026.11.1 | 2026-11-15 | `claude/go-migration` | `1eea0cd` | 271 | 169 |
| 2026.11.0 | 2026-11-07 | `main`, `claude/go-migration` (HISTORY entry) | `52b9233` (pack snapshot; see Sources) | 156 | 54 |
| 2025.10.0 | 2025-10-24 | `main`, `claude/go-migration` | none (host catalog only, `history.json`) | not recorded | 53 |

Application counts come from `pack.json`; `2025.10.0` has no application snapshot in the repository. The `2025.10.0` host catalog has 53 entries in `history.json`, while its `HISTORY` note says 51 services. This mismatch is not reconciled here; see the open item at the end.

## Terms

- **New application**: a name in `pack.json` `applications` that the previous snapshot did not have.
- **Modified application**: an application whose identification changed: server-name domains or web fronts added or removed, or a field (ports, technology, aliases, dependencies) changed. Metadata-only changes are listed separately.
- **Review before deploying**: changes an operator should check before rollout. A domain that moves from one application to another is the case that changes what is reported.

## Releases, newest first

### 2026.11.9 — 2026-11-19

- Branch: `claude/go-migration` only.
- Pack snapshot `2f6ad4d`; content commit `2f6ad4d`.
- Catalog after release: 544 applications, 442 server-name entries (previous: 543 and 441).
- Release note (from `HISTORY`): goto.com moved from GoTo Meeting to a vendor-level goto id.
- Review status (from `HISTORY`): engine-lane decision (Hermes, 2026-11-19) on the research lane goto.md question; independent review pending.

**New applications (1):** `goto`

**Modified applications:**

- `goto-meeting`: domains removed: `goto.com`.

**Removed applications:** none

**Review before deploying:**

- `goto.com` moved from `goto-meeting` to `goto`.

### 2026.11.8 — 2026-11-19

- Branch: `claude/go-migration` only.
- Pack snapshot `253a91d`; content commit `253a91d`.
- Catalog after release: 543 applications, 441 server-name entries (previous: 543 and 441).
- Release note (from `HISTORY`): Chrome Remote Desktop service host; Bitwarden regional and short-link domains.
- Review status (from `HISTORY`): application-research lane proposal with primary sources (research/apps on claude/app-research 56abe4e); engine-lane review of each spec against its sources; independent review pending.

**New applications (0):** none

**Modified applications:**

- `bitwarden`: domains added: `bitwarden.eu`, `bitwarden.net`, `btwrdn.co`, `btwrdn.com`.
- `chrome-remote-desktop`: domains added: `remotedesktop-pa.googleapis.com`.

**Removed applications:** none

**Review before deploying:**

- No ownership change or removal in this release. Additions in the list above can still change identification of traffic that was previously unidentified.

### 2026.11.7 — 2026-11-19

- Branch: `claude/go-migration` only.
- Pack snapshot `ee1645d`; content commit `ee1645d`.
- Catalog after release: 543 applications, 441 server-name entries (previous: 540 and 438).
- Release note (from `HISTORY`): Defender for Endpoint and Intune; iCloud Private Relay apart from iCloud; Cursor, 1Password, GitLab, Docker, Okta, Notion, GoTo Meeting, Zscaler, Figma for Government and Netskope hosts from vendor documentation.
- Review status (from `HISTORY`): application-research lane proposal with primary sources (research/apps on claude/app-research 7a8d4d7); engine-lane review of each spec against its sources; independent review pending.

**New applications (3):** `icloud-private-relay`, `ms-defender-endpoint`, `ms-intune`

**Modified applications:**

- `1password`: domains added: `1infra.net`, `1password.ca`, `1passwordservices.com`, `1passwordusercontent.ca`, `1passwordusercontent.com`, `1passwordusercontent.eu`, `app-updates.agilebits.com`, `cache.agilebits.com`.
- `cursor`: domains added: `cursor-cdn.com`, `cursorapi.com`, `cursorvm.com`.
- `docker-hub`: domains added: `dhi.io`.
- `figma`: domains added: `figma-gov.com`.
- `gitlab`: domains added: `gitlab-static.net`.
- `goto-meeting`: domains added: `gotomeet.at`, `gotomeet.me`, `joingotomeeting.com`, `openvoice.com`.
- `icloud`: domains added: `apple-cloudkit.com`, `apple-livephotoskit.com`, `icloud.apple.com`, `iwork.apple.com`.
- `netskope`: domains added: `epdlp-prod.netskope.io`.
- `notion`: domains added: `notion.com`, `notionusercontent.com`, `secure.notion-static.com`.
- `okta`: domains added: `okta-emea.com`, `okta-gov.com`, `okta.mil`.
- `zscaler`: domains added: `zdxbeta.net`, `zdxcloud.net`, `zdxgov.net`, `zdxten.net`, `zidentitygov.net`, `zpabeta.net`, `zpagov.net`, `zpatwo.net`, `zscalerbeta.net`, `zscalergov.net`, `zscalerone.net`, `zscalerten.net`, `zscalerthree.net`, `zscalertwo.net`, `zslogin.net`, `zsloginbeta.net`.

**Removed applications:** none

**Review before deploying:**

- No ownership change or removal in this release. Additions in the list above can still change identification of traffic that was previously unidentified.

### 2026.11.6 — 2026-11-18

- Branch: `claude/go-migration` only.
- Pack snapshot `b6ed149`; content commit `b6ed149`.
- Catalog after release: 540 applications, 438 server-name entries (previous: 540 and 438).
- Release note (from `HISTORY`): notebook.google.com; Dropbox www web fronts; ngrok agent hosts; Cloudflare One Client API hosts; Atlassian first-party domains; WeTransfer short links and named storage hosts.
- Review status (from `HISTORY`): application-research lane proposal with primary sources (research/apps on claude/app-research dc75176); engine-lane review of each spec against its sources; independent review pending.

**New applications (0):** none

**Modified applications:**

- `atlassian`: domains added: `atl-paas.net`, `jira.com`, `ss-inf.net`, `teamworkgraph.com`.
- `cloudflare-warp`: domains added: `api.devices.cloudflare.com`, `api.devices.fed.cloudflare.com`, `notifications.devices.fed.cloudflare.com`.
- `dropbox`: web_fronts added: `www.dropbox.tech`, `www.dropboxforum.com`, `www.dropboxforums.com`, `www.dropboxinsiders.com`, `www.dropboxlegal.com`.
- `google-notebooklm`: domains added: `notebook.google.com`.
- `ngrok`: domains added: `ngrok-agent.com`, `update.equinox.io`.
- `wetransfer`: domains added: `we.tl`, `wt-prod-euwest1-storm.s3-accelerate.amazonaws.com`, `wt-prod-euwest1-storm.s3.amazonaws.com`, `wt-prod-euwest1-storm.s3.eu-west-1.amazonaws.com`, `wt-prod-useast1-storm.s3-accelerate.amazonaws.com`, `wt-prod-useast1-storm.s3.amazonaws.com`, `wt-prod-useast1-storm.s3.us-east-1.amazonaws.com`.

**Removed applications:** none

**Review before deploying:**

- No ownership change or removal in this release. Additions in the list above can still change identification of traffic that was previously unidentified.

### 2026.11.5 — 2026-11-18

- Branch: `claude/go-migration` only.
- Pack snapshot `7dcabb7`; content commit `7dcabb7`.
- Catalog after release: 540 applications, 438 server-name entries (previous: 536 and 434).
- Release note (from `HISTORY`): DeepSeek, Perplexity, Mistral AI and xAI API hosts named apart from their chat applications.
- Review status (from `HISTORY`): application-research lane proposal with primary sources (research/apps on claude/app-research bb931b9); API split for these vendors decided by Hermes; engine-lane review of each spec; independent review pending.

**New applications (4):** `deepseek-api`, `mistral-api`, `perplexity-api`, `xai-api`

**Modified applications:**

- none

**Removed applications:** none

**Review before deploying:**

- No ownership change or removal in this release. Additions in the list above can still change identification of traffic that was previously unidentified.

### 2026.11.4 — 2026-11-18

- Branch: `claude/go-migration` only.
- Pack snapshot `6ab434d`; content commit `6ab434d`.
- Catalog after release: 536 applications, 434 server-name entries (previous: 536 and 434).
- Release note (from `HISTORY`): Google Drive and Docs editor hosts; OneDrive consumer hosts; Webex service domains; OpenAI help and developer documentation as web fronts.
- Review status (from `HISTORY`): application-research lane proposal with primary sources (research/apps on claude/app-research bb931b9); engine-lane review of each spec against its sources; independent review pending.

**New applications (0):** none

**Modified applications:**

- `ms-onedrive`: application fields changed: description.
- `google-drive`: domains added: `drive-data-export-eu.usercontent.google.com`, `drive-data-export.usercontent.google.com`, `googledrive.com`, `sheets.google.com`, `slides.google.com`.
- `ms-onedrive`: domains added: `photos.live.com`, `skydrive.live.com`, `storage.msn.com`; metadata changed: description.
- `openai-chatgpt`: web_fronts added: `help.openai.com`.
- `openai-platform`: web_fronts added: `developers.openai.com`.
- `webex`: domains added: `ciscospark.com`, `ciscosparkcontent.com`, `webexapis.com`, `webexcontent.com`.

**Removed applications:** none

**Review before deploying:**

- No ownership change or removal in this release. Additions in the list above can still change identification of traffic that was previously unidentified.

### 2026.11.3 — 2026-11-18

- Branch: `claude/go-migration` only.
- Pack snapshot `baa07b9`; content commit `baa07b9`.
- Catalog after release: 536 applications, 434 server-name entries (previous: 533 and 431).
- Release note (from `HISTORY`): Microsoft 365 cloud.microsoft names and Exchange Online Protection separated from web mail; Copilot app host; GitHub Copilot service hosts; Anthropic API split from the apps; Dropbox verified domains, web fronts and DocSend.
- Review status (from `HISTORY`): application-research lane proposal with primary sources (research/apps on claude/app-research 9c040b2); engine-lane review of each spec against its sources; independent review pending.

**New applications (3):** `anthropic-api`, `docsend`, `ms-exchange-online-protection`

**Modified applications:**

- `anthropic-claude`: domains added: `claudeusercontent.com`; web_fronts added: `claude.com`, `code.claude.com`.
- `dropbox`: domains added: `addtodropbox.com`, `db.tt`, `dropbox-dns.com`, `dropboxbusiness.com`, `dropboxcaptcha.com`, `dropboxexperiment.com`, `getdropbox.com`; web_fronts added: `dropbox.tech`, `dropboxforum.com`, `dropboxforums.com`, `dropboxinsiders.com`, `dropboxlegal.com`, `learn.dropbox.com`.
- `dropbox-sign`: domains added: `hellofax.com`.
- `github-copilot`: domains added: `copilot-proxy.githubusercontent.com`, `copilot-telemetry.githubusercontent.com`, `origin-tracker.githubusercontent.com`, `production-copilot-host-austriaeast.webpubsub.azure.com`, `production-copilot-host-centralus-02.webpubsub.azure.com`, `production-copilot-host-centralus.webpubsub.azure.com`, `production-copilot-host-eastasia.webpubsub.azure.com`, `production-copilot-host-westus.webpubsub.azure.com`, `production-copilot-host-westus3.webpubsub.azure.com`, `production-copilot-host.webpubsub.azure.com`.
- `ms-copilot`: domains added: `copilot.cloud.microsoft`.
- `ms-office365`: domains added: `cloud.microsoft`, `microsoft365.com`.
- `ms-teams`: domains added: `lync.com`, `teams.cloud.microsoft`.
- `outlook-web`: domains added: `outlook.cloud.microsoft`.
- `sharepoint-online`: domains added: `sharepointonline.com`, `svc.ms`.

**Removed applications:** none

**Review before deploying:**

- No ownership change or removal in this release. Additions in the list above can still change identification of traffic that was previously unidentified.

### 2026.11.2 — 2026-11-15

- Branch: `claude/go-migration` only.
- Pack snapshot `3b0ddf9`; content commit `3b0ddf9`.
- Catalog after release: 533 applications, 431 server-name entries (previous: 271 and 169).
- Release note (from `HISTORY`): 262 more services on operator-owned domains (media, social, messaging, mail, storage and backup, business, management and endpoint security, developer, identity, generative AI, remote access and RMM, VPN and circumvention, cloud proxies, resolvers, commerce, news, education, advertising and measurement); remote-access, RMM and VPN apex/www names are web fronts.
- Review status (from `HISTORY`): engine-lane self-review against the operator-owned-domain rule; independent review pending.

**New applications (262):** <details><summary>262 names</summary>

`4shared`, `8x8`, `9gag`, `adjust`, `adp`, `alibaba`, `alibaba-tongyi`, `amazon-ads`, `ammyy-admin`, `amplitude`, `android-services`, `aol`, `apple-software-update`, `appsflyer`, `atera`, `audible`, `authy`, `avast`, `backblaze`, `baidu-ernie`, `bamboohr`, `bandcamp`, `basecamp`, `bbc`, `best-buy`, `beyondtrust`, `bilibili`, `bitdefender`, `blackboard`, `branch-io`, `braze`, `bumble`, `calendly`, `canvas-lms`, `cash-app`, `catbox`, `circleci`, `cleanbrowsing-dns`, `clickup`, `cloudflare-warp`, `cnn`, `codepen`, `cohere`, `connectwise-control`, `controld-dns`, `copy-ai`, `costco`, `coursera`, `craigslist`, `crates-io`, `criteo`, `crowdstrike`, `crunchyroll`, `cursor`, `cyberghost`, `dashlane`, `databricks`, `datadog`, `dazn`, `debian`, `dialpad`, `digicert`, `digitalocean`, `discovery-plus`, `dns-sb`, `doordash`, `doubao`, `dropbox-sign`, `duolingo`, `dwservice`, `egnyte`, `elevenlabs`, `eset`, `espn`, `expedia`, `expensify`, `fastmail`, `fedora`, `file-io`, `flickr`, `flipkart`, `freshworks`, `getscreen`, `gmx-mail`, `go-modules`, `godaddy`, `gofile`, `gog`, `goodreads`, `google-ai-studio`, `google-chat`, `google-colab`, `google-maps`, `google-notebooklm`, `google-photos`, `google-voice`, `gotomypc`, `gradle`, `groq`, `groupme`, `gusto`, `heroku`, `hide-me`, `homebrew`, `hotjar`, `hotspot-shield`, `huawei`, `idrive`, `iheartradio`, `ikea`, `imdb`, `imgur`, `instacart`, `intercom`, `internet-archive`, `intuit`, `ipvanish`, `jasper-ai`, `jd-com`, `jitsi-meet`, `jumpcloud`, `kaggle`, `kakaotalk`, `kaseya`, `kaspersky`, `keeper`, `khan-academy`, `kick`, `kraken`, `lantern`, `lets-encrypt`, `linode`, `lucid`, `magnite`, `mailchimp`, `malwarebytes`, `maven-central`, `mcafee`, `medium`, `mercadolibre`, `meta-ai`, `metamask`, `minecraft`, `mixpanel`, `mozilla`, `ms-telemetry`, `namecheap`, `netlify`, `netskope`, `netsuite`, `new-relic`, `nextdoor`, `ngrok`, `ninjaone`, `nomachine`, `norton`, `nuget`, `nytimes`, `onelogin`, `onesignal`, `opendns`, `openrouter`, `openstreetmap`, `openx`, `oracle-cloud`, `outbrain`, `packagist`, `pagerduty`, `pandadoc`, `parsec`, `phind`, `ping-identity`, `plex`, `postman`, `power-bi`, `private-internet-access`, `psiphon`, `pubmatic`, `quantcast`, `quizlet`, `rakuten`, `remotepc`, `replicate`, `replit`, `reuters`, `revolut`, `robinhood`, `rubygems`, `rumble`, `runway`, `samsung`, `sap`, `sap-concur`, `scorecard-research`, `segment`, `sendgrid`, `sendspace`, `sentinelone`, `sentry`, `shein`, `smartsheet`, `snowflake`, `snyk`, `sonarcloud`, `sophos`, `sourceforge`, `splunk-cloud`, `squarespace`, `stability-ai`, `strava`, `substack`, `suno`, `supremo`, `surveymonkey`, `sync-com`, `tableau`, `tabnine`, `taboola`, `taobao`, `target`, `temu`, `the-guardian`, `the-trade-desk`, `tidal`, `tinder`, `together-ai`, `tor-project`, `transfer-sh`, `tripadvisor`, `tunein`, `tunnelbear`, `tuta-mail`, `twilio`, `typeform`, `ubisoft-connect`, `ubuntu`, `udemy`, `ultrasurf`, `unity`, `venmo`, `vercel`, `virustotal`, `visual-studio`, `vonage`, `waze`, `weather-com`, `whereby`, `windscribe`, `windsurf`, `wise`, `wix`, `wordpress-com`, `writesonic`, `xandr`, `xero`, `xiaomi`, `yandex-mail`, `you-com`, `zalo`, `zhipu-ai`, `zoho-assist`, `zscaler`

</details>

**Modified applications:**

- none

**Removed applications:** none

**Review before deploying:**

- Domain additions can move traffic that was previously unidentified, or matched by another entry, to this application. Check the lists above before rollout.

### 2026.11.1 — 2026-11-15

- Branch: `claude/go-migration` only.
- Pack snapshot `1eea0cd`; content commit `9cec1e6`.
- Catalog after release: 271 applications, 169 server-name entries (previous: 156 and 54).
- Release note (from `HISTORY`): 115 more services on operator-owned domains (streaming, gaming, social, messaging, storage, business, developer, identity, generative AI, remote access, VPN, encrypted-DNS resolvers, platform bases, search, commerce); remote-access and VPN apex/www names are web fronts.
- Review status (from `HISTORY`): engine-lane self-review against the operator-owned-domain rule; independent review pending.

**New applications (115):** <details><summary>115 names</summary>

`1password`, `adguard-dns`, `adobe-cloud`, `airbnb`, `airtable`, `aliexpress`, `apple-app-store`, `apple-base`, `apple-music`, `apple-push`, `apple-tv`, `asana`, `auth0`, `baidu`, `battle-net`, `binance`, `bing`, `bitwarden`, `bluesky`, `booking`, `canva`, `character-ai`, `chrome-remote-desktop`, `cloudflare-dns`, `coinbase`, `dailymotion`, `deepseek`, `deezer`, `docker-hub`, `docusign`, `duckduckgo`, `duo-security`, `ea-games`, `epic-games`, `etsy`, `evernote`, `expressvpn`, `facebook-messenger`, `figma`, `github-copilot`, `google-accounts`, `google-ads`, `google-analytics`, `google-play`, `google-public-dns`, `goto-meeting`, `grammarly`, `hbo-max`, `hubspot`, `hugging-face`, `jetbrains`, `lastpass`, `line`, `logmein`, `matrix-element`, `mediafire`, `mega`, `midjourney`, `miro`, `mistral-ai`, `monday`, `ms-base`, `ms-copilot`, `mullvad`, `nextdns`, `nintendo`, `nordvpn`, `npm`, `okta`, `pandora`, `paramount-plus`, `pastebin`, `pcloud`, `peacock`, `perplexity`, `playstation-network`, `poe`, `proton-mail`, `proton-vpn`, `pypi`, `quad9-dns`, `quora`, `ringcentral`, `riot-games`, `roblox`, `rustdesk`, `servicenow`, `shopify`, `soundcloud`, `speedtest`, `splashtop`, `stack-overflow`, `stripe`, `surfshark`, `tailscale`, `threads`, `threema`, `trello`, `tumblr`, `uber`, `viber`, `vk`, `walmart`, `wechat`, `weibo`, `wetransfer`, `workday`, `xai-grok`, `xbox-live`, `yahoo`, `yahoo-mail`, `yandex`, `zendesk`, `zerotier`, `zoho`

</details>

**Modified applications:**

- none

**Removed applications:** none

**Review before deploying:**

- Engine change in the same commit `9cec1e6` (not content data): the port-table cache is keyed by the application's port lists rather than its name, so one application seen over two carriers (for example ssl, then quic) no longer reuses the first carrier's ports. Per the commit message, `test_appid.PortTablePerCarrierTests` fails without the fix. This changes identification for host-named applications seen over more than one carrier.
- Domain additions can move traffic that was previously unidentified, or matched by another entry, to this application. Check the lists above before rollout.

### 2026.11.0 — 2026-11-07 (on `main` and `claude/go-migration`)

- Pack snapshot `52b9233`: 156 applications, 54 server-name entries.
- Release note (from `HISTORY`): provider web fronts separated from service domains; OpenAI split into ChatGPT, platform and web front; github.io (tenant hosting) removed; TeamViewer/AnyDesk apex and www names are web fronts.
- Review status (from `HISTORY`): engine-lane self-review (D03); independent review pending on PR #18.

**New server-name entries (1):** `openai-platform` (compared with `2025.10.0` in `history.json`).

**Modified (compared with `2025.10.0`):**

- `anydesk`: web_fronts added: `anydesk.com`, `www.anydesk.com`.
- `github`: domains removed: `github.io`.
- `openai-chatgpt`: domains removed: `openai.com`; domains added: `chat.openai.com`; web_fronts added: `openai.com`, `www.openai.com`; description changed.
- `teamviewer`: web_fronts added: `teamviewer.com`, `www.teamviewer.com`.

**Removed:** none (domains removed: `github.io` from the `github` entry).

**Review before deploying:**

- `github.io` is no longer a `github` domain. Tenant-hosted `*.github.io` traffic is no longer identified as GitHub, per the release note (`github.io` is tenant hosting).
- `openai.com` moved from the `openai-chatgpt` service domains to its web fronts, and `openai-platform` is a new entry. Check any rule that relied on `openai.com` being a service domain.
- `anydesk` and `teamviewer` apex and www names are web fronts now, not service domains.

### 2025.10.0 — 2025-10-24 (on `main` and `claude/go-migration`)

- Baseline release for the server-name catalog (v0.65). Host catalog 53 entries in `history.json`.
- Release note (from `HISTORY`): v0.65 built-in server-name catalog: 51 services on operator-owned domains.
- Review status (from `HISTORY`): engine-lane self-review; independent Codex rounds on v0.65 (issue #2).
- There is no earlier release to diff against, so this release has no new/modified/removed lists.

## Open items

- `2025.10.0`: `HISTORY` says 51 services; `history.json` holds 53 host catalog entries. Unreconciled.
- `2026.11.1` to `2026.11.9` are on `claude/go-migration` only. Once the Go branch is merged, `main` needs this file updated to the merged head.
- Independent review: `HISTORY` records independent review as pending for `2026.11.0` through `2026.11.9`. PR #18 was merged on 2026-11-15, but no independent review record for the content is in the repository. This document does not claim one.
- Application catalog for `2025.10.0`: no snapshot in the repository; application-level changes before `2026.11.0` cannot be listed.

## Sources

- Release list and notes: `protocol_engine/content.py` `HISTORY` at `origin/claude/go-migration` (`93937a3`) and at `origin/main` (`2b97e2d`).
- Pack snapshots: `go/internal/content/pack.json` at each commit in the table above.
- Earlier host catalogs: `go/internal/content/history.json` at `origin/claude/go-migration`.
- Pack snapshot `52b9233` (2026.11.0) is not an ancestor of `claude/go-migration`; it is on `claude/culvert-integration-prep` and `claude/cicd-go-minimum-probe`. Its release entry is on both `main` and `claude/go-migration`.
- Derived with a script that compares consecutive snapshots by application name and by server-name entry name. The script is not committed.
