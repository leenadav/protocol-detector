# Child apps, wave 3: 30 more services already in the pack (PRO-569)

Continues wave 0 (`wave-0.md`, PRO-495, PR #161), wave 1 (`wave-1.md`, PRO-524, PR #176) and wave 2 (`wave-2.md`, PRO-550,
PR #180) for Engine PRO-492. Data: `wave-3.json` (schema `child-apps/v1`, `wave: 3`, same validator as wave 2:
`../tools/check_child_apps.py`). Parent ids are those of `go/internal/content/pack.json` at `5cb35d2` (release `2026.11.9`,
identical on `origin/main`); every parent was checked against the pack. Sources accessed 2026-11-27.

## Scope and overlap

- **PR #166** (`research/catalog-pipeline/enterprise-300.md` at `4cf00fe`, PRO-491): rechecked, none of its 65 rows is in
  the pack, so none can be a parent. Its row `yandex-disk` (not in the pack) is a different product from Yandex Mail below
  and is linked, not repeated.
- **30 new services**, none in waves 0 to 2, in the task's category order: file sharing (Backblaze B2, Gofile, file.io,
  IDrive), webmail (GMX Mail, Yandex Mail), AI assistants and model APIs (Cohere, Groq, OpenRouter, ElevenLabs, Replicate,
  Together AI, Stability AI, Windsurf), code hosting and package registries (Postman, crates.io, RubyGems, NuGet, Maven
  Central, Packagist, Go modules), CRM and ticketing (Freshworks, Intercom, PagerDuty, Mailchimp, SendGrid), e-signature
  (PandaDoc), social posting vs reading (Bluesky, Tumblr, Imgur).
- **Left out**: `anthropic-api`, `mistral-api`, `perplexity-api`, `deepseek-api` (their API children are in wave 0 under
  the consumer parent), `xai-api` (wave 2 `xai-grok`), `openai-platform` (wave 0).

## Method

Same as wave 2. Official vendor sources only, one citation per verified child (more in `citation_also`). Nothing is taken
from nDPI, Wireshark, Suricata, Snort or OpenAppID. No traffic was captured and no vendor API was called. **Unverified
children keep every signal field `null`.** Every vendor documentation site in this wave except `learning.postman.com`,
`learn.microsoft.com`, `packagist.org` and `pkg.go.dev` was refused by this session's network policy (curl 000, WebFetch
DNS failure). Rows therefore cite the vendor's own OpenAPI spec, SDK or documentation repository on
`raw.githubusercontent.com`, pinned to a commit (Cargo docs to the `rust-1.98.0` tag), or a vendor registry document.

Checks before submission:
- **Quote check.** The first single-quoted string in each verified child's note was fetched again and found in its cited
  file: 118 of 118.
- **Manual sample.** 25 rows (one verified child per service) were compared field by field with the source, and 11 further
  host and path signals were spot-checked in the cited files. No error was found. PagerDuty Events and Mandrill paths are
  `servers` / `basePath` plus the spec path, as their notes say.

Rejected sources:
- the npm package `stability-ai`, published by an individual;
- the npm package `@idrivee2/s3-mcp`: its publisher could not be tied to IDrive, so the two IDrive rows built on it were
  downgraded to unverified;
- the `backblaze-b2-samples` repository: ownership unconfirmed, so the S3 row cites Backblaze's own `b2-sdk-python` instead;
- the Gofile, file.io, GMX and Yandex packages: all third-party;
- Thunderbird ISPDB: not vendor-owned.

## Result

30 services, 159 proposed children, **118 verified with an official citation** (118 distinct pages); 41 unverified.

25 separate partly by method, path or host; 5 are blocked (no readable primary source for any function split). 2 services with web-UI evidence.

Counts asked for by PRO-569: **30 services**; **118 children with citations** (73 primary pages, 118 with `citation_also`); **2 services with web-UI evidence** (Postman (different), crates.io (same)); **5 blocked**: Gofile, file.io, IDrive, GMX Mail, Yandex Mail.

| # | Service | Parent | Verified children | Unverified children | Verified | Separability | Web UI |
|---|---|---|---|---|---|---|---|
| 1 | Cohere | `cohere` | `cohere-api-chatting`, `cohere-api-embedding`, `cohere-api-uploading`, `cohere-api-transcribing`, `cohere-api-fine-tuning` | `cohere-web-using` | 5/6 | partial | none |
| 2 | Groq | `groq` | `groq-api-chatting`, `groq-api-speech-generating`, `groq-api-transcribing`, `groq-api-uploading`, `groq-api-downloading` | `groq-web-using` | 5/6 | partial | none |
| 3 | OpenRouter | `openrouter` | `openrouter-api-chatting`, `openrouter-api-speech-generating`, `openrouter-api-transcribing`, `openrouter-api-uploading`, `openrouter-api-downloading` | `openrouter-web-using` | 5/6 | partial | none |
| 4 | ElevenLabs | `elevenlabs` | `elevenlabs-api-speech-generating`, `elevenlabs-api-transcribing`, `elevenlabs-api-realtime-transcribing`, `elevenlabs-api-voice-cloning`, `elevenlabs-api-downloading` | `elevenlabs-web-using` | 5/6 | partial | none |
| 5 | Replicate | `replicate` | `replicate-api-predicting`, `replicate-api-uploading`, `replicate-delivery-downloading`, `replicate-api-training`, `replicate-api-deploying` | `replicate-web-using` | 5/6 | partial | none |
| 6 | Together AI | `together-ai` | `together-ai-api-chatting`, `together-ai-api-uploading`, `together-ai-api-downloading`, `together-ai-api-fine-tuning`, `together-ai-api-speech-generating` | `together-ai-web-using` | 5/6 | partial | none |
| 7 | Stability AI | `stability-ai` | `stability-ai-api-generating`, `stability-ai-api-managing-assets`, `stability-ai-api-account`, `stability-ai-downloading` | `stability-ai-api-rest-generating`, `stability-ai-web-app` | 4/6 | partial | none |
| 8 | Windsurf / Codeium | `windsurf` | `windsurf-ide-completing`, `windsurf-authenticating`, `windsurf-client-downloading` | `windsurf-editor` | 3/4 | partial | none |
| 9 | Postman | `postman` | `postman-api-creating`, `postman-api-reading`, `postman-api-updating`, `postman-desktop-syncing`, `postman-web-syncing`, `postman-extension-syncing` | - | 6/6 | partial | different |
| 10 | crates.io | `crates-io` | `crates-io-api-publishing`, `crates-io-api-yanking`, `crates-io-api-searching`, `crates-io-downloading`, `crates-io-index-reading` | - | 5/5 | partial | same |
| 11 | RubyGems | `rubygems` | `rubygems-api-publishing`, `rubygems-api-yanking`, `rubygems-api-searching`, `rubygems-installing`, `rubygems-index-reading` | `rubygems-web-browsing` | 5/6 | partial | none |
| 12 | NuGet | `nuget` | `nuget-api-publishing`, `nuget-api-unlisting`, `nuget-installing`, `nuget-searching`, `nuget-metadata-reading` | `nuget-web-browsing` | 5/6 | partial | none |
| 13 | Maven Central | `maven-central` | `maven-central-publishing`, `maven-central-publish-checking`, `maven-central-downloading`, `maven-central-index-downloading` | `maven-central-searching` | 4/5 | partial | none |
| 14 | Packagist | `packagist` | `packagist-submitting`, `packagist-updating`, `packagist-metadata-reading`, `packagist-package-browsing`, `packagist-searching` | - | 5/5 | partial | none |
| 15 | Go modules | `go-modules` | `go-modules-version-listing`, `go-modules-downloading`, `go-modules-checksum-verifying`, `go-modules-package-browsing` | - | 4/4 | partial | none |
| 16 | Bluesky | `bluesky` | `bluesky-posting`, `bluesky-uploading`, `bluesky-reading`, `bluesky-messaging`, `bluesky-firehose-streaming` | `bluesky-web-browsing` | 5/6 | partial | none |
| 17 | Tumblr | `tumblr` | `tumblr-posting`, `tumblr-blog-reading`, `tumblr-dashboard-reading`, `tumblr-tag-searching` | `tumblr-web-browsing` | 4/5 | partial | none |
| 18 | Imgur | `imgur` | `imgur-uploading`, `imgur-image-viewing`, `imgur-gallery-browsing`, `imgur-searching`, `imgur-messaging` | `imgur-web-browsing` | 5/6 | partial | none |
| 19 | Freshworks (Freshdesk / Freshservice) | `freshworks` | `freshworks-ticket-creating`, `freshworks-ticket-reading`, `freshworks-conversation-replying`, `freshworks-contact-exporting`, `freshworks-freshservice-ticket-creating` | `freshworks-web-app` | 5/6 | partial | none |
| 20 | Intercom | `intercom` | `intercom-api-message-sending`, `intercom-api-conversation-replying`, `intercom-api-conversation-reading`, `intercom-api-ticket-creating`, `intercom-api-data-exporting` | `intercom-web-app` | 5/6 | partial | none |
| 21 | PagerDuty | `pagerduty` | `pagerduty-api-incident-creating`, `pagerduty-api-incident-reading`, `pagerduty-api-note-posting`, `pagerduty-events-sending` | `pagerduty-web-app` | 4/5 | partial | none |
| 22 | Mailchimp | `mailchimp` | `mailchimp-api-campaign-sending`, `mailchimp-api-contact-importing`, `mailchimp-api-report-reading`, `mailchimp-api-file-uploading`, `mailchimp-transactional-mail-sending` | `mailchimp-web-app` | 5/6 | partial | none |
| 23 | Twilio SendGrid | `sendgrid` | `sendgrid-api-mail-sending`, `sendgrid-api-campaign-sending`, `sendgrid-api-contact-importing`, `sendgrid-api-contact-exporting` | `sendgrid-web-app` | 4/5 | partial | none |
| 24 | PandaDoc | `pandadoc` | `pandadoc-api-document-creating`, `pandadoc-api-document-sending`, `pandadoc-api-signed-pdf-downloading`, `pandadoc-api-attachment-uploading`, `pandadoc-api-attachment-downloading` | `pandadoc-web-app` | 5/6 | partial | none |
| 25 | Backblaze B2 | `backblaze` | `backblaze-b2-uploading`, `backblaze-b2-downloading`, `backblaze-b2-deleting`, `backblaze-b2-sharing`, `backblaze-s3-transferring` | `backblaze-web-console` | 5/6 | partial | none |
| 26 | Gofile | `gofile` | - | `gofile-uploading`, `gofile-downloading`, `gofile-deleting`, `gofile-web-app` | 0/4 | blocked | none |
| 27 | file.io | `file-io` | - | `file-io-uploading`, `file-io-downloading`, `file-io-deleting`, `file-io-web-app` | 0/4 | blocked | none |
| 28 | IDrive / IDrive e2 | `idrive` | - | `idrive-e2-provisioning`, `idrive-e2-console-browsing`, `idrive-e2-uploading`, `idrive-e2-downloading`, `idrive-backup-syncing` | 0/5 | blocked | none |
| 29 | GMX Mail | `gmx-mail` | - | `gmx-mail-smtp-sending`, `gmx-mail-imap-reading`, `gmx-mail-web-mail` | 0/3 | blocked | none |
| 30 | Yandex Mail | `yandex-mail` | - | `yandex-mail-smtp-sending`, `yandex-mail-imap-reading`, `yandex-mail-web-mail` | 0/3 | blocked | none |

## Web-UI evidence

- **Postman** (`different`, https://learning.postman.com/docs/getting-started/installation/firewall.md): "For the Postman
  web app v10 and later to make WebSocket connections, allowlist the following domains:" followed by `bifrost-web-*`
  hosts under `gw.postman.co` / `gw.postman.com`, not the REST API host `api.postman.com`.
- **crates.io** (`same`, `rust-lang/crates.io` `src/openapi.rs`): "This document describes the API used by the crates.io
  website, cargo client, and other third-party tools to interact with the crates.io registry."
- Every other service: `none` (no official page read here says what its browser app calls); see each `web_ui_note`.

## Where a function cannot be separated by path

No service is wholly `not-separable`. Some functions inside a service cannot be split by path:
- **Bluesky**: post, like, repost and follow are all `POST /xrpc/com.atproto.repo.createRecord`; the record type is in
  the JSON body.
- **Stability AI (gRPC)**: an image sent for editing travels in the same `Generate` request as the prompt.
- **Windsurf**: completions and chat both go through the local language server to `server.codeium.com`. The paths are
  inside a closed binary, so only the host is known.
- **Run-time transfer targets**: the destination is returned at run time and is not documented. This covers the Together
  file-upload redirect, the B2 `uploadUrl` and account `downloadUrl`, the SendGrid import and export URLs, the Cohere
  dataset files and the IDrive e2 regional endpoint. The documented call is the rule; the follow-up host is not.

## Findings for Engine (ENGINE-FIELD, Go only)

1. **API hosts outside the parent's pack domains** need adding, or a host-to-parent override, before these children can
   match:
   - `replicate.delivery` (Replicate outputs);
   - `mandrillapp.com` (Mailchimp Transactional);
   - `api.bsky.chat`, `*.host.bsky.network`, `bsky.network` and `video.bsky.app` (Bluesky);
   - `central.sonatype.com` and `repo.maven.apache.org` (Maven Central; the pack has `maven.org` only);
   - `*.postman.co` (Postman sync);
   - `idrivee2.com` (lead only).
2. **gRPC and WebSocket children**: Stability AI uses `grpc.stability.ai` with paths `/gooseai.<Service>/<Method>`.
   ElevenLabs realtime STT and the Bluesky firehose are WebSocket upgrades, so a rule must look at the upgrade request.
3. **Multi-tenant hosts**: Freshdesk and Freshservice use `{subdomain}.freshdesk.com` / `{subdomain}.freshservice.com` with
   the same `/api/v2/tickets` path. The agent web UI shares that host, so these API rows also see web traffic to `/api/v2`.
4. **Registry pairs**: in NuGet, publish and download are split by host (`www.nuget.org` vs `api.nuget.org`). In
   crates.io, download redirects to `static.crates.io`.

## Unknowns

Every unverified child (41) is unknown; the ids are in the table. The unknown fields within verified rows are:
- `host_sni` for the Backblaze download row and the RubyGems compact index;
- `http_method` for the Windsurf sign-in and pkg.go.dev;
- `content_type` where the SDK names only a file body (Cohere and ElevenLabs uploads);
- every browser web app except Postman and crates.io.

## Blocked sources

Rows 93 to 116 of `../blocked-urls.md` (24 vendors); the hosts are batch R5 in `../allowlist-requests.md`.
