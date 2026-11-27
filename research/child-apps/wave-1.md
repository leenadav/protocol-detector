# Child apps, wave 1: 30 more services already in the pack (PRO-524)

Continues wave 0 (`wave-0.md`, PRO-495) for Engine PRO-492 (Lee, 2026-11-27: enterprise App-ID model with child apps
per function). Data: `wave-1.json` (schema `child-apps/v1`). Parent ids are those of `go/internal/content/pack.json`
at `5cb35d2` (release `2026.11.9`); every parent was checked against the pack, not assumed. Sources accessed
2026-11-27. The file also carries the SEC-CHILD-3 vendor evidence Engine asked for (PRO-510), section below.

## Scope and overlap

- **30 new services** from Hermes's preferred list, all present in the pack: Google Meet, Google Photos, Google
  Chat, SharePoint Online, OneNote (under `ms-office365`), Webex, Skype, Salesforce, ServiceNow, Jira, Confluence
  (both `atlassian`), Trello, GitLab, Notion, monday.com, Asana, Figma, Canva, Miro, TikTok, Pinterest, Snapchat,
  Twitch, Vimeo, Perplexity, DeepSeek, Mistral (Le Chat), Yahoo Mail, Proton Mail, pCloud.
- **2 retries** of wave 0 (Pastebin, Reddit) through their official API docs: still blocked (rows 53 and 58).
- **Left out, with the reason**: Google Calendar, Amazon S3 and Azure Blob have no app id in the pack (a parent would
  be a guess); Outlook / Exchange Online is wave 0's `outlook-web`; **Bitbucket** is row 47 (`bitbucket`, not in
  the pack) of PR #166's `research/catalog-pipeline/enterprise-300.md` (PRO-491) and is linked there, not repeated.
  None of the 30 services above is in PR #166's 65-service list (checked by name, 2026-11-27).

## Method

Same as wave 0: official vendor pages only, one citation URL per verified child (further sources in
`citation_also`), nothing from nDPI, Wireshark, Suricata, Snort or OpenAppID. Signals are what a decrypting proxy
sees: host/SNI, method, path, request content type, direction, WebSocket; non-HTTP signals go in `transport`.
**Unverified children keep every signal field `null`** and are proposals for the id space only. `surface: api`
rows are vendor API endpoints; the web clients' own request paths are not published by any vendor read here.

Where a documentation site was not reachable, rows cite the vendor's own published OpenAPI spec or official SDK on
`raw.githubusercontent.com` (Hermes's PRO-501 rule): `Asana/openapi`, `figma/rest-api-spec`,
`pinterest/api-description`, `vimeo/openapi`, `miroapp/api-clients`, `canva-sdks/canva-connect-api-starter-kit`,
`makenotion/notion-sdk-js`, `mondaycom/monday-sdk-js`, `ProtonMail/go-proton-api`, `pCloud/pcloud-sdk-js`,
`discord/discord-api-docs`, `dropbox/dropbox-sdk-python` and `dropbox/dropbox-sdk-js`. Each such note quotes the file
line. Google rows use the APIs' official Discovery documents; Microsoft rows use learn.microsoft.com and the
`endpoints.office.com` web service. Specs were parsed (YAML/JSON), not only searched.

Blocked pages are listed per service (`sources_blocked`) and in `../blocked-urls.md` rows 59 to 71 (13 vendors);
the hosts that would unblock them are batch R3 in `../allowlist-requests.md`. A WebFetch retry from this session hit
the same network policy (DNS refused), so it is not a way around the block.

`../tools/check_child_apps.py` checks this file (parents in the pack, unique ids, unverified rows fully null,
verified rows cited, the evidence items, and the counts below).

## Result

32 services, 115 proposed children, **61 verified with an official citation** (43 distinct pages); 54 unverified.
19 services separate partly by method and path, 3 by host only, 9 are blocked (no readable primary source for any function split) and 1 is not separable.

Counts asked for by PRO-524: **32 services** (30 new, 2 retries); **61 children with citations**; **not separable:
4** (Skype is retired; Confluence is not separable from Jira by host; monday.com puts every function in one GraphQL
body; Meet screen sharing rides the media stream). **9 services are blocked**: Salesforce, ServiceNow, Confluence,
TikTok, Snapchat, Twitch, Yahoo Mail, Pastebin, Reddit.

| # | Service | Parent | Verified children | Unverified children | Verified | Separability |
|---|---|---|---|---|---|---|
| 1 | Google Meet | `google-meet` | `google-meet-base`, `google-meet-signalling`, `google-meet-voice-video`, `google-meet-live-streaming`, `google-meet-api-spaces`, `google-meet-api-records` | - | 6/6 | partial |
| 2 | Google Photos | `google-photos` | `google-photos-api-library`, `google-photos-api-creating`, `google-photos-api-picker` | `google-photos-base`, `google-photos-uploading`, `google-photos-downloading` | 3/6 | partial |
| 3 | Google Chat | `google-chat` | `google-chat-base`, `google-chat-api-posting`, `google-chat-api-uploading`, `google-chat-api-downloading` | - | 4/4 | partial |
| 4 | SharePoint Online | `sharepoint-online` | `sharepoint-online-base`, `sharepoint-online-uploading`, `sharepoint-online-downloading`, `sharepoint-online-graph-uploading`, `sharepoint-online-graph-downloading` | - | 5/5 | partial |
| 5 | OneNote (Microsoft 365) | `ms-office365` | `ms-onenote-base`, `ms-onenote-posting`, `ms-onenote-downloading` | - | 3/3 | partial |
| 6 | Webex | `webex` | `webex-base`, `webex-file-transfer`, `webex-voice-video` | `webex-messaging` | 3/4 | partial |
| 7 | Skype | `skype` | - | `skype-base` | 0/1 | not-separable |
| 8 | Salesforce | `salesforce` | - | `salesforce-base`, `salesforce-uploading`, `salesforce-downloading` | 0/3 | blocked |
| 9 | ServiceNow | `servicenow` | - | `servicenow-base`, `servicenow-uploading`, `servicenow-downloading` | 0/3 | blocked |
| 10 | Jira | `atlassian` | `atlassian-jira-base` | `atlassian-jira-uploading`, `atlassian-jira-downloading` | 1/3 | host-only |
| 11 | Confluence | `atlassian` | - | `atlassian-confluence-base`, `atlassian-confluence-uploading`, `atlassian-confluence-downloading` | 0/3 | blocked |
| 12 | Trello | `trello` | `trello-base`, `trello-file-transfer` | `trello-uploading` | 2/3 | host-only |
| 13 | GitLab | `gitlab` | `gitlab-base`, `gitlab-uploading`, `gitlab-repo-file-posting`, `gitlab-downloading`, `gitlab-git-ssh`, `gitlab-container-registry` | - | 6/6 | partial |
| 14 | Notion | `notion` | `notion-api-uploading` | `notion-base`, `notion-downloading` | 1/3 | partial |
| 15 | monday.com | `monday` | `monday-api` | `monday-base`, `monday-uploading` | 1/3 | host-only |
| 16 | Asana | `asana` | `asana-uploading`, `asana-posting` | `asana-base`, `asana-downloading` | 2/4 | partial |
| 17 | Figma | `figma` | `figma-api-reading`, `figma-api-exporting`, `figma-api-posting` | `figma-base` | 3/4 | partial |
| 18 | Canva | `canva` | `canva-api-uploading`, `canva-api-exporting`, `canva-api-designing` | `canva-base` | 3/4 | partial |
| 19 | Miro | `miro` | `miro-api-uploading`, `miro-api-posting` | `miro-base`, `miro-downloading` | 2/4 | partial |
| 20 | TikTok | `tiktok` | - | `tiktok-base`, `tiktok-uploading`, `tiktok-posting` | 0/3 | blocked |
| 21 | Pinterest | `pinterest` | `pinterest-api-posting`, `pinterest-api-upload-register` | `pinterest-base` | 2/3 | partial |
| 22 | Snapchat | `snapchat` | - | `snapchat-base`, `snapchat-uploading` | 0/2 | blocked |
| 23 | Twitch | `twitch` | - | `twitch-base`, `twitch-streaming`, `twitch-messaging` | 0/3 | blocked |
| 24 | Vimeo | `vimeo` | `vimeo-api-upload-start`, `vimeo-api-posting` | `vimeo-base`, `vimeo-downloading` | 2/4 | partial |
| 25 | Perplexity | `perplexity` | `perplexity-api-messaging`, `perplexity-api-uploading`, `perplexity-api-downloading` | `perplexity-base` | 3/4 | partial |
| 26 | DeepSeek | `deepseek` | `deepseek-api-messaging` | `deepseek-base`, `deepseek-uploading` | 1/3 | partial |
| 27 | Mistral (Le Chat) | `mistral-ai` | `mistral-api-messaging`, `mistral-api-uploading`, `mistral-api-downloading` | `mistral-le-chat-base`, `mistral-le-chat-uploading` | 3/5 | partial |
| 28 | Yahoo Mail | `yahoo-mail` | - | `yahoo-mail-base`, `yahoo-mail-sending`, `yahoo-mail-uploading` | 0/3 | blocked |
| 29 | Proton Mail | `proton-mail` | `proton-mail-api-uploading`, `proton-mail-api-downloading`, `proton-mail-api-sending` | `proton-mail-base` | 3/4 | partial |
| 30 | pCloud | `pcloud` | `pcloud-api`, `pcloud-api-uploading` | `pcloud-base`, `pcloud-downloading` | 2/4 | partial |
| 31 | Pastebin (retry of wave 0) | `pastebin` | - | `pastebin-base`, `pastebin-posting` | 0/2 | blocked |
| 32 | Reddit (retry of wave 0) | `reddit` | - | `reddit-base`, `reddit-posting`, `reddit-uploading` | 0/3 | blocked |

## Where a function cannot be separated

- **Skype**: "As of May 5th, 2025, Skype is retired" (support.microsoft.com); only `skype-base` is kept, unverified.
- **Confluence versus Jira**: Atlassian's domain table says "*.atlassian.net Jira and Confluence use this" (same for
  `*.jira.com`). A path split needs developer.atlassian.com (row 63). Atlassian also advises excluding its domains
  from TLS inspection, so path rules may never see this traffic.
- **monday.com**: one GraphQL endpoint (`https://api.monday.com/v2`); the operation is in the body.
- **Google Meet**: screen share and in-meeting chat travel with the media session (UDP 3478, 19302-19309).
- **Proton Mail** (separable, but opaque): the attachment parts are client-encrypted packets (`KeyPacket`,
  `DataPacket`, `Signature`), so a proxy sees that a file moves, never its content.
- **Upload targets given at run time**: Pinterest (`upload_url`), Vimeo (upload link), Figma and Canva (export URLs),
  SharePoint/OneDrive (`uploadUrl`, `downloadUrl`): the documented call is the rule; the follow-up host is not.

## Findings for Engine (ENGINE-FIELD, Go only)

1. **More shared Google API hosts**: `meet.googleapis.com`, `meetings.googleapis.com`, `hangouts.googleapis.com`,
   `photoslibrary.googleapis.com`, `photospicker.googleapis.com` and `chat.googleapis.com` all map to `google-base`
   in 2026.11.9, so these children need a host-to-parent override (or path-based parent) before they can match.
2. **API children under a different parent**: `api.perplexity.ai` is `perplexity-api`, `api.deepseek.com` is
   `deepseek-api`, `api.mistral.ai` is `mistral-api` (as `openai-platform` in wave 0).
3. **graph.microsoft.com** carries SharePoint and OneNote functions too (wave 0 finding 1): parent from the path
   (`/sites/...`, `/.../onenote/...`).
4. **NAME-BASED candidate**: `*.onenote.com` ("OneNote notebooks", Microsoft 365 endpoint set 49) has no pack entry.
5. **Virtual-hosted S3 bucket**: Trello attachments are `trello-attachments.s3.amazonaws.com`; the parent has to come
   from the full name, never from `s3.amazonaws.com`.

## SEC-CHILD-3 vendor evidence for Engine (PRO-510)

10 items, 9 verified from 15 distinct official pages, 1 unverified. Each item is in `wave-1.json` under `sec_child_3` with its citation(s).

| Item | Verified | What the vendor says | What it means for a rule |
|---|---|---|---|
| `gmail-multipart-resumable` | yes | Every Gmail upload method has two path forms, '/upload/gmail/v1/...' (simple) and '/resumable/upload/gmail/v1/...' (resumable), both with multipart: true: users.messages.send, users.messages.insert, users.messages.import, users.drafts.create, users.drafts.send (POST) and users.drafts.update (PUT /upload/gmail/v1/users/{userId}/drafts/{id}). uploadType is a query parameter ('Legacy upload protocol for media (e.g. "media", "multipart")'), not a path segment. | A rule keyed on '/upload/gmail' alone misses '/resumable/upload/gmail'; drafts.update is PUT. Wave 0 rows cover the five POST methods; drafts.update (PUT) is new here. |
| `graph-beta` | yes | 'APIs debut in the beta version and are accessible in the https://graph.microsoft.com/beta endpoint' and v1.0 'in the https://graph.microsoft.com/v1.0 endpoint'. URL form '{HTTP method} https://graph.microsoft.com/{version}/{resource}?{query-parameters}' (use-the-api). | Every graph.microsoft.com child path must accept both /v1.0/ and /beta/ as the first segment. |
| `graph-case-insensitive` | yes | 'Path URL resource names, query parameters, and action parameters and values are case insensitive. However, values you assign, entity IDs, and other base64-encoded values are case-sensitive.' traverse-the-graph: 'Assume path URL resource names, query parameters, action and function names ... are not case-sensitive.' OneDrive: path identifiers used with colons and filenames in the URL 'are not case-sensitive', but metadata path identifiers such as '/items/{item-id}/image' 'are case-sensitive'. | Match Graph resource-name segments case-insensitively (/ME/DRIVE/... is /me/drive/...); keep IDs as literal wildcards. The OneDrive page's case-sensitive metadata segments are a narrower exception for that API surface. |
| `graph-dollar-batch` | yes | 'Microsoft Graph implements the $batch OData URL path segment'; 'POST https://graph.microsoft.com/v1.0/$batch' (or beta); each inner request has a relative 'url' ('while the absolute URL is https://graph.microsoft.com/v1.0/users, this url is /users'); 'JSON batch requests are currently limited to 20 individual requests.' Also: 'On the beta endpoint, the $ prefix is optional' for query options (query-parameters page). | A $batch POST carries up to 20 operations (methods and paths) in its JSON body, so a path rule sees only '/$batch': either parse the body (bounded by the request budget) or treat $batch as 'any Graph function'. |
| `google-batch` | yes | Discovery 'batchPath' is 'batch' for gmail.googleapis.com (and for meet, chat, photoslibrary), and 'batch/drive/v3' and 'batch/drive/v2' on www.googleapis.com for Drive. | POST /batch (or /batch/drive/v3) wraps several API calls in one multipart/mixed body; the inner method and path are not in the outer request line. |
| `drive-v2` | yes | Drive v2 is still published: rootUrl https://www.googleapis.com/, servicePath 'drive/v2/'; files.insert POST simple '/upload/drive/v2/files', resumable '/resumable/upload/drive/v2/files'; files.update PUT '/upload/drive/v2/files/{fileId}' and '/resumable/upload/drive/v2/files/{fileId}'; files.get GET 'files/{fileId}' with media download, files.export GET 'files/{fileId}/export'. v3 uses POST '/upload/drive/v3/files' and PATCH '/upload/drive/v3/files/{fileId}'. | Drive upload rules need v2 and v3 paths and both POST/PUT (v2) and POST/PATCH (v3) methods. |
| `telegram-case-insensitive` | yes | 'All queries to the Telegram Bot API must be served over HTTPS and need to be presented in this form: https://api.telegram.org/bot<token>/METHOD_NAME'; 'All methods in the Bot API are case-insensitive.' Files: 'https://api.telegram.org/file/bot<token>/<file_path>'. | sendDocument, SENDDOCUMENT and senddocument are the same method: compare the method segment case-insensitively. The path also carries the bot token, which must never be emitted. |
| `discord-versions` | yes | 'You should specify which version to use by including it in the request path like https://discord.com/api/v{version_number}. Omitting the version number from the route will route requests to the current default version (marked below).' Table: v10 Available, v9 Available, v8 and v7 Deprecated, v6 Deprecated and Default, v5 to v3 Discontinued. | Discord child paths must accept /api/v10/, /api/v9/ (and deprecated v8, v7, v6) and the unversioned /api/ prefix, which routes to v6. Wave 0 rows that name /api/v10 only are too narrow. |
| `dropbox-arg` | yes | Dropbox's official SDKs: 'Download style means that the route argument goes in a Dropbox-API-Arg header'; upload style sets Content-Type 'application/octet-stream' and the Dropbox-API-Arg header; RPC style is 'application/json'. Hosts: API_CONTENT_HOST 'content' + '.dropboxapi.com', API_HOST 'api' + '.dropboxapi.com' (session.py). The JS SDK sends method POST with headers['Dropbox-API-Arg'] for download and upload. | The file path and options of a Dropbox upload or download are in the Dropbox-API-Arg header (JSON), not in the URL; both directions are POST to content.dropboxapi.com. |
| `dropbox-arg-url-parameter` | **no** | UNVERIFIED: whether content endpoints also accept the argument as a URL query parameter 'arg' (and 'authorization') is stated, if anywhere, in the HTTP documentation's 'Formats' section on www.dropbox.com, which is SOURCE BLOCKED (row 48). Not in the SDK files read. | Until read, a rule must not assume the header is the only place the argument can appear. |
