# Child apps, wave 0: 30 services already in the pack (PRO-495)

Feeds Engine PRO-492 (Lee, 2026-11-27: enterprise App-ID model with child apps per function). Data:
`wave-0.json` (schema `child-apps/v1`). Parent ids are those of `go/internal/content/pack.json` at `5cb35d2`
(release `2026.11.9`). Sources accessed 2026-11-27. PRO-491 (Research Lab, new services) has no output on `main`
yet, so nothing here could be cross-linked; none of these 30 should be repeated there.

## Method

- **Official vendor pages only**: API references and network-requirement pages, one citation URL per child, with the
  page's own date where it shows one. Nothing from nDPI, Wireshark, Suricata, Snort or OpenAppID.
- **What a decrypting proxy sees**: host/SNI, HTTP method, path pattern, request content type, direction, WebSocket
  upgrade. Non-HTTP signals (ports, UDP media) go in `transport`: an HTTP rule cannot see them, and UDP is off the
  Phase 1 observed path.
- **Unverified children keep every signal field `null`.** They are proposals for the id space only, never rules.
- **API versus web UI** (`surface`): most documented paths are vendor API endpoints (scripts, integrations, bots).
  The first-party web clients' internal request paths are not published by any vendor read here, so a rule built
  from `surface: api` rows will not match the browser UI. That is not a gap this lane can close from primary
  sources.
- Blocked pages are listed per service (`sources_blocked`) and in `../blocked-urls.md` rows 45 to 58; the hosts
  that would unblock them are batch R2 in `../allowlist-requests.md`.
- **Vendor spec and SDK repositories** (follow-up, Hermes's decision PRO-501): where a vendor's documentation site was
  not reachable, Box, Discord, X and Mega rows cite the vendor's own published OpenAPI spec or SDK source on
  `raw.githubusercontent.com` (`box/box-openapi`, `discord/discord-api-spec` and `discord/discord-api-docs`,
  `xdevplatform/xdk-python`, `meganz/sdk` and `meganz/webclient`). Each such row names the file and the line content;
  `citation_also` lists a second source for the same row. Their documentation-site rows stay open (49, 51, 52, 53).
- `../tools/check_child_apps.py` checks this file: parents in the pack, unique ids, unverified rows fully null,
  verified rows cited, and the counts below.

## Result

30 services, 105 proposed children, **64 verified with an official citation** (45 distinct pages); 41 unverified.
3 services are fully blocked (WhatsApp, Pastebin, Reddit), 5 are not separable by these signals (Telegram, iCloud,
Mega, TeamViewer, AnyDesk), 5 separate by host only, 17 partly by method and path.

| # | Service | Parent | Verified children | Unverified children | Verified | Separability |
|---|---|---|---|---|---|---|
| 1 | Gmail | `gmail` | `gmail-base`, `gmail-api`, `gmail-api-uploading`, `gmail-api-uploading-simple`, `gmail-api-uploading-resumable` | `gmail-uploading`, `gmail-downloading` | 5/7 | partial |
| 2 | Outlook.com / Outlook on the web | `outlook-web` | `outlook-web-base`, `outlook-web-sending`, `outlook-web-uploading` | `outlook-web-downloading` | 3/4 | partial |
| 3 | Google Drive | `google-drive` | `google-drive-base`, `google-drive-content` | `google-drive-uploading`, `google-drive-downloading` | 2/4 | host-only |
| 4 | Google Docs | `google-drive` | `google-docs-base` | `google-docs-editing`, `google-docs-downloading` | 1/3 | host-only |
| 5 | OneDrive | `ms-onedrive` | `ms-onedrive-uploading`, `ms-onedrive-uploading-session`, `ms-onedrive-downloading` | `ms-onedrive-base` | 3/4 | partial |
| 6 | Dropbox | `dropbox` | `dropbox-base`, `dropbox-downloading` | `dropbox-uploading` | 2/3 | partial |
| 7 | Box | `box` | `box-uploading`, `box-uploading-session`, `box-downloading` | `box-base` | 3/4 | partial |
| 8 | WeTransfer | `wetransfer` | `wetransfer-base`, `wetransfer-file-transfer` | `wetransfer-uploading` | 2/3 | host-only |
| 9 | Slack | `slack` | `slack-base`, `slack-messaging` | `slack-uploading`, `slack-downloading` | 2/4 | partial |
| 10 | Microsoft Teams | `ms-teams` | `ms-teams-base`, `ms-teams-voice-video`, `ms-teams-posting` | `ms-teams-file-transfer` | 3/4 | partial |
| 11 | Zoom | `zoom` | `zoom-base`, `zoom-voice-video` | `zoom-file-transfer` | 2/3 | partial |
| 12 | WhatsApp Web | `whatsapp` | - | `whatsapp-base`, `whatsapp-file-transfer` | 0/2 | blocked |
| 13 | Telegram Web | `telegram` | `telegram-web-base` | `telegram-file-transfer` | 1/2 | not-separable |
| 14 | Discord | `discord` | `discord-posting`, `discord-uploading`, `discord-downloading` | `discord-base`, `discord-voice-video` | 3/5 | partial |
| 15 | Facebook | `facebook` | `facebook-posting`, `facebook-uploading` | `facebook-base` | 2/3 | partial |
| 16 | Instagram | `instagram` | `instagram-posting`, `instagram-uploading` | `instagram-base` | 2/3 | partial |
| 17 | X / Twitter | `twitter` | `twitter-posting`, `twitter-uploading` | `twitter-base` | 2/3 | partial |
| 18 | LinkedIn | `linkedin` | `linkedin-posting`, `linkedin-uploading`, `linkedin-messaging` | `linkedin-base` | 3/4 | partial |
| 19 | YouTube | `youtube` | `youtube-base` | `youtube-uploading`, `youtube-posting` | 1/3 | host-only |
| 20 | ChatGPT | `openai-chatgpt` | `openai-chatgpt-base`, `openai-chatgpt-messaging`, `openai-chatgpt-uploading`, `openai-chatgpt-voice`, `openai-platform-uploading`, `openai-platform-realtime` | - | 6/6 | partial |
| 21 | Claude | `anthropic-claude` | `anthropic-api-uploading`, `anthropic-api-downloading` | `anthropic-claude-base`, `anthropic-claude-uploading` | 2/4 | partial |
| 22 | Gemini | `google-gemini` | `google-gemini-base`, `google-gemini-api-uploading`, `google-gemini-api-live` | `google-gemini-uploading` | 3/4 | partial |
| 23 | Microsoft Copilot | `ms-copilot` | `ms-copilot-base` | `ms-copilot-uploading` | 1/2 | host-only |
| 24 | GitHub | `github` | `github-git-transport`, `github-uploading`, `github-downloading`, `github-release-uploading`, `github-posting` | `github-base` | 5/6 | partial |
| 25 | Pastebin | `pastebin` | - | `pastebin-base`, `pastebin-posting` | 0/2 | blocked |
| 26 | iCloud | `icloud` | `icloud-base`, `icloud-iwork` | `icloud-file-transfer` | 2/3 | not-separable |
| 27 | Mega | `mega` | `mega-api` | `mega-base`, `mega-file-transfer` | 1/3 | not-separable |
| 28 | TeamViewer | `teamviewer` | `teamviewer-remote-control` | `teamviewer-file-transfer` | 1/2 | not-separable |
| 29 | AnyDesk | `anydesk` | `anydesk-remote-control` | `anydesk-file-transfer` | 1/2 | not-separable |
| 30 | Reddit | `reddit` | - | `reddit-base`, `reddit-posting`, `reddit-uploading` | 0/3 | blocked |

## Where a function cannot be separated

- **Telegram**: every function is MTProto inside one obfuscated, encrypted WebSocket or TCP stream
  (`core.telegram.org/mtproto/transports`); file parts are RPCs inside it (`core.telegram.org/api/files`).
- **TeamViewer**, **AnyDesk**: file transfer, chat and control share one session (TeamViewer's port-5938 protocol is
  unpublished; AnyDesk asks for TLS inspection to be bypassed). Only the remote-control parent is separable.
- **iCloud**: hosts carry no published upload/download split; with Advanced Data Protection the data is end-to-end
  encrypted (`support.apple.com/en-us/102651`).
- **Microsoft Copilot**: Microsoft publishes no per-feature names.
- **Mega**: every command goes to `g.api.mega.co.nz/cs` with the command in the JSON body, transfer hosts come at run
  time, and data is encrypted on the client ("User Controlled Encryption (UCE)", `meganz/webclient` README). Only
  the API itself is separable (`mega-api`).
- **Discord voice and video**: UDP media to a run-time server, moving to end-to-end encryption (DAVE,
  `developers/topics/voice-connections.mdx`).
- **Box sharing**: `PUT /2.0/files/{file_id}` with a `shared_link` body; the same method and path rename or move a
  file, so only the body separates it.
- **WhatsApp**: expected end-to-end encrypted, but no page could be read: `UNVERIFIED`.

## Findings for Engine (ENGINE-FIELD, Go only)

1. **Shared API hosts need path-based parents.** `graph.microsoft.com` (OneDrive, Outlook, Teams) maps to `ms-base`;
   `www.googleapis.com` (Gmail API), `generativelanguage.googleapis.com` (Gemini API) and `youtubei.googleapis.com`
   map to `google-base`; `graph.facebook.com` and `rupload.facebook.com` serve Instagram publishing but map to
   `facebook`. A child rule on these hosts must select the parent from the path, which needs the method and path
   fields from a decrypting proxy (PRO-492).
2. **API children under a different parent.** `api.openai.com` is `openai-platform` and `api.anthropic.com` is
   `anthropic-api`, so `openai-platform-*` and `anthropic-api-*` children belong there, not under the consumer apps.
3. **Redirected and opaque upload URLs.** OneDrive and Outlook upload sessions PUT to an opaque `uploadUrl`
   (examples `*.up.1drv.com`, `outlook.office.com/api/...AttachmentSessions`); OneDrive downloads 302 to a
   preauthenticated URL. Match the documented POST/GET, and treat the follow-up host as an example only.
4. **NAME-BASED candidate**: `youtubei.googleapis.com` and `youtube.googleapis.com` are YouTube hosts per Google's
   Restricted Mode page but resolve to `google-base` today.

## Sample check of the follow-up rows (PRO-501, rerun 2026-11-27)

`random.seed(1); random.sample(rows, min(20, len(rows)))` over the 11 verified rows added after `e98f784` (9 for Box,
Discord, X and Mega in `c4842af`, and the two Gmail upload-protocol rows), so all 11 were checked. Each row's citation
and `citation_also` were fetched again and read: the host, every path key and the content type of the row were found in
the cited source, in the operation the row names (the OpenAPI and Discovery files were parsed, not only searched).
`check_child_apps.py` passes on the file.

| Row | Evidence in the cited source | Result |
|---|---|---|
| `box-uploading` | servers `https://upload.box.com/api/2.0`; `/files/content`, `/files/{file_id}/content` POST, `multipart/form-data` | OK |
| `box-uploading-session` | `/files/upload_sessions`, `/files/{file_id}/upload_sessions` POST on upload.box.com, `application/json` | OK |
| `box-downloading` | servers `https://api.box.com/2.0`; `/files/{file_id}/content` GET, 302 "on `dl.boxcloud.com`" | OK |
| `discord-posting` | servers `https://discord.com/api/v10`; create_message, execute_webhook; `application/json` | OK |
| `discord-uploading` | "`https://discord.com/api/v{version_number}`"; "file uploads use a `multipart/form-data` request body" | OK |
| `discord-downloading` | CDN base `https://cdn.discordapp.com/`; example `https://cdn.discordapp.com/attachments/...` | OK |
| `twitter-posting` | `base_url: str = "https://api.x.com"`; `"/2/tweets"`; `application/json` | OK |
| `twitter-uploading` | same base_url; `/2/media/upload/initialize`, `/{id}/append`, `/{id}/finalize`; `application/json` | OK |
| `mega-api` | `g_APIURL_default = "https://g.api.mega.co.nz/"`; `posturl.append("cs?id=")` | OK |
| `gmail-api-uploading-simple` | rootUrl `https://gmail.googleapis.com/`; simple paths of 5 methods; accept `message/*`; `uploadType` | OK |
| `gmail-api-uploading-resumable` | resumable paths of the same 5 methods; accept `message/*` | OK |

Result: **11/11 OK, 0 wrong, 0 unsupported.** The first run of this check (before `c4842af`) caught a Discord webhook
path without `/v10`, fixed in that commit. No row uses a shared-hosting or tenant domain; Box's upload-session `PUT`
host is a server variable (`{box-upload-server}`) and is left out of `host_sni`.

## Rows corrected after Research Lead's sample (PRO-507)

| Row | Finding | Disposition |
|---|---|---|
| `google-docs-base` | `*.c.docs.google.com` not on the page | Kept: re-read 2026-11-27, the cited page lists `*.c.docs.google.com:443/HTTPS` for Drive and the Docs editors ("Last updated 2026-11-10 UTC"); the line is now quoted in `notes` |
| `github-release-uploading` | `application/octet-stream` only in the curl example | `content_type` set to null: the page asks for "the media type of the asset" |
| `google-gemini-base` | surface `web` not stated | `surface` set to null; the host stays (allowlist group "Generative AI") |
| `outlook-web-uploading` | opaque uploadUrl host in the rule; prose path | Rule is now the documented POST only: `graph.microsoft.com`, `POST`, `/v1.0/me/messages/{id}/attachments/createUploadSession`, `application/json`; the PUT to the opaque uploadUrl is in `notes` |
| `slack-base` | `slack.com` only in a help-centre link | Re-cited to "Approve Slack workspaces for your network": "configure ... proxy server to intercept traffic to slack.com" |
| `anydesk-remote-control` | firewall URL 404 | Re-verified: the old URL answers 301 to `https://support.anydesk.com/firewall` ("Configure firewalls for AnyDesk", updated Jan 21, 2026), which states `*.net.anydesk.com` and TCP 80, 443, 6568; citation updated |

The Gmail multipart and resumable upload forms (Engine PRO-510) are the two `gmail-api-uploading-*` rows, from
Gmail's official Discovery document.
