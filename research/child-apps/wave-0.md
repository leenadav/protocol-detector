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
- Blocked pages are listed per service (`sources_blocked`) and in `../blocked-urls.md` rows 45 to 54; the hosts
  that would unblock them are batch R2 in `../allowlist-requests.md`.

## Result

30 services, 99 proposed children, **53 verified with an official citation** (36 distinct pages); 46 unverified.
7 services are fully blocked (Box, WhatsApp, Discord, X, Pastebin, Mega, Reddit), 4 are not separable by these
signals (Telegram, iCloud, TeamViewer, AnyDesk), 5 separate by host only, 14 partly by method and path.

| # | Service | Parent | Verified children | Unverified children | Verified | Separability |
|---|---|---|---|---|---|---|
| 1 | Gmail | `gmail` | `gmail-base`, `gmail-api`, `gmail-api-uploading` | `gmail-uploading`, `gmail-downloading` | 3/5 | partial |
| 2 | Outlook.com / Outlook on the web | `outlook-web` | `outlook-web-base`, `outlook-web-sending`, `outlook-web-uploading` | `outlook-web-downloading` | 3/4 | partial |
| 3 | Google Drive | `google-drive` | `google-drive-base`, `google-drive-content` | `google-drive-uploading`, `google-drive-downloading` | 2/4 | host-only |
| 4 | Google Docs | `google-drive` | `google-docs-base` | `google-docs-editing`, `google-docs-downloading` | 1/3 | host-only |
| 5 | OneDrive | `ms-onedrive` | `ms-onedrive-uploading`, `ms-onedrive-uploading-session`, `ms-onedrive-downloading` | `ms-onedrive-base` | 3/4 | partial |
| 6 | Dropbox | `dropbox` | `dropbox-base`, `dropbox-downloading` | `dropbox-uploading` | 2/3 | partial |
| 7 | Box | `box` | - | `box-base`, `box-uploading`, `box-downloading` | 0/3 | blocked |
| 8 | WeTransfer | `wetransfer` | `wetransfer-base`, `wetransfer-file-transfer` | `wetransfer-uploading` | 2/3 | host-only |
| 9 | Slack | `slack` | `slack-base`, `slack-messaging` | `slack-uploading`, `slack-downloading` | 2/4 | partial |
| 10 | Microsoft Teams | `ms-teams` | `ms-teams-base`, `ms-teams-voice-video`, `ms-teams-posting` | `ms-teams-file-transfer` | 3/4 | partial |
| 11 | Zoom | `zoom` | `zoom-base`, `zoom-voice-video` | `zoom-file-transfer` | 2/3 | partial |
| 12 | WhatsApp Web | `whatsapp` | - | `whatsapp-base`, `whatsapp-file-transfer` | 0/2 | blocked |
| 13 | Telegram Web | `telegram` | `telegram-web-base` | `telegram-file-transfer` | 1/2 | not-separable |
| 14 | Discord | `discord` | - | `discord-base`, `discord-voice-video`, `discord-uploading` | 0/3 | blocked |
| 15 | Facebook | `facebook` | `facebook-posting`, `facebook-uploading` | `facebook-base` | 2/3 | partial |
| 16 | Instagram | `instagram` | `instagram-posting`, `instagram-uploading` | `instagram-base` | 2/3 | partial |
| 17 | X / Twitter | `twitter` | - | `twitter-base`, `twitter-posting`, `twitter-uploading` | 0/3 | blocked |
| 18 | LinkedIn | `linkedin` | `linkedin-posting`, `linkedin-uploading`, `linkedin-messaging` | `linkedin-base` | 3/4 | partial |
| 19 | YouTube | `youtube` | `youtube-base` | `youtube-uploading`, `youtube-posting` | 1/3 | host-only |
| 20 | ChatGPT | `openai-chatgpt` | `openai-chatgpt-base`, `openai-chatgpt-messaging`, `openai-chatgpt-uploading`, `openai-chatgpt-voice`, `openai-platform-uploading`, `openai-platform-realtime` | - | 6/6 | partial |
| 21 | Claude | `anthropic-claude` | `anthropic-api-uploading`, `anthropic-api-downloading` | `anthropic-claude-base`, `anthropic-claude-uploading` | 2/4 | partial |
| 22 | Gemini | `google-gemini` | `google-gemini-base`, `google-gemini-api-uploading`, `google-gemini-api-live` | `google-gemini-uploading` | 3/4 | partial |
| 23 | Microsoft Copilot | `ms-copilot` | `ms-copilot-base` | `ms-copilot-uploading` | 1/2 | host-only |
| 24 | GitHub | `github` | `github-git-transport`, `github-uploading`, `github-downloading`, `github-release-uploading`, `github-posting` | `github-base` | 5/6 | partial |
| 25 | Pastebin | `pastebin` | - | `pastebin-base`, `pastebin-posting` | 0/2 | blocked |
| 26 | iCloud | `icloud` | `icloud-base`, `icloud-iwork` | `icloud-file-transfer` | 2/3 | not-separable |
| 27 | Mega | `mega` | - | `mega-base`, `mega-file-transfer` | 0/2 | blocked |
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
- **WhatsApp**, **Mega**: expected end-to-end or client-side encrypted, but no page could be read: `UNVERIFIED`.

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
