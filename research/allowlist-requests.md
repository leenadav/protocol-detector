# Network allowlist requests (method v2)

Each batch is one approval request. Every host is vendor-owned or a vendor-published feed; nothing else is requested.
Lee or Hermes approves through the environment prompt. Reason codes: **WEB** = public web-client or login page loaded without
signing in, for dependency mapping (item 2); **FEED** = vendor machine-readable endpoint feed (item 4).

## Batch R1 (2026-11-19): web-client entry pages and one feed

| Host | Reason | Spec | Page |
|---|---|---|---|
| `account.adobe.com` | WEB | `apps/adobe-cloud.md` | `https://account.adobe.com/` |
| `account.box.com` | WEB | `apps/box.md` | `https://account.box.com/login` |
| `account.jetbrains.com` | WEB | `apps/jetbrains-ai.md` | `https://account.jetbrains.com/login` |
| `admin.duosecurity.com` | WEB | `apps/duo-security.md` | `https://admin.duosecurity.com/` |
| `app.goto.com` | WEB | `apps/goto.md` | `https://app.goto.com/` |
| `app.grammarly.com` | WEB | `apps/grammarly.md` | `https://app.grammarly.com/` |
| `app.zoom.us` | WEB | `apps/zoom.md` | `https://app.zoom.us/wc` |
| `chat.deepseek.com` | WEB | `apps/deepseek.md` | `https://chat.deepseek.com/` |
| `chat.mistral.ai` | WEB | `apps/mistral.md` | `https://chat.mistral.ai/` |
| `citrix.cloud.com` | WEB | `apps/citrix-cloud.md` | `https://citrix.cloud.com/` |
| `claude.ai` | WEB | `apps/anthropic-claude.md` | `https://claude.ai/login` |
| `clients.amazonworkspaces.com` | WEB | `apps/amazon-workspaces.md` | `https://clients.amazonworkspaces.com/` |
| `console.gotoresolve.com` | WEB | `apps/logmein-resolve.md` | `https://console.gotoresolve.com/` |
| `copilot.microsoft.com` | WEB | `apps/microsoft-copilot.md` | `https://copilot.microsoft.com/` |
| `dashboard.ngrok.com` | WEB | `apps/ngrok.md` | `https://dashboard.ngrok.com/login` |
| `drive.google.com` | WEB | `apps/onedrive-drive-personal-business.md` | `https://drive.google.com/` |
| `gemini.google.com` | WEB | `apps/google-gemini.md` | `https://gemini.google.com/` |
| `github.com` | WEB | `apps/github-copilot.md` | `https://github.com/copilot` |
| `gitlab.com` | WEB | `apps/gitlab.md` | `https://gitlab.com/users/sign_in` |
| `grok.com` | WEB | `apps/xai-grok.md` | `https://grok.com/` |
| `hub.docker.com` | WEB | `apps/docker-hub.md` | `https://hub.docker.com/` |
| `id.atlassian.com` | WEB | `apps/atlassian.md` | `https://id.atlassian.com/login` |
| `identity.getpostman.com` | WEB | `apps/postman.md` | `https://identity.getpostman.com/login` |
| `intune.microsoft.com` | WEB | `apps/ms-intune.md` | `https://intune.microsoft.com/` |
| `login.okta.com` | WEB | `apps/okta.md` | `https://login.okta.com/` |
| `login.salesforce.com` | WEB | `apps/salesforce.md` | `https://login.salesforce.com/` |
| `login.tailscale.com` | WEB | `apps/tailscale.md` | `https://login.tailscale.com/` |
| `login.teamviewer.com` | WEB | `apps/teamviewer.md` | `https://login.teamviewer.com/` |
| `mail.google.com` | WEB | `apps/google-workspace.md` | `https://mail.google.com/` |
| `meet.google.com` | WEB | `apps/google-workspace.md` | `https://meet.google.com/` |
| `miro.com` | WEB | `apps/miro.md` | `https://miro.com/login/` |
| `my.1password.com` | WEB | `apps/1password.md` | `https://my.1password.com/signin` |
| `my.anydesk.com` | WEB | `apps/anydesk.md` | `https://my.anydesk.com/` |
| `my.splashtop.com` | WEB | `apps/splashtop.md` | `https://my.splashtop.com/login` |
| `onedrive.live.com` | WEB | `apps/onedrive-drive-personal-business.md` | `https://onedrive.live.com/` |
| `remotedesktop.google.com` | WEB | `apps/chrome-remote-desktop.md` | `https://remotedesktop.google.com/` |
| `security.microsoft.com` | WEB | `apps/ms-defender-endpoint.md` | `https://security.microsoft.com/` |
| `teams.microsoft.com` | WEB | `apps/microsoft-365.md` | `https://teams.microsoft.com/` |
| `vault.bitwarden.com` | WEB | `apps/bitwarden.md` | `https://vault.bitwarden.com/` |
| `web.telegram.org` | WEB | `apps/telegram.md` | `https://web.telegram.org/` |
| `web.webex.com` | WEB | `apps/webex.md` | `https://web.webex.com/` |
| `web.whatsapp.com` | WEB | `apps/whatsapp.md` | `https://web.whatsapp.com/` |
| `windows.cloud.microsoft` | WEB | `apps/ms-virtual-desktop.md` | `https://windows.cloud.microsoft/` |
| `www.dropbox.com` | WEB | `apps/dropbox.md` | `https://www.dropbox.com/login` |
| `www.figma.com` | WEB | `apps/figma.md` | `https://www.figma.com/login` |
| `www.icloud.com` | WEB | `apps/apple-icloud.md` | `https://www.icloud.com/` |
| `www.loom.com` | WEB | `apps/loom.md` | `https://www.loom.com/login` |
| `www.notion.so` | WEB | `apps/notion.md` | `https://www.notion.so/login` |
| `www.office.com` | WEB | `apps/microsoft-365.md` | `https://www.office.com/` |
| `www.perplexity.ai` | WEB | `apps/perplexity.md` | `https://www.perplexity.ai/` |
| `www.zendesk.com` | WEB | `apps/zendesk.md` | `https://www.zendesk.com/login/` |
| `ip-ranges.salesforce.com` | FEED | `apps/salesforce.md` | `https://ip-ranges.salesforce.com/ip-ranges.json` (cited by the Salesforce article; recorded for change tracking only, the catalog uses no IPs) |

### Status of R1 (2026-11-19)

- **Approved and added (20)**: `account.adobe.com` through `grok.com` in the order of the first request
  (`account.adobe.com`, `account.box.com`, `account.jetbrains.com`, `admin.duosecurity.com`, `app.goto.com`,
  `app.grammarly.com`, `app.zoom.us`, `chat.deepseek.com`, `chat.mistral.ai`, `citrix.cloud.com`, `claude.ai`,
  `clients.amazonworkspaces.com`, `console.gotoresolve.com`, `copilot.microsoft.com`, `dashboard.ngrok.com`,
  `drive.google.com`, `gemini.google.com`, `github.com`, `gitlab.com`, `grok.com`).
- **BLOCKED (32)**: the environments service rejected every further addition, even a request for 5 hosts,
  without a reason. The allowlist now holds 130 hosts, so this lane takes it to be a size limit
  (`UNVERIFIED`). The remaining R1 hosts in the table above can be added by Lee in the environment settings,
  or in a new environment dedicated to dependency mapping. This lane does not work around the limit.

## Batch R2 (2026-11-27, PRO-495): vendor API references for child apps (not yet requested)

Reason code **API** = vendor API reference read for child-app signals (method, path, content type). Read-only; one
approval for the batch. Unblocks `blocked-urls.md` rows 45 to 53 and 55 to 58.

| Host | Reason | Use | Page |
|---|---|---|---|
| `developers.google.com` | API | Gmail, Drive, YouTube | rows 45 to 47 |
| `www.dropbox.com` | API | Dropbox | row 48 |
| `developer.box.com` | API | Box | row 49 |
| `docs.slack.dev` | API | Slack | row 50 |
| `discord.com` | API | Discord | row 51 |
| `docs.x.com` | API | X | row 52 |
| `pastebin.com` | API | Pastebin | row 53 |
| `www.reddit.com` | API | Reddit | row 53 |
| `mega.io` | API | Mega | row 53 |
| `developer.wetransfer.com` | API | WeTransfer | row 55 |
| `docs.slack.dev` | API | Slack file download | row 56 (also row 50) |
| `developers.zoom.us` | API | Zoom | row 57 |
| `support.reddithelp.com` | API | Reddit | row 58 |

## Batch R3 (2026-11-27, PRO-524): vendor API references for child apps wave 1 (not yet requested)

Reason code **API**, as batch R2. Read-only; one approval for the batch. Unblocks `blocked-urls.md` rows 59 to 71.

| Host | Reason | Use | Page |
|---|---|---|---|
| `developers.google.com` | API | Google Photos upload (also batch R2) | row 59 |
| `developer.webex.com` | API | Webex | row 60 |
| `developer.salesforce.com` | API | Salesforce | row 61 |
| `developer.servicenow.com` | API | ServiceNow | row 62 |
| `developer.atlassian.com` | API | Jira, Confluence, Trello | row 63 |
| `developers.notion.com` | API | Notion | row 64 |
| `developer.monday.com` | API | monday.com | row 65 |
| `developers.tiktok.com` | API | TikTok | row 66 |
| `developers.snap.com`, `help.snapchat.com` | API | Snapchat | row 67 |
| `dev.twitch.tv`, `help.twitch.tv` | API | Twitch | row 68 |
| `help.yahoo.com` | API | Yahoo Mail | row 69 |
| `proton.me` | API | Proton Mail | row 70 |
| `docs.pcloud.com`, `www.pcloud.com` | API | pCloud | row 71 |

## Batch R4 (2026-11-27, PRO-550): vendor API references for child apps wave 2 (not yet requested)

Reason code **API**, as batches R2 and R3. Read-only; one approval for the batch. Unblocks `blocked-urls.md` rows 72 to 92.

| Host | Reason | Use | Page |
|---|---|---|---|
| `www.zoho.com`, `www.zoho.eu`, `help.zoho.com` | API | Zoho | row 72 |
| `www.fastmail.com` | API | Fastmail | row 73 |
| `developers.docusign.com`, `support.docusign.com`, `www.docusign.com` | API | DocuSign | row 74 |
| `developers.hellosign.com`, `faq.hellosign.com`, `sign.dropbox.com` | API | Dropbox Sign | row 75 |
| `www.adobe.com`, `developer.adobe.com` | API | Adobe | row 76 |
| `dev.evernote.com`, `help.evernote.com` | API | Evernote | row 77 |
| `docs.replit.com`, `replit.com`, `blog.replit.com` | API | Replit | row 78 |
| `docs.netlify.com` | API | Netlify | row 79 |
| `vercel.com` | API | Vercel | row 80 |
| `developer.zendesk.com` | API | Zendesk | row 81 |
| `developers.hubspot.com` | API | HubSpot | row 82 |
| `developers.smartsheet.com` | API | Smartsheet | row 83 |
| `airtable.com` | API | Airtable | row 84 |
| `developer.clickup.com`, `help.clickup.com`, `clickup.com` | API | ClickUp | row 85 |
| `cloud.google.com` | API | Google NotebookLM | row 86 |
| `developers.egnyte.com`, `www.egnyte.com`, `helpdesk.egnyte.com` | API | Egnyte | row 87 |
| `www.mediafire.com` | API | MediaFire | row 88 |
| `www.sync.com` | API | Sync.com | row 89 |
| `transfer.sh` | API | transfer.sh | row 90 |
| `developers.facebook.com`, `www.messenger.com`, `www.facebook.com` | API | Facebook Messenger | row 91 |
| `api.stackexchange.com`, `stackoverflow.com`, `stackapps.com`, `meta.stackexchange.com` | API | Stack Overflow | row 92 |

## Decisions needed (not vendor-owned, so not requested): **resolved 2026-11-20**

Hermes's decisions 1, 2 and 6: the live tools and dependency-mapping pass 2 run on the Hermes server (no proxy). No DoH
resolver or Tranco host is added here, and the allowlist limit is not pursued. Inputs for those runs: `live-hosts-r2.txt`
and `web-urls.txt`.

| Host | Why | Decision |
|---|---|---|
| a DNS-over-HTTPS resolver (for example `dns.google` or `cloudflare-dns.com`) | item 1 DNS (A/AAAA, CNAME chain, HTTPS records with `ech=` and `alpn`) from this environment, which does not permit direct DNS | DECISION for Lee: a resolver is not vendor-owned |
| `tranco-list.eu` | to read the Tranco list's licence (item 6) before using it for ranking | DECISION for Lee |
| an unproxied vantage point (Lee's machine or a Culvert lab host) | item 1 TLS: this environment's proxy re-terminates TLS, so a handshake here shows the proxy | DECISION for Lee: run `tools/live_verify.py HOSTS OUT.json` there |

