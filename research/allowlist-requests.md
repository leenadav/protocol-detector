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

## Decisions needed (not vendor-owned, so not requested)

| Host | Why | Decision |
|---|---|---|
| a DNS-over-HTTPS resolver (for example `dns.google` or `cloudflare-dns.com`) | item 1 DNS (A/AAAA, CNAME chain, HTTPS records with `ech=` and `alpn`) from this environment, which does not permit direct DNS | DECISION for Lee: a resolver is not vendor-owned |
| `tranco-list.eu` | to read the Tranco list's licence (item 6) before using it for ranking | DECISION for Lee |
| an unproxied vantage point (Lee's machine or a Culvert lab host) | item 1 TLS: this environment's proxy re-terminates TLS, so a handshake here shows the proxy | DECISION for Lee: run `tools/live_verify.py HOSTS OUT.json` there |

