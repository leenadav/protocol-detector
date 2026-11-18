# Ranked application backlog: secure web gateway, visibility-only mode

Batch 1, 2026-11-18. Method, sources policy and confidence levels: `README.md`.

## Scoring

- **Operator value V (1 to 5)**: this lane's assessment of prevalence in enterprise traffic, security
  and compliance relevance, and weight in the shadow-IT, generative-AI, remote-access, file-sharing
  and collaboration groups. **No primary source measures enterprise prevalence**, so V is a
  judgement and is labelled as one. It orders the research. It is not a measured fact.
- **Reliability R (1 to 5)**: how well this detector, on the visibility-phase path (TLS over CONNECT;
  SNI, offered ALPN, port), can name the application **from primary-sourced evidence**:
  5 = N3 names that also separate a sub-variant operators care about, 4 = N3 names,
  3 = N3 names with an important unverified gap or a large unobservable share, 2 = N2 only,
  1 = nothing verified.
- **Score = V × R.** A `BLOCKED` source caps R at 1 until it is read.

## Batch 1: full specs

| Rank | Candidate | Spec | Group | V | R | Score | Status | Ready for implementation |
|---|---|---|---|---|---|---|---|---|
| 1 | GitHub Copilot | `apps/github-copilot.md` | generative AI, dev | 5 | 5 | 25 | READY | plan-specific hosts (`individual.` / `business.` / `enterprise.githubcopilot.com`); three `githubusercontent.com` Copilot hosts; seven exact `webpubsub.azure.com` hosts |
| 2 | Microsoft 365 | `apps/microsoft-365.md` | collaboration, file sharing, mail | 5 | 4 | 20 | READY | `outlook.cloud.microsoft`, `teams.cloud.microsoft`, `lync.com`, `sharepointonline.com`, `svc.ms`, `microsoft365.com`, suite-level `cloud.microsoft`; fix `protection.outlook.com` being named `outlook-web` |
| 3 | Anthropic Claude | `apps/anthropic-claude.md` | generative AI | 5 | 4 | 20 | READY | `claudeusercontent.com`, `mcp-proxy.anthropic.com`; web fronts for `anthropic.com` and `claude.com`; **decision**: split `api.anthropic.com` into an API id |
| 4 | Google Gemini / AI Studio / Notebook | `apps/google-gemini.md` | generative AI | 5 | 4 | 20 | PARTIAL | add `notebook.google.com`; keep `notebooklm.google.com` as unverified |
| 5 | Dropbox | `apps/dropbox.md` | file sharing | 4 | 4 | 16 | READY | seven added domains, six web fronts; DocSend, Dash and Dropbox Sign separation |
| 6 | Zoom | `apps/zoom.md` | collaboration | 4 | 4 | 16 | READY | no name change; `zoomgov.com` provenance unverified |
| 7 | Microsoft Copilot | `apps/microsoft-copilot.md` | generative AI | 5 | 3 | 15 | PARTIAL | `copilot.cloud.microsoft`; in-app Copilot unobservable by design |
| 8 | AnyDesk | `apps/anydesk.md` | remote access | 4 | 3 | 12 | READY (names) | none needed (`net.anydesk.com` verified); SNI presence unverified |
| 9 | TeamViewer | `apps/teamviewer.md` | remote access | 4 | 3 | 12 | PARTIAL | none needed; port-5938 protocol unpublished, no structural profile |
| 10 | OpenAI ChatGPT / API | `apps/openai-chatgpt.md` | generative AI | 5 | 1 | 5 | **BLOCKED** | nothing until the vendor article is read; would be about 20 once verified |

### What batch 1 changes for the product

- **Generative-AI visibility can separate personal from business use in one case today**: GitHub
  publishes plan-specific Copilot host names. No other vendor in this batch publishes such a
  separation by host name.
- **Two vendors say their own lists are incomplete or dynamic**: Microsoft for Copilot features, and
  GitHub for its Meta API. Logs should name the application when a verified host is seen, and never
  claim that its absence means the application is unused.
- **One current catalog mapping is misleading**: Exchange Online Protection (`*.protection.outlook.com`,
  including port-25 MX traffic) is named `outlook-web` by the `outlook.com` suffix.
- **These current catalog names lack a primary source in this batch**: `copilot.microsoft.com`,
  `notebooklm.google.com`, `dropboxusercontent.com`, `zoomgov.com`, and all OpenAI names. They are not
  shown to be wrong, only unverified here.

## Batch 2 and later: queued candidates (not yet researched)

The order is provisional (V only, R unknown until researched). No claim is made about any of these yet.

| Order | Candidate | Group | Note |
|---|---|---|---|
| 11 | Slack | collaboration | Started. The vendor sends admins to a sign-in-only, per-workspace URL list (`my.slack.com/help/urls`). Public facts so far: WebSockets over 443 and `wss-primary`/`wss-backup`/`wss-mobile.slack.com`. The pack's `slack-edge.com`, `slack-msgs.com`, `slack-files.com` are unverified |
| 12 | Google Workspace (Drive, Docs, Gmail, Meet, Chat) | collaboration, file sharing | Source already read for batch 1 (host-name allowlist). Note that Gmail and Chat share `mail.google.com` |
| 13 | DeepSeek | generative AI | |
| 14 | Perplexity | generative AI | |
| 15 | Mistral (Le Chat, API) | generative AI | |
| 16 | xAI Grok | generative AI | |
| 17 | Box | file sharing | |
| 18 | WeTransfer | file sharing | |
| 19 | Google Drive / OneDrive personal vs business | file sharing | Personal vs business separation, as found for Copilot |
| 20 | Cisco Webex | collaboration | |
| 21 | Atlassian Cloud (Jira, Confluence) | collaboration | |
| 22 | Salesforce | business | |
| 23 | Tailscale | remote access, tunnel | WireGuard is already a family |
| 24 | Cloudflare WARP / Zero Trust client | tunnel | |
| 25 | ngrok | tunnel, shadow IT | |
| 26 | ConnectWise ScreenConnect, Splashtop, RustDesk | remote access | |
| 27 | Telegram, WhatsApp, Signal | messaging | Check whether any vendor publishes a transport specification, which would allow a structural (`S`) profile (not yet checked) |
| 28 | Zscaler, Netskope, other SSE client tunnels | tunnel | Visibility of competing security clients |

## Request to Hermes (blocked sources)

- OpenAI help article 9247338 ("Network recommendations for ChatGPT errors on web and apps") and the
  OpenAI API reference are behind a Cloudflare bot challenge. This lane will not bypass it. A text copy
  from Lee or Hermes would unblock rank 10.
