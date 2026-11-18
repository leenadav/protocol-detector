# Application backlog: the pull queue

Secure web gateway, visibility-only mode. Method, source policy and confidence levels: `README.md`.

## How the queue works (Lee via Hermes, 2026-11-18)

- This file is the queue. Every item has exactly one **status**:
  - `READY`: primary sources, synthetic test vectors and a confidence level, plus (for name-based items) exact catalog entries;
  - `PARTIAL`: some of that is missing;
  - `BLOCKED`: a primary source cannot be read;
  - `IN-PROGRESS`: Hermes has handed it to the Engine lane (only Hermes sets this);
  - `DONE`: implemented, or verified with no change needed.
- **Kind**:
  - `NAME`: identified by server or DNS names; content-pack data only (`protocol_engine/host_apps.py`), no parser;
  - `PROTOCOL`: needs new engine code.
- Until the Go migration is merged, only `NAME` items are implemented. After the merge, new `PROTOCOL`
  families are Go-only and are tested with this lane's synthetic vectors instead of Python parity.
- When the Engine lane finishes a task, Hermes hands it the next READY batch (about 10 items). Specs
  found unclear or wrong come back to this lane.

## Scoring

**V** is operator value, 1 to 5. It is this lane's judgement: no primary source measures enterprise
prevalence. **R** is reliability from primary-sourced evidence on the visibility path, 1 to 5. The
score is V × R. `BLOCKED` caps R at 1.

## Queue

### NAME: READY (next hand-off: batch A, one patch)

Patch: `patches/batch-a-name-based.patch` against `claude/go-migration` `6b280a6`. Release 2026.11.3 is
proposed. Tested in scratch: content gates, rollback, 47 name vectors, Python and Go parity 7336/7336.
Pinned test values to update are listed in `patches/README.md`.

| Id | Item | Spec | V | R | Score | Status | Entries |
|---|---|---|---|---|---|---|---|
| A1 | GitHub Copilot: service hosts | `apps/github-copilot.md` 8a | 5 | 5 | 25 | READY | 3 `githubusercontent.com` hosts and 7 exact `webpubsub.azure.com` hosts → `github-copilot` |
| A2 | Microsoft 365: `cloud.microsoft` names | `apps/microsoft-365.md` 8 | 5 | 4 | 20 | READY | `outlook.cloud.microsoft`, `teams.cloud.microsoft`, `lync.com`, `sharepointonline.com`, `svc.ms`, `microsoft365.com`, `cloud.microsoft` |
| A3 | Microsoft 365: Exchange Online Protection split from web mail | `apps/microsoft-365.md` 8 | 4 | 4 | 16 | READY | new `ms-exchange-online-protection`: `protection.outlook.com`, `mx.microsoft` |
| A4 | Anthropic API split (decided) | `apps/anthropic-claude.md` 8 | 5 | 4 | 20 | READY | new `anthropic-api`: `api.anthropic.com`, `platform.claude.com` |
| A5 | Anthropic apps: content host, web fronts | `apps/anthropic-claude.md` 8 | 5 | 4 | 20 | READY | `claudeusercontent.com`; web fronts `claude.com`, `code.claude.com` |
| A6 | Microsoft Copilot app host | `apps/microsoft-copilot.md` 8 | 5 | 3 | 15 | READY | `copilot.cloud.microsoft` |
| A7 | Google notebook host | `apps/google-gemini.md` 8 | 5 | 4 | 20 | READY | `notebook.google.com` → `google-notebooklm` |
| A8 | Dropbox verified domains and web fronts | `apps/dropbox.md` 8 | 4 | 4 | 16 | READY | 7 domains, 6 web fronts |
| A9 | DocSend and Dropbox Sign | `apps/dropbox.md` 8 | 3 | 4 | 12 | READY | new `docsend`: `docsend.com`; `hellofax.com` → `dropbox-sign` |

### NAME: DONE (verified, no catalog change)

| Item | Spec | Note |
|---|---|---|
| OpenAI ChatGPT names | `apps/openai-chatgpt.md` | All four domains sourced (article relayed by Hermes). `cdn.platform.openai.com` attribution risk recorded |
| AnyDesk | `apps/anydesk.md` | `net.anydesk.com` verified |
| TeamViewer | `apps/teamviewer.md` | `teamviewer.com` verified |
| Zoom | `apps/zoom.md` | `zoom.us`, `zoom.com` verified |
| Gemini, AI Studio | `apps/google-gemini.md` | `gemini.google.com`, `aistudio.google.com` verified |

### NAME: PARTIAL or BLOCKED

| Item | Spec | Status | Missing |
|---|---|---|---|
| `openai-platform` (`api.openai.com`, `platform.openai.com`) | `apps/openai-chatgpt.md` | BLOCKED | OpenAI API docs behind a bot challenge; a copy from Lee's browser would unblock it |
| `anthropic.com` / `www.anthropic.com` as web fronts | `apps/anthropic-claude.md` | PARTIAL | `anthropic.com` not readable from this session |
| `dash.ai` (Dropbox) | `apps/dropbox.md` | PARTIAL | the source does not say what it serves |
| Unverified current names: `copilot.microsoft.com`, `notebooklm.google.com`, `dropboxusercontent.com`, `zoomgov.com` | respective specs | PARTIAL | primary source not yet found; kept, not removed |
| Slack | (batch 2) | PARTIAL | the vendor's URL list is sign-in-only per workspace |

### PROTOCOL: later queue (after the Go merge; Go-only, vector-tested)

| Item | Spec | Status | Note |
|---|---|---|---|
| GitHub Copilot plan field `copilot_plan` (decided: an evidence field) | `apps/github-copilot.md` 8b | READY | Engine code that derives a closed enum from the matched name; **no parser**. Hermes may classify it separately |
| TeamViewer port-5938 protocol | `apps/teamviewer.md` | BLOCKED | vendor publishes no protocol; never to be reconstructed from third-party dissectors |
| AnyDesk session TLS details (SNI or not) | `apps/anydesk.md` | PARTIAL | not published; research only |

## Research queue (not yet researched, provisional order by V)

No claim is made about these yet.

| Order | Candidate | Group | Expected kind |
|---|---|---|---|
| 11 | Slack | collaboration | NAME |
| 12 | Google Workspace (Drive, Docs, Gmail, Meet, Chat) | collaboration, file sharing | NAME |
| 13 | DeepSeek | generative AI | NAME |
| 14 | Perplexity | generative AI | NAME |
| 15 | Mistral (Le Chat, API) | generative AI | NAME |
| 16 | xAI Grok | generative AI | NAME |
| 17 | Box | file sharing | NAME |
| 18 | WeTransfer | file sharing | NAME |
| 19 | OneDrive and Google Drive personal vs business | file sharing | NAME |
| 20 | Cisco Webex | collaboration | NAME |
| 21 | Atlassian Cloud | collaboration | NAME |
| 22 | Salesforce | business | NAME |
| 23 | Tailscale | remote access, tunnel | NAME (WireGuard is already a family) |
| 24 | Cloudflare WARP / Zero Trust client | tunnel | NAME |
| 25 | ngrok | tunnel, shadow IT | NAME |
| 26 | ConnectWise ScreenConnect, Splashtop, RustDesk | remote access | NAME |
| 27 | Telegram, WhatsApp, Signal | messaging | NAME, maybe PROTOCOL if a vendor publishes a transport specification (not yet checked) |
| 28 | Zscaler, Netskope and other SSE client tunnels | tunnel | NAME |
