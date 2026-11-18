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
  - `PROTOCOL`: needs new parsing code;
  - `ENGINE-FIELD`: needs engine or data-model code but no new parser (Hermes, 2026-11-18). Same policy as `PROTOCOL`.
- Until the Go migration is merged, only `NAME` items are implemented. After the merge, new `PROTOCOL`
  families and `ENGINE-FIELD` items are Go-only and are tested with this lane's synthetic vectors instead
  of Python parity.
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

### NAME: READY (batch B, after A; one patch)

Patch: `patches/batch-b-name-based.patch`, applied after batch A. Proposes release 2026.11.4. Tested in scratch: content gates, rollback, 26 vectors (plus A's 47), Python and Go parity 7338/7338.

| Id | Item | Spec | V | R | Score | Status | Entries |
|---|---|---|---|---|---|---|---|
| B1 | Google Drive and Docs editor hosts | `apps/google-workspace.md` 8 | 4 | 4 | 16 | READY | `googledrive.com`, `sheets.google.com`, `slides.google.com`, two `drive-data-export` hosts → `google-drive` |
| B2 | OneDrive consumer hosts (personal vs business) | `apps/onedrive-drive-personal-business.md` 8 | 5 | 4 | 20 | READY | `skydrive.live.com`, `photos.live.com`, `storage.msn.com` → `ms-onedrive` ("consumer") |
| B3 | Webex service domains | `apps/webex.md` 8 | 4 | 4 | 16 | READY | `ciscospark.com`, `webexapis.com`, `webexcontent.com`, `ciscosparkcontent.com` |
| B4 | OpenAI help and developer docs as web fronts | `apps/openai-chatgpt.md` 8 | 3 | 4 | 12 | READY | `help.openai.com` → `openai-chatgpt`, `developers.openai.com` → `openai-platform` (fronts) |

### NAME: READY pending a decision (batch B2, after B)

Patch: `patches/batch-b2-api-split.patch`. **Needs Hermes's confirmation** that the Anthropic API-split rule applies to these vendors. Tested: 11 vectors, parity 7342/7342.

| Id | Item | Spec | V | R | Score | Status | Entries |
|---|---|---|---|---|---|---|---|
| B5 | DeepSeek API | `apps/deepseek.md` | 5 | 4 | 20 | READY (decision) | new `deepseek-api`: `api.deepseek.com` |
| B6 | Perplexity API | `apps/perplexity.md` | 4 | 4 | 16 | READY (decision) | new `perplexity-api`: `api.perplexity.ai` |
| B7 | Mistral AI API | `apps/mistral.md` | 4 | 4 | 16 | READY (decision) | new `mistral-api`: `api.mistral.ai` |
| B8 | xAI API | `apps/xai-grok.md` | 4 | 4 | 16 | READY (decision) | new `xai-api`: `api.x.ai` |

### NAME: DONE (verified, no catalog change)

| Item | Spec | Note |
|---|---|---|
| OpenAI ChatGPT names | `apps/openai-chatgpt.md` | All four domains sourced (article relayed by Hermes). `cdn.platform.openai.com` attribution risk recorded |
| OpenAI platform names | `apps/openai-chatgpt.md` | `api.openai.com`, `platform.openai.com` sourced (API reference read directly, also relayed) |
| Gmail, Google Chat, Meet | `apps/google-workspace.md` | Verified. Gmail and Chat share `mail.google.com`; Meet media hosts are YouTube's (attribution risks, no change) |
| Google Drive personal vs business | `apps/onedrive-drive-personal-business.md` | Not separable by name: no change possible |
| AnyDesk | `apps/anydesk.md` | `net.anydesk.com` verified |
| TeamViewer | `apps/teamviewer.md` | `teamviewer.com` verified |
| Zoom | `apps/zoom.md` | `zoom.us`, `zoom.com` verified |
| Gemini, AI Studio | `apps/google-gemini.md` | `gemini.google.com`, `aistudio.google.com` verified |

### NAME: PARTIAL or BLOCKED

| Item | Spec | Status | Missing |
|---|---|---|---|
| `anthropic.com` / `www.anthropic.com` as web fronts | `apps/anthropic-claude.md` | PARTIAL | `anthropic.com` not readable from this session |
| `dash.ai` (Dropbox) | `apps/dropbox.md` | PARTIAL | the source does not say what it serves |
| Unverified current names: `copilot.microsoft.com`, `notebooklm.google.com`, `dropboxusercontent.com`, `zoomgov.com` | respective specs | PARTIAL | primary source not yet found; kept, not removed |
| Slack (`slack-edge.com`, `slack-msgs.com`, `slack-files.com`) | `apps/slack.md` | PARTIAL | the vendor's URL list is sign-in-only per workspace; a member's copy would verify them |
| Box | `apps/box.md` | BLOCKED | the firewall article requires sign-in; a copy from Lee would unblock it |
| WeTransfer | `apps/wetransfer.md` | BLOCKED | the help centre moved to `wetransfer.com`; host to be allowed in batch C |
| Chat-app hosts of DeepSeek, Perplexity, Mistral, Grok | B5 to B8 specs | PARTIAL | no primary page names them; they stay under the existing domains |

### PROTOCOL and ENGINE-FIELD: later queue (after the Go merge; Go-only, vector-tested)

| Item | Spec | Status | Note |
|---|---|---|---|
| GitHub Copilot plan field `copilot_plan` (decided: an evidence field) | `apps/github-copilot.md` 8b | READY, **ENGINE-FIELD** | derives a closed enum from the matched name; no parser |
| TeamViewer port-5938 protocol | `apps/teamviewer.md` | BLOCKED | vendor publishes no protocol; never to be reconstructed from third-party dissectors |
| AnyDesk session TLS details (SNI or not) | `apps/anydesk.md` | PARTIAL | not published; research only |

## Research queue (not yet researched, provisional order by V)

Items 11 to 20 were researched in batch B (above). No claim is made about the rest yet.

| Order | Candidate | Group | Expected kind |
|---|---|---|---|
| 21 | Atlassian Cloud | collaboration | NAME |
| 22 | Salesforce | business | NAME |
| 23 | Tailscale | remote access, tunnel | NAME (WireGuard is already a family) |
| 24 | Cloudflare WARP / Zero Trust client | tunnel | NAME |
| 25 | ngrok | tunnel, shadow IT | NAME |
| 26 | ConnectWise ScreenConnect, Splashtop, RustDesk | remote access | NAME |
| 27 | Telegram, WhatsApp, Signal | messaging | NAME, maybe PROTOCOL if a vendor publishes a transport specification (not yet checked) |
| 28 | Zscaler, Netskope and other SSE client tunnels | tunnel | NAME |
| 29 | WeTransfer and Box (retry) | file sharing | NAME |
