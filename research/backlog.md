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

### NAME: READY (batch C, one patch)

Patch: `patches/batch-c-name-based.patch` against the current head `47b2743`. Proposes release 2026.11.6. Tested in
scratch: content gates, rollback with unchanged earlier digests, 31 vectors, Python and Go parity 7418/7418.

| Id | Item | Spec | V | R | Score | Status | Entries |
|---|---|---|---|---|---|---|---|
| C1 | NotebookLM URL (re-sourced) | `apps/google-gemini.md` 8 | 5 | 4 | 20 | READY | `notebook.google.com` → `google-notebooklm` |
| C2 | ngrok agent hosts | `apps/ngrok.md` 8 | 5 | 5 | 25 | READY | `ngrok-agent.com`, `update.equinox.io` → `ngrok` |
| C3 | Cloudflare One Client API hosts | `apps/cloudflare-warp.md` 8 | 4 | 4 | 16 | READY | `api.devices.cloudflare.com` and two FedRAMP hosts (exact) |
| C4 | WeTransfer short links and storage | `apps/wetransfer.md` 8 | 4 | 4 | 16 | READY | `we.tl`, six exact `wt-prod-*-storm` S3 hosts |
| C5 | Atlassian first-party domains | `apps/atlassian.md` 8 | 4 | 4 | 16 | READY | `atl-paas.net`, `ss-inf.net`, `jira.com`, `teamworkgraph.com` |
| C6 | Dropbox `www.` web fronts | `apps/dropbox.md` 8 | 2 | 4 | 8 | READY | five `www.` variants |

### NAME: READY (batch D, after C; one patch)

Candidate selection (2026-11-19): the highest enterprise-visibility apps that this lane had not yet researched,
in collaboration, remote access, AI tools, file sharing, developer platforms and security agents. Ranked by V × R.
Patch: `patches/batch-d-name-based.patch` (release 2026.11.7). Tested: 45 vectors, parity 7427/7427.

| Rank | Id | Item | Spec | V | R | Score | Status |
|---|---|---|---|---|---|---|---|
| 1 | D1 | Microsoft Defender for Endpoint (new id) | `apps/ms-defender-endpoint.md` | 5 | 4 | 20 | READY |
| 2 | D2 | iCloud Private Relay (new id), iCloud domains | `apps/apple-icloud.md` | 5 | 4 | 20 | READY |
| 3 | D3 | Cursor | `apps/cursor.md` | 5 | 4 | 20 | READY (records an `accounts.x.ai` attribution risk) |
| 4 | D4 | Microsoft Intune (new id) | `apps/ms-intune.md` | 4 | 4 | 16 | READY |
| 5 | D5 | Zscaler clouds and Client Connector | `apps/zscaler.md` | 4 | 4 | 16 | READY |
| 6 | D6 | Okta regional and government domains | `apps/okta.md` | 4 | 4 | 16 | READY |
| 7 | D7 | 1Password | `apps/1password.md` | 4 | 4 | 16 | READY |
| 8 | D8 | GitLab.com | `apps/gitlab.md` | 4 | 4 | 16 | READY |
| 9 | D9 | Docker Hub and Desktop | `apps/docker-hub.md` | 4 | 4 | 16 | READY |
| 10 | D10 | Notion | `apps/notion.md` | 4 | 4 | 16 | READY |
| 11 | D11 | GoTo Meeting | `apps/goto.md` | 4 | 3 | 12 | READY; **DECISION** on `goto.com` attribution |
| 12 | D12 | Netskope Endpoint DLP host | `apps/netskope.md` | 3 | 4 | 12 | READY |
| 13 | D13 | Figma for Government | `apps/figma.md` | 3 | 3 | 9 | READY |
| 14 | - | GoTo Resolve | `blocked-urls.md` #7 | 5 | 1 | 5 | BLOCKED |
| 15 | - | Gemini API host | `blocked-urls.md` #8 | 5 | 1 | 5 | BLOCKED |
| 16 | - | Miro | `blocked-urls.md` #5 | 4 | 1 | 4 | BLOCKED |
| 17 | - | Splashtop | `blocked-urls.md` #4 | 4 | 1 | 4 | BLOCKED |
| 18 | - | Grammarly | `blocked-urls.md` #6 | 3 | 1 | 3 | BLOCKED |
| 19 | E1 | Chrome Remote Desktop service host | `apps/chrome-remote-desktop.md` | 4 | 4 | 16 | READY (batch E) |
| 20 | E2 | Bitwarden domains | `apps/bitwarden.md` | 3 | 4 | 12 | READY (batch E) |
| 21 | - | Canva, Duo, Hugging Face | `blocked-urls.md` #9 to #11 | 3 to 4 | 1 | | BLOCKED |

### NAME: DONE (implemented by the Engine lane)

| Batch | Items | Release |
|---|---|---|
| A | A1 to A9 (except `notebook.google.com`, now C1) | 2026.11.3 (`baa07b9`) |
| B | B1 to B4 | 2026.11.4 (`6ab434d`) |
| B2 | B5 to B8 (confirmed by Hermes 2026-11-18, API hosts from vendor docs only) | 2026.11.5 (`7dcabb7`) |

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
| Tailscale | `apps/tailscale.md` | `login.`, `controlplane.`, `log.tailscale.com` verified; `tailscale.io` and DERP names unverified |

### NAME: PARTIAL or BLOCKED

| Item | Spec | Status | Missing |
|---|---|---|---|
| `anthropic.com` / `www.anthropic.com` as web fronts | `apps/anthropic-claude.md` | PARTIAL | `anthropic.com` not readable from this session |
| `dash.ai` (Dropbox) | `apps/dropbox.md` | PARTIAL | the source does not say what it serves |
| Unverified current names: `copilot.microsoft.com`, `notebooklm.google.com`, `dropboxusercontent.com`, `zoomgov.com` | respective specs | PARTIAL | primary source not yet found; kept, not removed |
| Slack (`slack-edge.com`, `slack-msgs.com`, `slack-files.com`) | `apps/slack.md` | PARTIAL, low priority | sign-in-only list; Lee cannot supply a copy (2026-11-18) |
| Box | `apps/box.md` | BLOCKED, low priority | sign-in required; Lee cannot supply a copy (2026-11-18) |
| Chat-app hosts of DeepSeek, Perplexity, Mistral, Grok | B5 to B8 specs | PARTIAL | no primary page names them; they stay under the existing domains |
| Salesforce, Signal, WhatsApp, Splashtop | `blocked-urls.md` | BLOCKED | exact URLs listed for Hermes to relay |
| ConnectWise ScreenConnect | `apps/connectwise-screenconnect.md` | PARTIAL | no official cloud allowlist found |
| RustDesk | `apps/rustdesk.md` | PARTIAL | self-host ports sourced; public server names unverified |
| Telegram names | `apps/telegram.md` | PARTIAL | no allowlist read |

### PROTOCOL and ENGINE-FIELD: later queue (after the Go merge; Go-only, vector-tested)

| Item | Spec | Status | Note |
|---|---|---|---|
| GitHub Copilot plan field `copilot_plan` (decided: an evidence field) | `apps/github-copilot.md` 8b | READY, **ENGINE-FIELD** | derives a closed enum from the matched name; no parser |
| TeamViewer port-5938 protocol | `apps/teamviewer.md` | BLOCKED | vendor publishes no protocol; never to be reconstructed from third-party dissectors |
| AnyDesk session TLS details (SNI or not) | `apps/anydesk.md` | PARTIAL | not published; research only |
| Telegram MTProto TCP family | `protocol/telegram-mtproto.md` | READY, **PROTOCOL** | byte-exact vectors; open point: CRC variant and byte order |
| UDP flow decisions for weak families (CoAP, OpenVPN) | `protocol/udp-flow-decision.md` | READY for decision, **ENGINE-FIELD** | measured random-input rates 1.35e-4 (CoAP) and 0.95e-4 (OpenVPN) per datagram |
| TLS ServerHello profile widening | `protocol/tls-serverhello-legacy.md` | READY for decision, **PROTOCOL** | accept registered TLS 1.0 to 1.2 suites; RFC 8996 risk instead of invalidation |
| D09 findings | `d09-iscx-vpn2016.md` 4.4, 6 | tracked by the Engine lane; now specified in `protocol/` | post-merge Go-only items (Hermes, 2026-11-18) |

## Research queue

Items 21 to 29 were researched in batch C (above). Remaining, by provisional V:

| Order | Candidate | Status |
|---|---|---|
| 30 | Netskope client | researched: `goskope.com` DONE; `epdlp-prod.netskope.io` READY for the next patch (`apps/netskope.md`) |
| 31 | Tailscale DERP relay names | BLOCKED (DERP map host not allowed; low value, likely already under `tailscale.com`) |
| 32 | Retries: Salesforce, Signal, WhatsApp, Zscaler, Splashtop | BLOCKED (see the table above) |

No unresearched candidates remain in this queue.
