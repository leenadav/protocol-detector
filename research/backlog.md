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

### Decisions recorded (Hermes, 2026-11-19)

- Window overflow after identification (D09 (a)), Hermes 2026-11-20 (PRO-30): an identified side keeps its
  identification; the overflow ends tracking and is flagged; overlap conflicts still invalidate. Engine item
  `protocol/window-overflow.md` (ENGINE-FIELD, post-merge, Go only, approved parity delta).

- Hermes 2026-11-20: live tools and dependency pass 2 run on the Hermes server; observed-only names enter at O only with
  certificate or official-page ownership; shared vendor CDNs go to vendor-level ids; email server names recorded in aggregate.
- Method v2 adopted (Lee via Hermes): live verification, dependency mapping, App-ID attributes, change tracking, per-app accuracy and usage-based priority (`README.md`).

- `goto.com` and the other GoTo universal domains get a vendor-level `goto` id (the Engine lane is implementing it).
- UDP flow rule adopted: first datagram per direction, two consecutive matches for CoAP and OpenVPN, no port gating;
  post-merge, Go only (`protocol/udp-flow-decision.md`).
- TLS ServerHello widening adopted; post-merge, Go only (`protocol/tls-serverhello-legacy.md`).
- Telegram CRC: the Engine lane confirms it against tdlib.

### NAME: READY (batch K, after J: dependency mapping pass 2, PRO-36, 2026-11-20)

Pass 2: Hermes ran `observe_web.js` over the 59 URLs on its server with a direct connection (`observations/pass2-2026-11-20.tsv`).
39 pages answered; 20 timed out on a bot or JavaScript challenge from a datacenter address (their host lists are a lower
bound). Patch: `patches/batch-k-dependency-pass2.patch` (placeholder release `2026.12.7`). Tested: 35 targeted vectors, rollback
exact, parity 7467/7467 (Python and Go), 88/88 families.

| Measure (pass 2, across all specs) | Result |
|---|---|
| Hosts observed (per spec and page) | 764: 159 app-owned and attributed correctly; 602 dependencies; **3 vendor-owned but unmapped** |
| Dependencies attributed to the app whose page loaded them | **0** (1,109 v2 vectors, all pass) |
| Consumer-app tag hosts on unrelated pages (before K) | 19 names reported `facebook`, `linkedin`, `twitter`, `reddit`, `quora`, `tiktok`, `spotify` or `bing` on Slack, Dropbox, Figma, Grammarly, Notion, Zendesk, Perplexity, WeTransfer and Splashtop pages; **17 fixed by K** (decision 4); 2 residual (below) |
| Residual false positives | `www.linkedin.com` (7 pages) and `www.facebook.com` (1 page) are main-site names that tags also call; unchanged |
| Vendor-owned gaps | `dockerstatic.com` (Docker), `campaign.slackhq.com` (Slack), `www.zndsk.com` (Zendesk): enter at O only after live round 2 shows certificate ownership (decision 3) |

| Rank | Id | Item | Spec | V | R | Score | Status |
|---|---|---|---|---|---|---|---|
| 1 | K1 | Tag hosts of 7 consumer apps to new vendor-level ids; Bing tags and `static.microsoft` to `ms-base` | `apps/embedded-trackers.md` | 5 | 4 | 20 | READY |

### NAME: READY (batch J, after L: rows 12 to 18 read by Research Lab, PRO-29/PRO-35, 2026-11-20)

Patch: `patches/batch-j-relayed-rows-12-18.patch` (placeholder release `2026.12.6`). Tested: 53 targeted vectors (all as
expected), rollback exact, parity 7455/7455 (Python and Go), 88/88 families. The new names are queued for live
round 2 (`live-hosts-r2.txt`, batch J block).

| Rank | Id | Item | Spec | V | R | Score | Status |
|---|---|---|---|---|---|---|---|
| 1 | J1 | Jamf Pro (new id `jamf-pro`) | `apps/jamf-pro.md` | 5 | 4 | 20 | READY |
| 2 | J2 | Salesforce: 22 Salesforce-operated domains | `apps/salesforce.md` | 5 | 4 | 20 | READY (`site.com` at N2: customer sites) |
| 3 | J3 | Cisco Umbrella: `umbrella.com` added to `opendns`, description updated | `apps/cisco-umbrella.md` | 4 | 4 | 16 | READY (resolver traffic is by IP; not used) |
| 4 | J4 | Atera: three exact vendor-named agent hosts | `apps/atera.md` | 4 | 4 | 16 | READY |
| 5 | J5 | Asana: `asana.plus`, `asanausercontent.com`, `app.asana-gov.com`, six S3 bucket hosts | `apps/asana.md` | 3 | 4 | 12 | READY |
| 6 | J6 | Parsec: `parsecusercontent.com` | `apps/parsec.md` | 3 | 4 | 12 | READY |
| 7 | J7 | Grammarly: `grammarly.net` | `apps/grammarly.md` | 3 | 4 | 12 | READY (`coda.io` left out: separate product) |

### Method v2 retrofit summary (updated 2026-11-20 with live verification)

All 63 entries in `apps.json` (batches A to D included) carry sections 9 to 11 and the v2 vectors (`tools/retrofit_specs.py`).
Live data: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`live-results-2026-11-20.tsv`, 358 names).

| Measure | Result |
|---|---|
| Catalog names in the specs | 320 (the round-1 list covers 358 names, including observed hosts) |
| Confirmed live (`L`: resolves and completes TLS) | **206** |
| Suffix entries verified through a documented subdomain | **7** (apex has no address, documented subdomain live) |
| Apex with no address, not yet verified | **87**: normal for suffix entries, **not dead**; 12 have a documented probe queued in round 2, and 75 are documented only as wildcards or bare domains |
| Resolve, but TLS failed | **17** (7 certificate verification, 5 timeout, 3 SSL, 2 other: apex names serving another name's certificate, or no listener); not removal reasons; round 2 re-checks |
| NXDOMAIN (recommend removal, RFC 8020) | **3**: `emdl.ws.microsoft.com` (removed in patch L), `epm.gpcloudservice.com` and `filter.paloaltonetworks.com` (Engine lane to drop `prisma-access` from patch F) |
| CDN- or cloud-fronted (name usable, IPs never) | **28** catalog names (37 of the 358) |
| ECH-capable (HTTPS record `ech`) | **2**: `bitwarden.eu`, `signal.art` |
| QUIC advertised (`h3`) | **27** catalog names (28 of the 358) |
| Hosts observed (dependency mapping, pass 1) | 92: 51 app-owned (47 already mapped, plus the 4 that patch R maps), 41 dependencies |
| Live round 2 (Hermes, 2026-11-20, `live-results-2026-11-20-r2.tsv`) | 363 names; flags tls-fail 19, no-address 95, cdn 36, h3 28, ech 2, nxdomain 3. Across the 375 spec catalog names (both rounds): 207 live (78 with a certificate naming an organisation), 17 suffixes verified through documented probes, 75 apexes with no address and no documented probe, 17 TLS failures (not removal), 2 NXDOMAIN in both rounds (`prisma-access`), 57 added later (round 3: `live-hosts-r3.txt`, 69 names) |
| Attributions changed | patch L: `cdn.office.net` → `ms-base`; `play.google.com` → `google-base`; `emdl.ws.microsoft.com` removed; `googlemail.com` → `gmail`. patch R decided from round 2: `copilot.com` → `ms-copilot` (certificate organisation Microsoft Corporation); `boxcdn.net` and `gitlab.net` dropped (domain-validated certificates) |
| Vectors | 399 v2 vectors, all pass with R and L applied |
| D09 per application | Gmail in the email captures: 0 of 294 SNI-bearing unnamed sessions before L; all are `*.googlemail.com`, so all are named with L |
| Re-verify by | 2027-02-17 for every spec |

Pending runs (Hermes server): `live-hosts-r2.txt` (363 names, 20 with probes, now recording certificate organisation) and
dependency-mapping pass 2 with `web-urls.txt` (59 URLs): `node research/tools/observe_web.js OUT.json --urls research/web-urls.txt`.

### Older open items resolved by this lane (Hermes decision 7, 2026-11-20)

- **Content version ordering: recommendation applied.** The Engine lane makes release comparison numeric (per
  `YYYY.MM.N` component, with a regression test that `x.y.9` sorts before `x.y.10`) in `protocol_engine/content.py` and
  `go/internal/content/content.go`. Until then the patches keep their sortable placeholders (`2026.12.1` to `2026.12.5`),
  and the Engine lane renumbers them at implementation.
- **`google-gemini-api` split: kept** (rationale in `apps/google-gemini-api.md`).
- **`citrix-cloud` risk: 3** (rationale in `apps/citrix-cloud.md`).
- **WorkSpaces regional API hosts: left out** (rationale in `apps/amazon-workspaces.md`).
- **Window-overflow revocation: DECIDED** by Hermes (CTO), 2026-11-20 (Paperclip PRO-30): the recommendation is
  accepted, and the Engine item is `protocol/window-overflow.md` (ENGINE-FIELD, post-merge, Go only, with an approved parity
  delta). The accepted recommendation: a side identified from a complete initial message keeps its identification
  when later data overruns the stream window; the overflow ends tracking for that side and is reported, but does not
  revoke the identification. Overlap conflicts keep invalidating, as the AGENTS contract requires.

### Prioritisation inputs (method v2, item 6)

V is now stated with its reasons: enterprise prevalence (this lane's judgement, no licensed ranking yet),
risk (section 11 of each spec) and unknown rate. No public ranking is used yet. Cloudflare Radar and the default Tranco list fail LEE-1 (Radar is CC BY-NC;
Hermes, 2026-11-20). CrUX (CC BY 4.0) and the Majestic Million (CC BY 3.0) **pass LEE-1** (licences quoted from
the providers' own pages by Research Lab, 2026-11-20; verdicts and attribution lines in `datasets.md`), and are used with attribution (`datasets.md`, "Ranking sources"; `tools/rank_domains.py`, run on the Hermes server).

| Input | Status |
|---|---|
| Culvert field data (unknown-session share per server name, top unmapped names) | **placeholder**: not available yet |
| D09 unknowns per application | available for the ISCX labels only (section 8 of the D09 report) |
| Public popularity rank (CrUX bucket, Majestic rank) | licences **PASS** (2026-11-20); **pending**: the Hermes server run of `tools/rank_domains.py` with `majestic_million.csv` (free download) and a CrUX `origin,rank` export (needs BigQuery on the server) |

### NAME: READY (batch I, after H)

Patch: `patches/batch-i-name-based.patch` (placeholder release `2026.12.3`). Tested: 18 vectors, rollback exact, parity
7449/7449 (Python and Go), 88/88 families parity-verified.

| Rank | Id | Item | Spec | V | R | Score | Status |
|---|---|---|---|---|---|---|---|
| 1 | I1 | Azure Virtual Desktop / Windows 365 (new id `ms-virtual-desktop`) | `apps/ms-virtual-desktop.md` | 5 | 4 | 20 | READY (moves `windows.cloud.microsoft` off `ms-office365`) |
| 2 | I2 | Amazon WorkSpaces (new id `amazon-workspaces`) | `apps/amazon-workspaces.md` | 4 | 4 | 16 | READY; DECISION: add the 48 exact regional API hosts? |
| 3 | - | Fortinet, Datto RMM, N-able | `apps/fortinet-datto-nable.md` | 4 | 1 | | BLOCKED (no page located, 404, 403) |

### NAME: READY (batch H, after G)

Candidate selection (2026-11-19): high-visibility enterprise services with an official endpoint page this lane can
read. Patch: `patches/batch-h-name-based.patch` (placeholder release `2026.12.2`). Tested: 33 vectors (all as
expected), rollback exact, parity 7445/7445 (Python and Go), 88/88 families parity-verified.

| Rank | Id | Item | Spec | V | R | Score | Status |
|---|---|---|---|---|---|---|---|
| 1 | H1 | Citrix Cloud (new id `citrix-cloud`) | `apps/citrix-cloud.md` | 5 | 4 | 20 | READY (`cloud.com` suffix at N2) |
| 2 | H2 | Windows Update / Delivery Optimization names | `apps/ms-update.md` | 5 | 4 | 20 | READY |
| 3 | H3 | Adobe-hosted domains | `apps/adobe-cloud.md` | 4 | 4 | 16 | READY (web-embedded Adobe domains left out) |
| 4 | H4 | Postman domains | `apps/postman.md` | 3 | 4 | 12 | READY |
| 5 | - | Zendesk | `apps/zendesk.md` | 3 | 4 | | DONE (no change) |
| 6 | - | HubSpot | no official allowlist page found (the guessed knowledge-base URL returns 404) | 3 | | | PARTIAL |
| 7 | - | Discord, monday.com | help centres return HTTP 403 to this lane | 3 | 1 | | BLOCKED (not yet in `blocked-urls.md`: exact article URLs unknown) |

### NAME: READY (batch G, after F: pages relayed by Hermes, 2026-11-19)

Patch: `patches/batch-g-name-based.patch` (placeholder release `2026.12.1`, see the version note below). Tested:
40 vectors (all as expected), rollback exact, parity 7441/7441 (Python and Go), 88/88 families parity-verified.

| Rank | Id | Item | Spec | V | R | Score | Status |
|---|---|---|---|---|---|---|---|
| 1 | G1 | LogMeIn Resolve (new id `logmein-resolve`) | `apps/logmein-resolve.md` | 5 | 4 | 20 | READY |
| 2 | G2 | Gemini API (new id `google-gemini-api`, exact `generativelanguage.googleapis.com`) | `apps/google-gemini-api.md` | 5 | 4 | 20 | READY (id split mirrors `anthropic-api`) |
| 3 | G3 | Signal link and sticker domains | `apps/signal.md` | 4 | 4 | 16 | READY |
| 4 | G4 | Splashtop regional API and relay names | `apps/splashtop.md` | 4 | 4 | 16 | READY |
| 5 | G5 | Miro domains | `apps/miro.md` | 4 | 4 | 16 | READY |
| 6 | G6 | Canva domains | `apps/canva.md` | 4 | 4 | 16 | READY |
| 7 | G7 | Cisco Duo web front `www.duo.com` | `apps/duo-security.md` | 3 | 4 | 12 | READY |
| 8 | - | Salesforce | `apps/salesforce.md` | 4 | 4 | | DONE (no change); linked "Required Domains" page still unread (`blocked-urls.md` #17) |
| 9 | - | Grammarly | `apps/grammarly.md` | 3 | 1 | | BLOCKED (the article has no list; `blocked-urls.md` #18) |

**Version note for the Engine lane (finding, product code).** `protocol_engine/content.py` compares release
versions as strings (`item.version < version` at line 255, `>` at line 276, and `versions != sorted(versions)` in
`check()` at line 448, on `c08773f`). After D, E and F the next release in November would be `2026.11.10`, which
sorts before `2026.11.9`. Reproduced in scratch: with `2026.11.10`, `check_content.py --update` still wrote a lock
whose host count was 431 (the 2026.11.2 state), and `content_history.py` then failed with "content release
2026.11.2 no longer reproduces its host catalog". The patch therefore uses the placeholder `2026.12.1`. The Engine
lane decides between a numeric version comparison (with a regression test for `x.y.9` < `x.y.10`) and a
numbering rule, then renumbers. The Go engine has the same assumption: `go/internal/content/content.go:446` sorts
release versions with `sort.Strings` under the comment "YYYY.MM.N with zero-padded month: lexical order is release
order", which holds only while N is at most 9.

### NAME: READY (batch F, after E; rebased on `c08773f`)

| Rank | Id | Item | Spec | V | R | Score | Status |
|---|---|---|---|---|---|---|---|
| 1 | F1 | Prisma Access agent (new id) | `apps/prisma-access.md` | 4 | 4 | 16 | READY |
| 2 | F2 | JetBrains AI (new id) | `apps/jetbrains-ai.md` | 4 | 4 | 16 | READY |
| 3 | F3 | Loom (new id) | `apps/loom.md` | 3 | 4 | 12 | READY |
| 4 | - | BeyondTrust Remote Support cloud | (verified: `beyondtrustcloud.com` per `https://docs.beyondtrust.com/rs/docs/cloud-network`) | 4 | 4 | | DONE (no change) |
| 5 | - | Cisco Umbrella, Parsec, Asana, Jamf, Atera | `apps/*` (batch J) | 3 to 5 | 4 | | READY (batch J, 2026-11-20) |
| 6 | - | Windsurf, Smartsheet, Airtable, npm, PyPI, NinjaOne | no official network page found | | | | PARTIAL |

### NAME: READY (batch D, after C; rebased on `c08773f`, apply D → E → F)

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
| 14 | - | GoTo Resolve | `apps/logmein-resolve.md` | 5 | 4 | 20 | READY (batch G1) |
| 15 | - | Gemini API host | `apps/google-gemini-api.md` | 5 | 4 | 20 | READY (batch G2) |
| 16 | - | Miro | `apps/miro.md` | 4 | 4 | 16 | READY (batch G5) |
| 17 | - | Splashtop | `apps/splashtop.md` | 4 | 4 | 16 | READY (batch G4) |
| 18 | - | Grammarly | `apps/grammarly.md` | 3 | 1 | 3 | BLOCKED (`blocked-urls.md` #18) |
| 19 | E1 | Chrome Remote Desktop service host | `apps/chrome-remote-desktop.md` | 4 | 4 | 16 | READY (batch E) |
| 20 | E2 | Bitwarden domains | `apps/bitwarden.md` | 3 | 4 | 12 | READY (batch E) |
| 21 | - | Canva, Duo; Hugging Face | `apps/canva.md`, `apps/duo-security.md`; `blocked-urls.md` #11 | 3 to 4 | | | READY (batch G6, G7); Hugging Face BLOCKED (no page known) |

### NAME: DONE (implemented by the Engine lane)

| Batch | Items | Release |
|---|---|---|
| C | C1 to C6 | 2026.11.6 (`b6ed149`) |
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
| WhatsApp | `blocked-urls.md` #3 | BLOCKED | no official page known (Hermes, 2026-11-19); Salesforce, Signal, Splashtop resolved in batch G |
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
| Stream-window overflow after identification keeps the identification (D09 (a)) | `protocol/window-overflow.md` | READY (decided by Hermes, PRO-30), **ENGINE-FIELD** | vectors W1 to W6; generator `protocol/vectors/tls12_window_pcap.py`; approved parity delta needed |
| UDP flow decisions for weak families (CoAP, OpenVPN) | `protocol/udp-flow-decision.md` | READY for decision, **ENGINE-FIELD** | measured random-input rates 1.35e-4 (CoAP) and 0.95e-4 (OpenVPN) per datagram |
| TLS ServerHello profile widening | `protocol/tls-serverhello-legacy.md` | READY for decision, **PROTOCOL** | accept registered TLS 1.0 to 1.2 suites; RFC 8996 risk instead of invalidation |
| D09 findings | `d09-iscx-vpn2016.md` 4.4, 6 | tracked by the Engine lane; now specified in `protocol/` | post-merge Go-only items (Hermes, 2026-11-18) |

## Research queue

Items 21 to 29 were researched in batch C (above). Remaining, by provisional V:

| Order | Candidate | Status |
|---|---|---|
| 30 | Netskope client | researched: `goskope.com` DONE; `epdlp-prod.netskope.io` READY for the next patch (`apps/netskope.md`) |
| 31 | Tailscale DERP relay names | BLOCKED (DERP map host not allowed; low value, likely already under `tailscale.com`) |
| 32 | Retries: WhatsApp | BLOCKED (Salesforce, Signal, Splashtop done in batch G; Zscaler done) |

No unresearched candidates remain in this queue.
