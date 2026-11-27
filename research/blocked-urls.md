# Pages this lane cannot read: for Hermes to open and relay

Updated 2026-11-27 (rows 45 to 54 added by PRO-495, child apps wave 0; rows 30 to 33, 36, 38, 40 and 42 to 44 resolved, PRO-169; 34, 35, 37, 39 and 41 stay BLOCKED). This lane does not bypass bot challenges, sign-ins or other access
controls. For each page, please open the exact URL in a normal browser and relay the parts named below as text
(domain names, ports and the page's own date). The relayed text is cited as "read by Hermes, relayed".

## Still open

| # | Vendor | Exact official URL | Why this lane cannot read it | What is needed from it |
|---|---|---|---|---|
| 3 | WhatsApp | **URL unknown**: no consumer WhatsApp network or firewall article was found (Hermes knows none either) | no primary page found | left as is |
| 11 | Hugging Face | **URL unknown**: no official network or firewall page found (Hermes knows none either) | | left as is |
| 19 | ServiceNow | **URL not located**: the vendor's documentation host is not reachable from this session (allowlist full, 2026-11-21) | host not allowed | the official network, firewall or allowlist page: server names, ports, date (batch M, PRO-92) ; Research Lab (PRO-108): still blocked (sign-in, bot challenge or JavaScript-only) |
| 20 | Workday | **URL not located**: the vendor's documentation host is not reachable from this session (allowlist full, 2026-11-21) | host not allowed | the official network, firewall or allowlist page: server names, ports, date (batch M, PRO-92) ; Research Lab (PRO-108): still blocked (sign-in, bot challenge or JavaScript-only) |
| 21 | CrowdStrike Falcon sensor | **URL not located**: the vendor's documentation host is not reachable from this session (allowlist full, 2026-11-21) | host not allowed | the official network, firewall or allowlist page: server names, ports, date (batch M, PRO-92) ; Research Lab (PRO-108): still blocked (sign-in, bot challenge or JavaScript-only) |
| 22 | SentinelOne agent | **URL not located**: the vendor's documentation host is not reachable from this session (allowlist full, 2026-11-21) | host not allowed | the official network, firewall or allowlist page: server names, ports, date (batch M, PRO-92) ; Research Lab (PRO-108): still blocked (sign-in, bot challenge or JavaScript-only) |
| 23 | Cisco Secure Client (AnyConnect) | **URL not located**: the vendor's documentation host is not reachable from this session (allowlist full, 2026-11-21) | host not allowed | the official network, firewall or allowlist page: server names, ports, date (batch M, PRO-92) ; Research Lab (PRO-108): still blocked (sign-in, bot challenge or JavaScript-only) |
| 28 | Egnyte | **URL not located**: the vendor's documentation host is not reachable from this session (allowlist full, 2026-11-21) | host not allowed | the official network, firewall or allowlist page: server names, ports, date (batch M, PRO-92) ; Research Lab (PRO-108): still blocked (sign-in, bot challenge or JavaScript-only) |
| 29 | Palo Alto GlobalProtect | **URL not located**: `docs.paloaltonetworks.com` answers but renders client-side | JavaScript-only page | any Palo Alto-operated names the GlobalProtect app reaches (portals and gateways are customer-hosted) ; Research Lab (PRO-108): still blocked (sign-in, bot challenge or JavaScript-only) |
| 34 | Mimecast | `https://mimecastsupport.zendesk.com/hc/en-us/articles/34000362728979` and `https://mimecastsupport.zendesk.com/hc/en-us/articles/34000479767443` | Research Lab, PRO-168, 2026-11-22: still blocked: 403 bot challenge (not bypassed) | BLOCKED |
| 35 | Proofpoint Essentials | `https://help.proofpoint.com/Proofpoint_Essentials/Administrator_Topics/000_gettingstarted/020_connectiondetails` | Research Lab, PRO-168, 2026-11-22: still blocked: sign-in wall | BLOCKED |
| 37 | LastPass | `https://support.lastpass.com/help/whitelisting-and-firewall-configuration-for-logmein-products` | Research Lab, PRO-168, 2026-11-22: still blocked: the server sends an incomplete TLS certificate chain (no read with verification off without Lee's approval; a browser relay is the alternative) | BLOCKED |
| 39 | Dialpad | `https://help.dialpad.com/docs/network-setup-recommendations` | Research Lab, PRO-168, 2026-11-22: still blocked: 403 | BLOCKED |
| 41 | Dashlane | `https://support.dashlane.com/hc/articles/27983351888786` | Research Lab, PRO-168, 2026-11-22: still blocked: 403 | BLOCKED |
| 45 | WeTransfer (developer API) | `https://developer.wetransfer.com/` | not reachable from this environment (PRO-495, 2026-11-27) | published request paths for creating and downloading a transfer (`research/child-apps/wave-0.json`) |
| 46 | Slack (upload method) | `https://docs.slack.dev/reference/methods/files.getUploadURLExternal` | not reachable (PRO-495) | method, content type and upload URL host, to confirm what wave 0 took from Slack's own SDK |
| 47 | Slack (file download) | `https://docs.slack.dev/messaging/working-with-files` | not reachable (PRO-495) | the download URL form (`url_private`, `files.slack.com` path) for `slack-downloading` |
| 48 | Zoom (developer API) | `https://developers.zoom.us/docs/api/` | not reachable (PRO-495) | chat file upload and recording download endpoints: host, method, path |
| 49 | Meta Graph API | `https://developers.facebook.com/docs/graph-api/` | not reachable (PRO-495) | reference pages for `/feed`, `/photos`, `/videos`, to confirm what wave 0 took from Meta's Business SDK |
| 50 | Instagram Platform | `https://developers.facebook.com/docs/instagram-platform/` | not reachable (PRO-495) | content publishing (`/media`, `/media_publish`) and whether `graph.instagram.com` is used |
| 51 | X API (media upload) | `https://docs.x.com/x-api/media/upload-media` | not reachable (PRO-495) | the media upload reference, to confirm X's SDK and any multipart form |
| 52 | Pastebin API | `https://pastebin.com/doc_api` | not reachable (PRO-495) | the paste-creation request: method, path, content type, the option field |
| 53 | Reddit API | `https://www.reddit.com/dev/api/` | not reachable (PRO-495) | submit and media-upload endpoints (host, method, path) |
| 54 | Reddit help | `https://support.reddithelp.com/` | not reachable (PRO-495) | any official network or firewall page |

Rows 12 to 18 were read by Research Lab from the Hermes server on 2026-11-20 (PRO-29) and are resolved below. Rows 30 to 44 were read by Research Lab on 2026-11-22 (PRO-168): ten are resolved below (PRO-169); rows 34, 35, 37, 39 and 41 stay BLOCKED above.

## Resolved (relays of 2026-11-19, 2026-11-20 and 2026-11-22)

| # | Vendor | Result |
|---|---|---|
| 1 | Salesforce (article 000384438) | read; no catalog change (`apps/salesforce.md`); the linked list is row 17 |
| 2 | Signal | batch G (`apps/signal.md`) |
| 4 | Splashtop | batch G (`apps/splashtop.md`) |
| 5 | Miro (both pages) | batch G (`apps/miro.md`) |
| 6 | Grammarly | read, but the article has no endpoint list (`apps/grammarly.md`); the linked article is row 18 |
| 7 | GoTo Resolve (redirected to `support.logmein.com`, LogMeIn Resolve) | batch G (`apps/logmein-resolve.md`) |
| 8 | Google Gemini API | the relayed page did not name the host; this lane then read the API reference itself (`aistudio.google.com` allowed for this session); batch G (`apps/google-gemini-api.md`) |
| 9 | Canva | batch G (`apps/canva.md`) |
| 10 | Cisco Duo | batch G (`apps/duo-security.md`) |
| 12 | Cisco Umbrella (three topics: 152386, 152709, 152715) | batch J (`apps/cisco-umbrella.md`): `umbrella.com` added to `opendns`; the resolver IPs are not used |
| 13 | Parsec (via the Zendesk API) | batch J (`apps/parsec.md`) |
| 14 | Asana | batch J (`apps/asana.md`) |
| 15 | Jamf Pro (via the Fluid Topics API) | batch J (`apps/jamf-pro.md`): new id `jamf-pro` |
| 16 | Atera (agent section) | batch J (`apps/atera.md`) |
| 17 | Salesforce "Allow the Required Domains" | batch J (`apps/salesforce.md`): 22 domains added |
| 18 | Grammarly "WebSockets Support Q&A" | batch J (`apps/grammarly.md`): `grammarly.net` added; `coda.io` left out (separate product) |
| 24 | DocuSign (PRO-108, relayed PRO-121; full re-read PRO-138, relayed PRO-139) | batch N (`apps/docusign.md`): `docucdn-a.akamaihd.net` added; READY: the list has 8 entries, email and Connect are IP ranges only; `*.docusign.pdfeditor.com` not mapped (Nitro-operated, live round 6) |
| 25 | Snowflake | batch N (`apps/snowflake.md`): no fixed list (per-account names from `SYSTEM$ALLOWLIST()`); no change |
| 26 | Twilio | batch N (`apps/twilio.md`): all names under `twilio.com`; no change (the essential-domains support article returned 403) |
| 27 | Sophos Central | batch N (`apps/sophos-central.md`): five Sophos domains added; Endpoint/EDR/XDR/MDR section only |
| 30 | Kaseya VSA (SaaS) | read by Research Lab, 2026-11-22 (PRO-168; relayed in `research/relay/pro-168-rows-30-44.md` on `hermes/research-data-pro168` `f721a8c`): IP ranges and ports only, no host names; no change (`apps/kaseya.md`, DONE) |
| 31 | Kaseya VSA (agent) | read by Research Lab, 2026-11-22 (PRO-168; relayed in `research/relay/pro-168-rows-30-44.md` on `hermes/research-data-pro168` `f721a8c`): `stun.kaseya.com` (3478), agent port 5721; no change, all names under `kaseya.com` (`apps/kaseya.md`, DONE) |
| 32 | ManageEngine Endpoint Central (Cloud) | read by Research Lab, 2026-11-22 (PRO-168; relayed in `research/relay/pro-168-rows-30-44.md` on `hermes/research-data-pro168` `f721a8c`) (moved to `.../help/cloud/server/domains-required-for-agent-communication.html`): batch Q (`apps/manageengine-endpoint-central.md`): new id `manageengine-endpoint-central`, 54 exact names; Zoho-hosted names not attributed |
| 33 | RingCentral (RingEX) | read by Research Lab, 2026-11-22 (PRO-168; relayed in `research/relay/pro-168-rows-30-44.md` on `hermes/research-data-pro168` `f721a8c`): batch Q (`apps/ringcentral.md`): 17 names added (regional domains, `glip.com`, exact PubNub and S3 hosts) |
| 36 | Keeper | read by Research Lab, 2026-11-22 (PRO-168; relayed in `research/relay/pro-168-rows-30-44.md` on `hermes/research-data-pro168` `f721a8c`): batch Q (`apps/keeper.md`): five regional domains and `keeper.io` added |
| 38 | 8x8 Work | read by Research Lab, 2026-11-22 (PRO-168; relayed in `research/relay/pro-168-rows-30-44.md` on `hermes/research-data-pro168` `f721a8c`) (moved to `help.8x8.com/docs/x-series-technical-requirements.md`): batch Q (`apps/8x8.md`): six 8x8 domains added; `callstats.io` and deprecated domains left out |
| 40 | Freshworks (Freshdesk, Freshservice) | read by Research Lab, 2026-11-22 (PRO-168; relayed in `research/relay/pro-168-rows-30-44.md` on `hermes/research-data-pro168` `f721a8c`): batch Q (`apps/freshworks.md`): five platform domains added; Freshchat and Freshmarketer left out |
| 42 | Intercom | read by Research Lab, 2026-11-22 (PRO-168; relayed in `research/relay/pro-168-rows-30-44.md` on `hermes/research-data-pro168` `f721a8c`) (moved to article `3894-using-intercom-with-content-security-policy`): batch Q (`apps/intercom.md`): 19 domains added |
| 43 | New Relic | read by Research Lab, 2026-11-22 (PRO-168; relayed in `research/relay/pro-168-rows-30-44.md` on `hermes/research-data-pro168` `f721a8c`) (page dated 2025-03-04): batch Q (`apps/new-relic.md`): browser-agent hosts to new vendor-level id `new-relic-base`; `new-relic` unchanged |
| 44 | PagerDuty | read by Research Lab, 2026-11-22 (PRO-168; relayed in `research/relay/pro-168-rows-30-44.md` on `hermes/research-data-pro168` `f721a8c`) (moved to `docs.pagerduty.com/account-admin/safelist-ips`): no change, all names under `pagerduty.com` (`apps/pagerduty.md`, DONE) |

Not listed (decided low priority, 2026-11-18): Box (sign-in required) and Slack (workspace-specific list).
No official network page found (not listed): Smartsheet, Airtable, npm, PyPI, NinjaOne (proxy article not located), Windsurf (proxy settings only, no domain list).
Research Lab's PRO-95 search (2026-11-22, batch O in `backlog.md`) confirmed: Smartsheet (connector relay only), Airtable, monday.com and HubSpot (IPs only), NinjaOne (ports only), FortiSASE (ports only), Discord (help centre 403; developer docs only), ConnectWise ScreenConnect (sign-in wall), Telegram and Windsurf (no allowlist).
No longer blocked: Zscaler, now sourced from `https://config.zscaler.com/zscaler.net/zscaler-app` (`apps/zscaler.md`).
