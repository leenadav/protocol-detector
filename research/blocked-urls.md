# Pages this lane cannot read: for Hermes to open and relay

Updated 2026-11-20 (rows 12 to 18 resolved). This lane does not bypass bot challenges, sign-ins or other access
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
| 24 | DocuSign | read by Research Lab on the Hermes server (PRO-108, 2026-11-21) | | content awaits relay to this lane (batch M follow-up) |
| 25 | Snowflake | read by Research Lab on the Hermes server (PRO-108, 2026-11-21) | | content awaits relay to this lane (batch M follow-up) |
| 26 | Twilio | read by Research Lab on the Hermes server (PRO-108, 2026-11-21) | | content awaits relay to this lane (batch M follow-up) |
| 27 | Sophos Central | read by Research Lab on the Hermes server (PRO-108, 2026-11-21) | | content awaits relay to this lane (batch M follow-up) |
| 28 | Egnyte | **URL not located**: the vendor's documentation host is not reachable from this session (allowlist full, 2026-11-21) | host not allowed | the official network, firewall or allowlist page: server names, ports, date (batch M, PRO-92) ; Research Lab (PRO-108): still blocked (sign-in, bot challenge or JavaScript-only) |
| 29 | Palo Alto GlobalProtect | **URL not located**: `docs.paloaltonetworks.com` answers but renders client-side | JavaScript-only page | any Palo Alto-operated names the GlobalProtect app reaches (portals and gateways are customer-hosted) ; Research Lab (PRO-108): still blocked (sign-in, bot challenge or JavaScript-only) |

Rows 12 to 18 were read by Research Lab from the Hermes server on 2026-11-20 (PRO-29) and are resolved below.

## Resolved (relays of 2026-11-19 and 2026-11-20)

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

Not listed (decided low priority, 2026-11-18): Box (sign-in required) and Slack (workspace-specific list).
No official network page found (not listed): Smartsheet, Airtable, npm, PyPI, NinjaOne (proxy article not located), Windsurf (proxy settings only, no domain list).
No longer blocked: Zscaler, now sourced from `https://config.zscaler.com/zscaler.net/zscaler-app` (`apps/zscaler.md`).
