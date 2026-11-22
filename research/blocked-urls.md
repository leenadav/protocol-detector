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
| 28 | Egnyte | **URL not located**: the vendor's documentation host is not reachable from this session (allowlist full, 2026-11-21) | host not allowed | the official network, firewall or allowlist page: server names, ports, date (batch M, PRO-92) ; Research Lab (PRO-108): still blocked (sign-in, bot challenge or JavaScript-only) |
| 29 | Palo Alto GlobalProtect | **URL not located**: `docs.paloaltonetworks.com` answers but renders client-side | JavaScript-only page | any Palo Alto-operated names the GlobalProtect app reaches (portals and gateways are customer-hosted) ; Research Lab (PRO-108): still blocked (sign-in, bot challenge or JavaScript-only) |
| 30 | Kaseya VSA (SaaS) | `https://helpdesk.kaseya.com/hc/en-gb/articles/229028268-Kaseya-Cloud-SaaS-IP-Addresses-and-Ports` | host not allowed from this session (allowlist at its cap), 2026-11-22 | SaaS host names and agent ports (the catalog uses no IPs) (batch P candidate, PRO-158) |
| 31 | Kaseya VSA (agent) | `https://help.vsa9.kaseya.com/help/Content/VSA/reqs/home.htm` | host not allowed from this session (allowlist at its cap), 2026-11-22 | agent outbound names and ports (agent minimum requirements) (batch P candidate, PRO-158) |
| 32 | ManageEngine Endpoint Central (Cloud) | `https://www.manageengine.com/products/desktop-central/help/domains-required-for-agent-communication.html` | host not allowed from this session (allowlist at its cap), 2026-11-22 | the per-data-centre domain list for agents, patching and remote control (batch P candidate, PRO-158) |
| 33 | RingCentral (RingEX) | `https://support.ringcentral.com/gb/en/network-and-system-requirements/network-requirements/network-requirements-ringex.html` | host not allowed from this session (allowlist at its cap), 2026-11-22 | the web-proxy rows (FQDNs and ports); the IP supernet rows are not used (batch P candidate, PRO-158) |
| 34 | Mimecast | `https://mimecastsupport.zendesk.com/hc/en-us/articles/34000362728979` and `https://mimecastsupport.zendesk.com/hc/en-us/articles/34000479767443` | host not allowed from this session (allowlist at its cap), 2026-11-22 | regional URLs and ports (data centres and URLs; Web Security prerequisites) (batch P candidate, PRO-158) |
| 35 | Proofpoint Essentials | `https://help.proofpoint.com/Proofpoint_Essentials/Administrator_Topics/000_gettingstarted/020_connectiondetails` | host not allowed from this session (allowlist at its cap), 2026-11-22 | connection details: host names per stack (US, EU) and ports (batch P candidate, PRO-158) |
| 36 | Keeper | `https://docs.keeper.io/en/enterprise-guide/ip-allow-keeper` | host not allowed from this session (allowlist at its cap), 2026-11-22 | the per-region domain list and ports (batch P candidate, PRO-158) |
| 37 | LastPass | `https://support.lastpass.com/help/whitelisting-and-firewall-configuration-for-logmein-products` | host not allowed from this session (allowlist at its cap), 2026-11-22 | the domain list and ports (batch P candidate, PRO-158) |
| 38 | 8x8 Work | `https://support.8x8.com/cloud-phone-service/voice/network-setup-voice/x-series-technical-requirements` | host not allowed from this session (allowlist at its cap), 2026-11-22 | the domain list and ports (and the hosted domains JSON it links) (batch P candidate, PRO-158) |
| 39 | Dialpad | `https://help.dialpad.com/docs/network-setup-recommendations` | host not allowed from this session (allowlist at its cap), 2026-11-22 | the restrictive domain list and ports (batch P candidate, PRO-158) |
| 40 | Freshworks (Freshdesk, Freshservice) | `https://support.freshdesk.com/support/solutions/articles/234412-freshdesk-domains-to-whitelist-in-your-firewall` and `https://support.freshservice.com/en/support/solutions/articles/50000003571-update-to-waf-web-application-firewall-for-freshservice-load-balancers` | host not allowed from this session (allowlist at its cap), 2026-11-22 | the domain lists for both products (batch P candidate, PRO-158) |
| 41 | Dashlane | `https://support.dashlane.com/hc/articles/27983351888786` | host not allowed from this session (allowlist at its cap), 2026-11-22 | the domain list and port (batch P candidate, PRO-158) |
| 42 | Intercom | `https://www.intercom.com/help/en/articles/3894-what-domains-do-i-need-to-whitelist` | host not allowed from this session (allowlist at its cap), 2026-11-22 | the Messenger and Inbox domain list per region (batch P candidate, PRO-158) |
| 43 | New Relic | `https://docs.newrelic.com/docs/new-relic-solutions/get-started/networks/` | host not allowed from this session (allowlist at its cap), 2026-11-22 | the endpoint list (ingest and user-facing domains) (batch P candidate, PRO-158) |
| 44 | PagerDuty | `https://support.pagerduty.com/docs/safelist-ips` | host not allowed from this session (allowlist at its cap), 2026-11-22 | the API, Events and app host names per region (batch P candidate, PRO-158) |

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
| 24 | DocuSign (PRO-108, relayed PRO-121; full re-read PRO-138, relayed PRO-139) | batch N (`apps/docusign.md`): `docucdn-a.akamaihd.net` added; READY: the list has 8 entries, email and Connect are IP ranges only; `*.docusign.pdfeditor.com` not mapped (Nitro-operated, live round 6) |
| 25 | Snowflake | batch N (`apps/snowflake.md`): no fixed list (per-account names from `SYSTEM$ALLOWLIST()`); no change |
| 26 | Twilio | batch N (`apps/twilio.md`): all names under `twilio.com`; no change (the essential-domains support article returned 403) |
| 27 | Sophos Central | batch N (`apps/sophos-central.md`): five Sophos domains added; Endpoint/EDR/XDR/MDR section only |

Not listed (decided low priority, 2026-11-18): Box (sign-in required) and Slack (workspace-specific list).
No official network page found (not listed): Smartsheet, Airtable, npm, PyPI, NinjaOne (proxy article not located), Windsurf (proxy settings only, no domain list).
Research Lab's PRO-95 search (2026-11-22, batch O in `backlog.md`) confirmed: Smartsheet (connector relay only), Airtable, monday.com and HubSpot (IPs only), NinjaOne (ports only), FortiSASE (ports only), Discord (help centre 403; developer docs only), ConnectWise ScreenConnect (sign-in wall), Telegram and Windsurf (no allowlist).
No longer blocked: Zscaler, now sourced from `https://config.zscaler.com/zscaler.net/zscaler-app` (`apps/zscaler.md`).
