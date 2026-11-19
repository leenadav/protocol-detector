# Pages this lane cannot read: for Hermes to open and relay

Updated 2026-11-19 (after the first relay). This lane does not bypass bot challenges, sign-ins or other access
controls. For each page, please open the exact URL in a normal browser and relay the parts named below as text
(domain names, ports and the page's own date). The relayed text is cited as "read by Hermes, relayed".

## Still open

| # | Vendor | Exact official URL | Why this lane cannot read it | What is needed from it |
|---|---|---|---|---|
| 3 | WhatsApp | **URL unknown**: no consumer WhatsApp network or firewall article was found (Hermes knows none either) | no primary page found | left as is |
| 11 | Hugging Face | **URL unknown**: no official network or firewall page found (Hermes knows none either) | | left as is |
| 12 | Cisco Umbrella (Secure Client / roaming client) | `https://securitydocs.cisco.com/docs/umbrella-sig/olh/152711.dita` and the roaming-client prerequisites (`docs.umbrella.com/deployment-umbrella/docs/prerequisites-5`) | the lists live in child topics this lane cannot reach | the host names and ports the client needs (DNS, `*.opendns.com`, `*.umbrella.com` and others), with purposes |
| 13 | Parsec | `https://support.parsec.app/hc/en-us/articles/32381460716180-Parsec-Connectivity-Requirements` | Cloudflare bot challenge | the host list (`kessel-ws.parsec.app` and others) with ports |
| 14 | Asana | `https://help.asana.com/s/article/asana-ip-address-ranges-and-hostnames` | page renders empty | the non-FedRAMP host names |
| 15 | Jamf Pro | `https://learn.jamf.com/r/en-US/technical-articles/Network_Ports_Used_by_Jamf_Pro` | page renders empty (JavaScript app) | the Jamf Cloud host names (`*.jamfcloud.com` and named hosts) |
| 16 | Atera | `https://support.atera.com/hc/en-us/articles/360015461139` | Cloudflare bot challenge | the agent domains and ports |
| 17 | Salesforce | the "Salesforce Help Required Domains" page linked from article 000384438 (**URL not in the relayed text**) | client-side app renders empty | its domain list, for any Salesforce-operated domain outside `salesforce.com` and `force.com` |
| 18 | Grammarly | the "WebSockets Support Q&A for System Administrators" article linked from article 115000090271 (**URL not in the relayed text**) | Grammarly's article body does not render for this lane | any endpoint or WebSocket host list |

Rows 12 to 16 were not in the first relay.

## Resolved by the relay of 2026-11-19

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

Not listed (decided low priority, 2026-11-18): Box (sign-in required) and Slack (workspace-specific list).
No official network page found (not listed): Smartsheet, Airtable, npm, PyPI, NinjaOne (proxy article not located), Windsurf (proxy settings only, no domain list).
No longer blocked: Zscaler, now sourced from `https://config.zscaler.com/zscaler.net/zscaler-app` (`apps/zscaler.md`).
