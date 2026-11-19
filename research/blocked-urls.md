# Pages this lane cannot read: for Hermes to open and relay

Updated 2026-11-19. This lane does not bypass bot challenges, sign-ins or other access controls. For each page,
please open the exact URL in a normal browser and relay the parts named below as text (domain names, ports and the
page's own date). The relayed text is cited as "read by Lee or Hermes, relayed", as was done for OpenAI.

| # | Vendor | Exact official URL | Why this lane cannot read it | What is needed from it |
|---|---|---|---|---|
| 1 | Salesforce | `https://help.salesforce.com/s/articleView?id=000384438&type=1` (target of the older `https://help.salesforce.com/HTViewSolution?id=000003652`) | client-side app renders empty for this lane | the "Required Domains" (or equivalent) list of Salesforce-operated domains for users (not IP lists); which domains are customer-specific (My Domain, `*.my.salesforce.com`, `*.force.com`, `*.lightning.force.com`); the page's updated date |
| 2 | Signal | `https://support.signal.org/hc/en-us/articles/360007320291-Firewall-and-Internet-settings` | Cloudflare bot challenge | the host names and ports Signal clients use (chat, calls, attachments, CDN); any statement about censorship-circumvention proxies; the page date |
| 3 | WhatsApp | **URL unknown**: no consumer WhatsApp network or firewall article was found on `faq.whatsapp.com`. The only official network page found, `https://developers.secure.facebook.com/docs/whatsapp/guides/network-requirements`, now redirects to the WhatsApp Business API on-premises sunset notice (a different product) | no primary page found | if WhatsApp publishes one, the URL of its consumer firewall or network article, and its host names and ports |
| 4 | Splashtop | `https://support-splashtopbusiness.splashtop.com/hc/en-us/articles/115001811966` ("What Are the Firewall Exceptions and IP addresses of Splashtop Servers/Services?"); the older host `support-splashtop.com` is unreachable | Cloudflare bot challenge on the business support host | the listed domains (wildcards) with their purpose, the ports (TCP 443 and any others), any per-product differences; the page date |
| 5 | Miro | `https://help.miro.com/hc/articles/360017572694` ("Add Miro to Allowed Domains"), plus the "Miro domains" page it links to | Cloudflare bot challenge | the full Miro domain list from the linked page, and the WebSocket and proxy notes |
| 6 | Grammarly | `https://support.grammarly.com/hc/en-us/articles/115000090271-Network-configuration-blocks-Grammarly-services` | the page renders without its article body for this lane | the endpoint list (`*.grammarly.com`, `*.grammarly.io`, any others) and WebSocket hosts; the page date |
| 7 | GoTo Resolve | `https://support.goto.com/resolve/help/allowlisting-and-goto-resolve` | the proxy tunnel fails for this path (the GoTo Meeting page on the same host worked) | the GoTo Resolve domains (`*.gotoresolve.com` and others) and ports |
| 8 | Google Gemini API | `https://aistudio.google.com/docs/get-started` (where `https://ai.google.dev/gemini-api/docs/quickstart` now redirects) | host not allowed in this session; this lane can request it if preferred | the REST base URL of the Gemini API (host name only), to decide whether a dedicated API host exists |

Not listed (decided low priority, 2026-11-18): Box (sign-in required) and Slack (workspace-specific list).
No longer blocked: Zscaler, now sourced from `https://config.zscaler.com/zscaler.net/zscaler-app` (`apps/zscaler.md`).
