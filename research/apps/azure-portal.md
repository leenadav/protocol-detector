# Microsoft Azure portal

- Content-pack id today: none
- Status: **READY**, NAME, batch M: new id `azure-portal`
- Sources: [Z] read in the research cloud (egress proxy), 2026-11-21; ms.date 2025-08-28

## 1. What it is

The web console for Microsoft Azure, and Azure Resource Manager (ARM), the management API behind it.

## 2. Transport and ports

HTTPS on 443 (the page lists URLs only) [Z].

## 3. Observable evidence

[Z] Azure portal authentication: `login.microsoftonline.com`, `login.microsoft.com`, `login.live.com`, `*.aadcdn.msftauth.net`, `*.msauth.net` and related sign-in CDNs. Azure portal framework: `*.portal.azure.com`, `*.hosting.portal.azure.net`, `*.hosting-ms.portal.azure.net`, `*.reactblade.portal.azure.net`, `management.azure.com`, `*.ext.azure.com`, `*.graph.windows.net`, `*.graph.microsoft.com`, `hosting.partners.azure.net`. Account data: `*.account.microsoft.com`, `*.bmx.azure.com`, `*.subscriptionrp.trafficmanager.net`, `*.signup.azure.com`. Further sections list per-service names (shared CDNs such as `*.azureedge.net`, `catalogartifact.azureedge.net`) and US Government names.

## 4. Encrypted-traffic caveats

`management.azure.com` is ARM: the Azure CLI, PowerShell, SDKs and infrastructure-as-code tools call it too, so a match means Azure management activity, not necessarily the portal (**N2**; the description says so). Sign-in stays `azure-ad`, Graph and account names stay Microsoft-wide. Only names in the Microsoft-owned `azure.com` and `azure.net` subtrees the page lists are proposed, never `azure.com` itself, which also hosts unrelated service names (for example `webpubsub.azure.com`). The retrofit table listed `portal.azure.com` as unmapped shared Microsoft infrastructure on the Intune page; it now maps here.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `portal.azure.com`, `portal.azure.net`, `ext.azure.com`, `hosting.partners.azure.net` | **N3** | Portal framework |
| Exact subtree `management.azure.com` | **N2** | ARM; shared with CLI and SDKs |
| SNI under `bmx.azure.com`, `signup.azure.com` | **N2** | Account and sign-up |
| Sign-in, Graph, CDNs | not mapped | Shared |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K and M): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `portal.azure.com`, `x.hosting.portal.azure.net`, `x.reactblade.portal.azure.net` | `azure-portal` (today unmapped) |
| P2 | SNI `management.azure.com`, `x.ext.azure.com` | `azure-portal` (today unmapped) |
| N1 | SNI `x.webpubsub.azure.com`, `gatewayadminportal.azure.com`, `login.microsoftonline.com`, `xportal.azure.com` | not `azure-portal` |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O, P and Q as rebuilt 2026-11-24)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xazure.com` | not azure-portal (label boundary) | no application | PASS |
| L- | `portal.azure.com.example.invalid` | not azure-portal (suffix look-alike) | no application | PASS |
| L- | `xazure.net` | not azure-portal (label boundary) | no application | PASS |
| L- | `portal.azure.net.example.invalid` | not azure-portal (suffix look-alike) | no application | PASS |
| L- | `ext.azure.com.example.invalid` | not azure-portal (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [Z] Microsoft Learn, "Allow the Azure portal URLs on your firewall or proxy server", `https://learn.microsoft.com/en-us/azure/azure-portal/azure-portal-safelist-urls`, read in the research cloud (egress proxy), 2026-11-21.

## 8. Catalog delta and recommendation

```python
("azure-portal", "business-systems", "management", "browser-based", 2, "Microsoft Azure portal and Azure Resource Manager", (),
 ("portal.azure.com", "portal.azure.net", "ext.azure.com", "management.azure.com", "hosting.partners.azure.net",
  "bmx.azure.com", "signup.azure.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `portal.azure.com` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `portal.azure.com`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation); CNAME into shared front end `s-part-0044.p-0010.p-msedge.net`: name usable, IPs never |
| `portal.azure.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `ext.azure.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `management.azure.com` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `edge.management.azure.com`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation); CNAME into shared front end `arm-0001.arm-msedge.net`: name usable, IPs never |
| `hosting.partners.azure.net` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `hosting.portal.azure.net`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation); CNAME into shared front end `part-0034.t-0009.t-msedge.net`: name usable, IPs never |
| `bmx.azure.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `signup.azure.com` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `signup.azure.com`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation); CNAME into shared front end `waws-prod-sn1-131.southcentralus.cloudapp.azure.com`: name usable, IPs never |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `azure-portal`: business-systems / management, browser-based; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
