# Citrix Cloud

- Content-pack id today: none
- Status: **READY**, NAME, batch H: new id `citrix-cloud`
- Sources: accessed 2026-11-19; page modified 2026-11-18 (page metadata)

## 1. What it is

Citrix Cloud: the control plane for Citrix DaaS (virtual apps and desktops), Workspace, the Citrix Gateway Service, Secure Private Access and Remote Browser Isolation.

## 2. Transport and ports

"For the management console to operate, you must have port 443 open for outbound connections." "Citrix Cloud supports Transport Layer Security (TLS) 1.2 for TCP-based connections between components"; Cloud Connectors need "HTTPS and long-lived secure web sockets" [S1]. HDX session ports (including any UDP transport) are not on this page (`UNVERIFIED`).

## 3. Observable evidence

[S1]: common addresses `*.citrixworkspacesapi.net` ("Citrix Cloud APIs"), `*.cloud.com` ("Citrix Cloud sign-in interface"), `trust.citrixnetworkapi.net` (Connector registration); Gateway Service `*.*.nssvc.net` (or `*.g.nssvc.net`, `*.c.nssvc.net`; PoPs such as `global-s.g.nssvc.net`); DaaS `https://[customerid].xendesktop.net`; Secure Private Access `*.netscalergateway.net`; Global App Configuration `discovery.cem.cloud.us`; Endpoint Management console `*.citrix.com`; Remote Browser Isolation `launch.cloud.com` and `*.browser.cloud.com` hosts; StoreFront Cloud "a cloud URL, e.g. https://<customername>.cloud.com"; VDA installers on `prod-us-`, `prod-eu-`, `prod-aps-`, `prod-jp-vus-storage-endpoint.azureedge.net`. Shared services also listed: `*.blob.core.windows.net`, `*.servicebus.windows.net`, Azure container registry hosts, Pendo (`citrix-cloud-*.customer.pendo.io`), DigiCert and Entrust CRL/OCSP. "SSL interception cannot be performed on Citrix Gateway addresses."

## 4. Encrypted-traffic caveats

`cloud.com` is proposed as a whole because the page uses `*.cloud.com` throughout for Citrix Cloud, including customer store names. Store and DaaS host names (`<customername>.cloud.com`, `[customerid].xendesktop.net`) carry customer identifiers; the catalog names the application only and must never emit them. Whether Citrix's parent company uses `cloud.com` for other products is `UNVERIFIED` (N2 for the apex suffix). `cloud.us` is not proposed, only the exact `discovery.cem.cloud.us`. Shared Azure, Pendo and CA names are not proposed. Gateway Service traffic (`nssvc.net`) tunnels the user's virtual sessions, hence `tunnels-other-applications`. The apex `citrix.com` and `www.citrix.com` are web fronts (provider affiliation only), as for the other remote-access vendors.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `citrixworkspacesapi.net`, `citrixnetworkapi.net`, `nssvc.net`, `xendesktop.net`, `netscalergateway.net` | **N3** |  |
| SNI under `cloud.com` | **N2** | Citrix Cloud per the page; parent-company use of the domain unverified |
| SNI `citrix.com`, `www.citrix.com` | web front | Provider affiliation only |
| Exact `discovery.cem.cloud.us` and the four `*-vus-storage-endpoint.azureedge.net` hosts | **N3** (exact) |  |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D, E, F, G and H): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `citrix.cloud.com`, `acme.cloud.com`, `api.cloud.com` | `citrix-cloud` |
| P2 | SNI `trust.citrixworkspacesapi.net`, `trust.citrixnetworkapi.net`, `global-s.g.nssvc.net`, `abc123.xendesktop.net`, `x.netscalergateway.net` | `citrix-cloud` |
| P3 | SNI `discovery.cem.cloud.us`, `prod-eu-vus-storage-endpoint.azureedge.net` | `citrix-cloud` |
| P4 | SNI `www.citrix.com` | `citrix-cloud` web front |
| N1 | SNI `cloud.us`, `x.servicebus.windows.net`, `citrix-cloud-data.customer.pendo.io` | unmapped |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O, P and Q as rebuilt 2026-11-24)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `accounts-webassets.cloud.com` | one of `citrix-cloud` | `citrix-cloud` | PASS |
| O+ | `accounts.cloud.com` | one of `citrix-cloud` | `citrix-cloud` | PASS |
| O+ | `citrix.cloud.com` | one of `citrix-cloud` | `citrix-cloud` | PASS |
| D- | `citrix-cloud-content.customer.pendo.io` | not citrix-cloud (third party (unclassified)) | no application | PASS |
| D- | `www.googletagmanager.com` | not citrix-cloud (third party) | `google-analytics` | PASS |
| L- | `xcloud.com` | not citrix-cloud (label boundary) | no application | PASS |
| L- | `cloud.com.example.invalid` | not citrix-cloud (suffix look-alike) | no application | PASS |
| L- | `xcitrix.com` | not citrix-cloud (label boundary) | no application | PASS |
| L- | `citrix.com.example.invalid` | not citrix-cloud (suffix look-alike) | no application | PASS |
| L- | `xcitrixworkspacesapi.net` | not citrix-cloud (label boundary) | no application | PASS |
| L- | `citrixworkspacesapi.net.example.invalid` | not citrix-cloud (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Citrix Product Documentation, "Internet connectivity requirements" (Citrix Cloud), `https://docs.citrix.com/us/en/citrix-cloud/internet-connectivity-requirements.html`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

```python
("citrix-cloud", "networking", "remote-access", "client-server", 3, "Citrix Cloud, DaaS and Workspace",
 ("tunnels-other-applications",),
 ("cloud.com", "citrix.com", "citrixworkspacesapi.net", "citrixnetworkapi.net", "nssvc.net", "xendesktop.net",
  "netscalergateway.net", "discovery.cem.cloud.us", "prod-us-vus-storage-endpoint.azureedge.net",
  "prod-eu-vus-storage-endpoint.azureedge.net", "prod-aps-vus-storage-endpoint.azureedge.net",
  "prod-jp-vus-storage-endpoint.azureedge.net"),
 ("citrix.com", "www.citrix.com")),
```

Risk 3, not 4 like the consumer remote-access tools: Citrix is centrally administered enterprise virtual desktop access. Hermes may set it differently.

**Decision applied (2026-11-20):** risk stays **3**. Reason: Citrix Cloud is centrally administered by the
customer's IT (tenant-bound stores, admin-controlled DaaS), unlike risk-4 tools such as AnyDesk or TeamViewer,
which any user can install and use for unsanctioned remote control. `tunnels-other-applications` still applies.
Live check supports the `cloud.com` attribution: `citrix.com`'s own certificate is `*.cloud.com` with 34 SANs, and
`accounts.cloud.com` and `citrix.cloud.com` serve `cloud.com` certificates.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `cloud.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `www.cloud.com`, subject organisation **Cloud Software Group, Inc.** (issuer DigiCert Inc) |
| `citrix.com` | **L** resolves; TLSv1.2, ALPN `http/1.1`, cert `*.cloud.com`, subject organisation **Cloud Software Group, Inc.** (issuer DigiCert Inc) |
| `citrixworkspacesapi.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `citrixnetworkapi.net` | apex has no address (normal for a suffix entry); suffix **verified** through documented `trust.citrixnetworkapi.net` (round 2) |
| `nssvc.net` | apex has no address (normal for a suffix entry); suffix **verified** through documented `global-s.g.nssvc.net` (round 2, cdn) |
| `xendesktop.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `netscalergateway.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `discovery.cem.cloud.us` | **L** resolves; TLSv1.3, ALPN `None`, cert `*.cem.cloud.us`, subject organisation **Cloud Software Group, Inc.** (issuer DigiCert Inc); CNAME into shared front end `d2h5okjz9875in.cloudfront.net`: name usable, IPs never |
| `prod-us-vus-storage-endpoint.azureedge.net` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.azureedge.net`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation); CNAME into shared front end `mr-afd-azuredge.tm-azurefd.net`: name usable, IPs never |
| `prod-eu-vus-storage-endpoint.azureedge.net` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.azureedge.net`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation); CNAME into shared front end `mr-afd-azuredge.tm-azurefd.net`: name usable, IPs never |
| `prod-aps-vus-storage-endpoint.azureedge.net` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.azureedge.net`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation); CNAME into shared front end `hel01r9b.msedge.net`: name usable, IPs never |
| `prod-jp-vus-storage-endpoint.azureedge.net` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.azureedge.net`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation); CNAME into shared front end `hel01r9b.msedge.net`: name usable, IPs never |

## 10. Observed web-client hosts (dependency mapping)

- `https://citrix.cloud.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `accounts.cloud.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `accounts-webassets.cloud.com` | seen | app-owned | `citrix-cloud` | not checked |  |
| `accounts.cloud.com` | seen | app-owned | `citrix-cloud` | cdn |  |
| `citrix-cloud-content.customer.pendo.io` | seen | third party (unclassified) | no application | not checked |  |
| `citrix.cloud.com` | seen | app-owned | `citrix-cloud` | cdn |  |
| `www.googletagmanager.com` | seen | third party | `google-analytics` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `citrix-cloud`: networking / remote-access, client-server; characteristics `tunnels-other-applications`; **risk 3**: carries other traffic or remote control.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `citrix-cloud-content.customer.pendo.io`, `google-analytics`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
