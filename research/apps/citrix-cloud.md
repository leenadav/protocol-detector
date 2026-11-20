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

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L and J)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `accounts.cloud.com` | one of `citrix-cloud` | `citrix-cloud` | PASS |
| O+ | `citrix.cloud.com` | one of `citrix-cloud` | `citrix-cloud` | PASS |
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

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `cloud.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `www.cloud.com` (SAN covers name: True) |
| `citrix.com` | **L** resolves; TLSv1.2, ALPN `http/1.1`, cert `*.cloud.com` (SAN covers name: True) |
| `citrixworkspacesapi.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `citrixnetworkapi.net` | apex has no address (normal for a suffix entry); documented probe `trust.citrixnetworkapi.net` queued for round 2 |
| `nssvc.net` | apex has no address (normal for a suffix entry); documented probe `global-s.g.nssvc.net` queued for round 2 |
| `xendesktop.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `netscalergateway.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `discovery.cem.cloud.us` | **L** resolves; TLSv1.3, ALPN `None`, cert `*.cem.cloud.us` (SAN covers name: True); CNAME into shared front end `d2h5okjz9875in.cloudfront.net`: name usable, IPs never |
| `prod-us-vus-storage-endpoint.azureedge.net` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.azureedge.net` (SAN covers name: True); CNAME into shared front end `mr-afd-azuredge.tm-azurefd.net`: name usable, IPs never |
| `prod-eu-vus-storage-endpoint.azureedge.net` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.azureedge.net` (SAN covers name: True); CNAME into shared front end `mr-afd-azuredge.tm-azurefd.net`: name usable, IPs never |
| `prod-aps-vus-storage-endpoint.azureedge.net` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.azureedge.net` (SAN covers name: True); CNAME into shared front end `hel01r9b.msedge.net`: name usable, IPs never |
| `prod-jp-vus-storage-endpoint.azureedge.net` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.azureedge.net` (SAN covers name: True); CNAME into shared front end `hel01r9b.msedge.net`: name usable, IPs never |

## 10. Observed web-client hosts (dependency mapping)

- `https://citrix.cloud.com/`, loaded 2026-11-19 without signing in: HTTP None (page.goto: net::ERR_TUNNEL_CONNECTION_FAILED at https://citrix.cloud.com/), final host `chromewebdata`.

Pass 1 is a lower bound. The proxy refuses hosts not on the allowlist ("failed" below), so hosts that only scripts from a refused host would contact are missing.

| Host | Requests (refused) | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `accounts.cloud.com` | 1 (1) | app-owned | `citrix-cloud` | cdn |  |
| `citrix.cloud.com` | 2 (0) | app-owned | `citrix-cloud` | cdn |  |

## 11. Attributes (App-ID model) and re-verify date

- `citrix-cloud`: networking / remote-access, client-server; characteristics `tunnels-other-applications`; **risk 3**: carries other traffic or remote control.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
