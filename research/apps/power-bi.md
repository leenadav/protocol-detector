# Microsoft Power BI and Fabric

- Content-pack id today: `power-bi` (`powerbi.com`)
- Status: **READY**, NAME, batch M (`research/patches/batch-m-name-based.patch`): back-end API, dedicated-capacity, Fabric SQL and Power Query Online names added
- Sources: [B] read in the research cloud (egress proxy), 2026-11-21; ms.date 2026-02-13

## 1. What it is

Microsoft's business-intelligence service (Power BI), now part of Microsoft Fabric.

## 2. Transport and ports

TCP 443 for the portal, back-end APIs, CDN and Power Query Online; TCP 1433 (TDS) for Datamart, Fabric Data Warehouse and Fabric SQL database, plus 11000 to 11999 for SQL database in Fabric under the redirect connection policy [B].

## 3. Observable evidence

[B]: portal `*.powerbi.com`; back-end APIs `api.powerbi.com`, `*.analysis.windows.net`, `*.pbidedicated.windows.net`; CDN `content.powerapps.com`; SQL `*.datamart.fabric.microsoft.com` or `*.datamart.pbidedicated.windows.net`, `*.datawarehouse.fabric.microsoft.com` or `*.datawarehouse.pbidedicated.windows.net`, `*.database.fabric.microsoft.com`; Power Query Online `*.powerquery.microsoft.com`; gateway management `gatewayadminportal.azure.com`; shared: `*.blob.core.windows.net`, `dc.services.visualstudio.com` (telemetry), `arc.msn.com`, `nps.onyx.azure.net`, Microsoft 365 sign-in; visuals `*.osi.office.net`, `*.msecnd.net`, `store.office.com`; landing and support `powerbi.microsoft.com`, `ideas.powerbi.com`, `support.powerbi.com`.

## 4. Encrypted-traffic caveats

Only the three `fabric.microsoft.com` SQL subtrees are proposed, not `fabric.microsoft.com` itself (the Fabric portal `app.fabric.microsoft.com` stays `ms-base`: the page does not list it). `content.powerapps.com` is the Power Platform CDN and goes to `ms-power-platform`. `powerquery.microsoft.com` is also used by Power Platform dataflows (**N2**). The TDS sessions on 1433 carry the server name in the TDS PRELOGIN/LOGIN7 exchange or TLS inside TDS; the engine attributes by TLS SNI only, so they match only where SNI is visible (`UNVERIFIED` for TDS 8.0 strict mode). Blob storage, telemetry and sign-in are shared.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `powerbi.com` | **N3** | Already mapped |
| SNI under `analysis.windows.net`, `pbidedicated.windows.net` | **N3** | Back-end APIs, capacities |
| SNI under the three Fabric SQL subtrees | **N3** | Port 1433 |
| SNI under `powerquery.microsoft.com` | **N2** | Shared with dataflows |
| Blob, telemetry, sign-in | not mapped | Shared |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K and M): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `app.powerbi.com` | `power-bi` |
| P2 | SNI `wabi-west-europe.analysis.windows.net`, `x.pbidedicated.windows.net`, `x.datawarehouse.fabric.microsoft.com` | `power-bi` (today unmapped) |
| N1 | SNI `app.fabric.microsoft.com`, `dc.services.visualstudio.com`, `x.windows.net` | not `power-bi` |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O and P as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xpowerbi.com` | not power-bi (label boundary) | no application | PASS |
| L- | `powerbi.com.example.invalid` | not power-bi (suffix look-alike) | no application | PASS |
| L- | `xwindows.net` | not power-bi (label boundary) | no application | PASS |
| L- | `analysis.windows.net.example.invalid` | not power-bi (suffix look-alike) | no application | PASS |
| L- | `pbidedicated.windows.net.example.invalid` | not power-bi (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [B] Microsoft Learn, "Add Power BI URLs to allowlist", `https://learn.microsoft.com/en-us/fabric/security/power-bi-allow-list-urls`, read in the research cloud (egress proxy), 2026-11-21.

## 8. Catalog delta and recommendation

```python
("power-bi", ..., ("powerbi.com", "analysis.windows.net", "pbidedicated.windows.net", "datamart.fabric.microsoft.com",
 "datawarehouse.fabric.microsoft.com", "database.fabric.microsoft.com", "powerquery.microsoft.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `powerbi.com` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `powerbi.com`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation) |
| `analysis.windows.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `pbidedicated.windows.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `datamart.fabric.microsoft.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `datawarehouse.fabric.microsoft.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `database.fabric.microsoft.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `powerquery.microsoft.com` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `e.microsoft.com`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation); CNAME into shared front end `reroute443.trafficmanager.net`: name usable, IPs never |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `power-bi`: business-systems / office-programs, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
