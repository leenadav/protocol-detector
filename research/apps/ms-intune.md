# Microsoft Intune

- Content-pack id today: none (`manage.microsoft.com` falls to `ms-base`)
- Status: **READY**, NAME, batch D: new id `ms-intune`
- Sources accessed: 2026-11-19

## 1. What it is

Microsoft's device-management (MDM/MAM) service.

## 2. Transport and ports

TCP 80 and 443 [S1].

## 3. Observable evidence

"If the firewall that you're using allows you to create firewall rules using a domain name, then use the *.manage.microsoft.com and manage.microsoft.com domain"; the required core row lists `*.manage.microsoft.com`, `manage.microsoft.com`, `*.dm.microsoft.com`, `EnterpriseEnrollment.manage.microsoft.com` [S1]. Delivery Optimization (`*.do.dsp.mp.microsoft.com`), `graph.microsoft.com`, notification and Office hosts are shared with other Microsoft services.

## 4. Encrypted-traffic caveats

"SSL traffic inspection isn't supported for '*.manage.microsoft.com', '*.dm.microsoft.com'" [S1]. Not relevant in the visibility phase, but important for later.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `manage.microsoft.com`, `dm.microsoft.com` | **N3** Intune |  |
| Delivery Optimization, Graph | do not map | Shared |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `enterpriseenrollment.manage.microsoft.com`, `x.dm.microsoft.com` | `ms-intune` |
| N1 | SNI `www.microsoft.com` | `ms-base` |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J and K as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| D- | `aadcdn.msftauth.net` | not ms-intune (shared vendor infra (unmapped)) | no application | PASS |
| D- | `browser.events.data.microsoft.com` | not ms-intune (shared vendor infra) | `ms-telemetry` | PASS |
| D- | `eu-mobile.events.data.microsoft.com` | not ms-intune (shared vendor infra) | `ms-telemetry` | PASS |
| D- | `intune.microsoft.com` | not ms-intune (shared vendor infra) | `ms-base` | PASS |
| D- | `login.live.com` | not ms-intune (shared vendor infra) | `azure-ad` | PASS |
| D- | `login.microsoftonline.com` | not ms-intune (shared vendor infra) | `azure-ad` | PASS |
| D- | `portal.azure.com` | not ms-intune (shared vendor infra (unmapped)) | no application | PASS |
| L- | `xmicrosoft.com` | not ms-intune (label boundary) | no application | PASS |
| L- | `manage.microsoft.com.example.invalid` | not ms-intune (suffix look-alike) | no application | PASS |
| L- | `dm.microsoft.com.example.invalid` | not ms-intune (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Microsoft Learn, "Network endpoints for Microsoft Intune", `https://learn.microsoft.com/en-us/intune/fundamentals/endpoints`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("ms-intune", "business-systems", "management", "client-server", 1, "Microsoft Intune device management",
 ("widely-used",), ("manage.microsoft.com", "dm.microsoft.com")),
```

Metadata is this lane's proposal.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `manage.microsoft.com` | **L** resolves; TLSv1.2, ALPN `None`, cert `EU01.manage.microsoft.com`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation); CNAME into shared front end `pexsucpeu01.northeurope.cloudapp.azure.com`: name usable, IPs never |
| `dm.microsoft.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |

## 10. Observed web-client hosts (dependency mapping)

- `https://intune.microsoft.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `login.microsoftonline.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `aadcdn.msftauth.net` | seen | shared vendor infra (unmapped) | no application | not checked | Microsoft Entra sign-in CDN |
| `browser.events.data.microsoft.com` | seen (some failed) | shared vendor infra | `ms-telemetry` | not checked |  |
| `eu-mobile.events.data.microsoft.com` | seen | shared vendor infra | `ms-telemetry` | not checked |  |
| `intune.microsoft.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `login.live.com` | seen | shared vendor infra | `azure-ad` | not checked |  |
| `login.microsoftonline.com` | seen | shared vendor infra | `azure-ad` | not checked |  |
| `portal.azure.com` | seen (some failed) | shared vendor infra (unmapped) | no application | not checked | Azure portal (Microsoft) |

## 11. Attributes (App-ID model) and re-verify date

- `ms-intune`: business-systems / management, client-server; characteristics `widely-used`; **risk 1**: widely used by enterprises.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `azure-ad`, `ms-base`, `ms-telemetry`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
