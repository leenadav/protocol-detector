# Microsoft Defender for Endpoint

- Content-pack id today: none (no catalog entry; `*.microsoft.com` falls to `ms-base`)
- Status: **READY**, NAME, batch D (`research/patches/batch-d-name-based.patch`): new id `ms-defender-endpoint`
- Sources accessed: 2026-11-19

## 1. What it is

Microsoft's endpoint detection and response sensor. Its presence on a device is a security-posture fact operators want, and its traffic should not be mistaken for generic Microsoft traffic.

## 2. Transport and ports

TCP 443 for the core services; certificate validation over TCP 80 [S1].

## 3. Observable evidence

"Core Defender for Endpoint services" on 443: `*.endpoint.security.microsoft.com`; "It is important to ensure connectivity to *.endpoint.security.microsoft.com is and remains possible" (streamlined connectivity). `reflector.defender.microsoft.com` is "Used by Microsoft Defender to probe IPv6 connectivity" [S1]. SmartScreen (`*.smartscreen.microsoft.com` and others), Windows Update, CRL and blob-storage hosts are listed too. They are shared with other Windows features or Azure storage, so they are not Defender evidence.

## 4. Encrypted-traffic caveats

Windows 10 versions 1607 to 1803 "require a longer list of URLs", many of them on `*.blob.core.windows.net` (shared Azure storage), so those devices are only partly visible [S1].

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `endpoint.security.microsoft.com` | **N3** sensor | Streamlined connectivity only |
| `reflector.defender.microsoft.com` | **N3** (exact) | IPv6 probe |
| SmartScreen, Windows Update, blob storage | do not map | Shared |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `x.endpoint.security.microsoft.com` | `ms-defender-endpoint` |
| P2 | SNI `reflector.defender.microsoft.com` | `ms-defender-endpoint` |
| N1 | SNI `security.microsoft.com`, `www.microsoft.com` | `ms-base` (unchanged) |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M and N as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| D- | `aadcdn.msauth.net` | not ms-defender-endpoint (shared vendor infra (unmapped)) | no application | PASS |
| D- | `eu-mobile.events.data.microsoft.com` | not ms-defender-endpoint (shared vendor infra) | `ms-telemetry` | PASS |
| D- | `login.live.com` | not ms-defender-endpoint (shared vendor infra) | `azure-ad` | PASS |
| D- | `login.microsoftonline.com` | not ms-defender-endpoint (shared vendor infra) | `azure-ad` | PASS |
| D- | `security.microsoft.com` | not ms-defender-endpoint (shared vendor infra) | `ms-base` | PASS |
| L- | `xmicrosoft.com` | not ms-defender-endpoint (label boundary) | no application | PASS |
| L- | `endpoint.security.microsoft.com.example.invalid` | not ms-defender-endpoint (suffix look-alike) | no application | PASS |
| L- | `reflector.defender.microsoft.com.example.invalid` | not ms-defender-endpoint (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Microsoft Learn, "Streamlined device connectivity URLs (commercial)", `https://learn.microsoft.com/en-us/defender-endpoint/streamlined-device-connectivity-urls-commercial`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("ms-defender-endpoint", "business-systems", "management", "client-server", 1, "Microsoft Defender for Endpoint",
 ("widely-used",), ("endpoint.security.microsoft.com", "reflector.defender.microsoft.com")),
```

Category `business-systems/management`, matching the existing `crowdstrike` and `sentinelone` entries. Metadata is this lane's proposal.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 5 of 2026-11-21 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `endpoint.security.microsoft.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `reflector.defender.microsoft.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `reflector.defender.microsoft.com`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation); CNAME into shared front end `reflector-appgwv6-prd-aec0a.uaecentral.cloudapp.azure.com`: name usable, IPs never |

## 10. Observed web-client hosts (dependency mapping)

- `https://security.microsoft.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `login.microsoftonline.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `aadcdn.msauth.net` | seen | shared vendor infra (unmapped) | no application | not checked | Microsoft Entra sign-in CDN |
| `eu-mobile.events.data.microsoft.com` | seen | shared vendor infra | `ms-telemetry` | not checked |  |
| `login.live.com` | seen | shared vendor infra | `azure-ad` | not checked |  |
| `login.microsoftonline.com` | seen | shared vendor infra | `azure-ad` | not checked |  |
| `security.microsoft.com` | seen | shared vendor infra | `ms-base` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `ms-defender-endpoint`: business-systems / management, client-server; characteristics `widely-used`; **risk 1**: widely used by enterprises.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `azure-ad`, `ms-base`, `ms-telemetry`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
