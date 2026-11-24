# Loom

- Content-pack id today: none
- Status: **READY**, NAME, batch F: new id `loom`
- Sources accessed: 2026-11-19. Article "Updated on April 30, 2026"

## 1. What it is

Video messaging and screen recording (an Atlassian product).

## 2. Transport and ports

`wss` and HTTPS on 443 (the article also lists 80) [S1].

## 3. Observable evidence

"Domains, Protocols and Ports required for Loom" [S1]: `*.loom.com`, `www.loom.com`, `proxy.loom.com`,
`record.loom.com`, `location.loom.com`, `cdn.loom.com`, `packages.loom.com`, `luna.loom.com`,
`loom-media-production.s3-accelerate.amazonaws.com`, `object-store.atlassian.com`, plus third parties
(`icanhazip.com`, `cdn.segment.com`, `*.intercom.io`, `*.s3.us-west-2.amazonaws.com`, `*.logs.datadoghq.com`).

## 4. Encrypted-traffic caveats

Recordings upload to S3. Only the named bucket host is proposed, never the generic regional S3 wildcard.
`object-store.atlassian.com` already resolves to `atlassian`.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `loom.com` | **N3** | |
| SNI `loom-media-production.s3-accelerate.amazonaws.com` | **N3** (exact) | Media uploads |
| `object-store.atlassian.com` | `atlassian` | Shared Atlassian storage |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `www.loom.com`, `record.loom.com` | `loom` |
| P2 | SNI `loom-media-production.s3-accelerate.amazonaws.com` | `loom` |
| N1 | SNI `object-store.atlassian.com` | `atlassian` |

Checked in scratch (`c08773f` plus D, E and F).

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O, P and Q as rebuilt 2026-11-24)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `bad-builds.loom.com` | one of `loom` | `loom` | PASS |
| O+ | `cdn.loom.com` | one of `loom` | `loom` | PASS |
| O+ | `www.loom.com` | one of `loom` | `loom` | PASS |
| D- | `accounts.google.com` | not loom (shared vendor infra) | `google-accounts` | PASS |
| D- | `api-private.atlassian.com` | not loom (third party) | `atlassian` | PASS |
| D- | `api.atlassian.com` | not loom (third party) | `atlassian` | PASS |
| D- | `as.atlassian.com` | not loom (third party) | `atlassian` | PASS |
| D- | `atl-global.atlassian.com` | not loom (third party) | `atlassian` | PASS |
| D- | `atl-onetrust-wrapper.atlassian.com` | not loom (third party) | `atlassian` | PASS |
| D- | `browser-intake-datadoghq.com` | not loom (shared vendor infra) | `datadog-base` | PASS |
| D- | `cdn.cookielaw.org` | not loom (third party) | no application | PASS |
| D- | `ds-cdn.prod-east.frontend.public.atl-paas.net` | not loom (third party) | `atlassian` | PASS |
| D- | `geolocation.onetrust.com` | not loom (third party) | no application | PASS |
| D- | `liecbddmkiiihnedobmlmillhodjkdmb` | not loom (third party (unclassified)) | no application | PASS |
| D- | `o398470.ingest.sentry.io` | not loom (third party) | `sentry` | PASS |
| D- | `www.atlassian.com` | not loom (third party) | `atlassian` | PASS |
| D- | `xp.atlassian.com` | not loom (third party) | `atlassian` | PASS |
| L- | `xloom.com` | not loom (label boundary) | no application | PASS |
| L- | `loom.com.example.invalid` | not loom (suffix look-alike) | no application | PASS |
| L- | `xamazonaws.com` | not loom (label boundary) | no application | PASS |
| L- | `loom-media-production.s3-accelerate.amazonaws.com.example.invalid` | not loom (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Atlassian Support (Loom), "Domains, Protocols and Ports required for Loom to work on your servers",
  `https://support.atlassian.com/loom/kb/domains-protocols-and-ports-required-for-loom-to-work-on-your-servers/`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

```python
("loom", "collaboration", "voip-video", "browser-based", 2, "Loom video messaging",
 ("transfers-files",), ("loom.com", "loom-media-production.s3-accelerate.amazonaws.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `loom.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `loom.com`, no subject organisation (domain-validated) (issuer Amazon); HTTPS record offers `h3` (QUIC path) |
| `loom-media-production.s3-accelerate.amazonaws.com` | **L** resolves; TLSv1.3, ALPN `None`, cert `*.s3-accelerate.amazonaws.com`, no subject organisation (domain-validated) (issuer Amazon) |

## 10. Observed web-client hosts (dependency mapping)

- `https://www.loom.com/login`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `www.loom.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `accounts.google.com` | seen | shared vendor infra | `google-accounts` |  |  |
| `api-private.atlassian.com` | seen | third party | `atlassian` | not checked |  |
| `api.atlassian.com` | seen | third party | `atlassian` | not checked |  |
| `as.atlassian.com` | seen | third party | `atlassian` | not checked |  |
| `atl-global.atlassian.com` | seen | third party | `atlassian` | not checked |  |
| `atl-onetrust-wrapper.atlassian.com` | seen | third party | `atlassian` | not checked |  |
| `bad-builds.loom.com` | seen | app-owned | `loom` | not checked |  |
| `browser-intake-datadoghq.com` | seen (some failed) | shared vendor infra | `datadog-base` | not checked |  |
| `cdn.cookielaw.org` | seen | third party | no application | not checked | OneTrust consent banner |
| `cdn.loom.com` | seen | app-owned | `loom` | not checked |  |
| `ds-cdn.prod-east.frontend.public.atl-paas.net` | seen | third party | `atlassian` | not checked |  |
| `geolocation.onetrust.com` | seen | third party | no application | not checked | OneTrust consent geolocation |
| `liecbddmkiiihnedobmlmillhodjkdmb` | seen (some failed) | third party (unclassified) | no application | not checked |  |
| `o398470.ingest.sentry.io` | seen | third party | `sentry` | not checked |  |
| `www.atlassian.com` | seen | third party | `atlassian` | not checked |  |
| `www.loom.com` | seen | app-owned | `loom` | not checked |  |
| `xp.atlassian.com` | seen | third party | `atlassian` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `loom`: collaboration / voip-video, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `atlassian`, `cdn.cookielaw.org`, `datadog-base`, `geolocation.onetrust.com`, `google-accounts`, `liecbddmkiiihnedobmlmillhodjkdmb`, `sentry`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `loom.com`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
