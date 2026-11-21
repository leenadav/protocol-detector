# Docker Hub and Docker Desktop

- Content-pack id today: `docker-hub` (`docker.com`, `docker.io`)
- Status: **READY**, NAME, batch D
- Sources accessed: 2026-11-19

## 1. What it is

Container registry and the Docker Desktop client.

## 2. Transport and ports

HTTPS [S1].

## 3. Observable evidence

Allowlist table [S1]: `auth.docker.io`, `login.docker.com`, `auth.docker.com`, `desktop.docker.com`, `hub.docker.com`, `registry-1.docker.io`, `production.cloudfront.docker.com`, `api.dso.docker.com`, `api.docker.com`, `api.offload.docker.com`, `api.sandboxes-cloud.docker.com`, `dhi.io` ("Docker Hardened Images"), `registry.scout.docker.com`, `ai-backend-service.docker.com`; third parties (Bugsnag, Auth0, an S3 bucket for troubleshooting).

## 4. Encrypted-traffic caveats

Image layers can be served from CDN hosts; `production.cloudfront.docker.com` is under `docker.com` and is already covered.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `docker.com`, `docker.io`, `dhi.io` | **N3** |  |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `dhi.io` | `docker-hub` (today unmapped) |
| P2 | SNI `registry-1.docker.io` | `docker-hub` |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J and K as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `desktop.docker.com` | one of `docker-hub` | `docker-hub` | PASS |
| O+ | `dockerstatic.com` | one of `docker-hub` | no application | GAP (unmapped) |
| O+ | `hub.docker.com` | one of `docker-hub` | `docker-hub` | PASS |
| O+ | `marlin-2.docker.com` | one of `docker-hub` | `docker-hub` | PASS |
| O+ | `sessions-bugsnag.docker.com` | one of `docker-hub` | `docker-hub` | PASS |
| D- | `790-ssb-375.mktoresp.com` | not docker-hub (third party (unclassified)) | no application | PASS |
| D- | `ad.doubleclick.net` | not docker-hub (third party) | `google-ads` | PASS |
| D- | `analytics.google.com` | not docker-hub (shared vendor infra) | `google-base` | PASS |
| D- | `api.segment.io` | not docker-hub (third party) | `segment` | PASS |
| D- | `b.6sc.co` | not docker-hub (third party (unclassified)) | no application | PASS |
| D- | `c.6sc.co` | not docker-hub (third party (unclassified)) | no application | PASS |
| D- | `cdn.cookielaw.org` | not docker-hub (third party) | no application | PASS |
| D- | `cdn.segment.com` | not docker-hub (third party) | `segment` | PASS |
| D- | `cdn.wootric.com` | not docker-hub (third party (unclassified)) | no application | PASS |
| D- | `djeqr6to3dedg.cloudfront.net` | not docker-hub (third party (unclassified)) | no application | PASS |
| D- | `epsilon.6sense.com` | not docker-hub (third party (unclassified)) | no application | PASS |
| D- | `fonts.googleapis.com` | not docker-hub (shared vendor infra) | `google-base` | PASS |
| D- | `fonts.gstatic.com` | not docker-hub (shared vendor infra) | `google-base` | PASS |
| D- | `geolocation.onetrust.com` | not docker-hub (third party) | no application | PASS |
| D- | `googleads.g.doubleclick.net` | not docker-hub (third party) | `google-ads` | PASS |
| D- | `ipv6.6sc.co` | not docker-hub (third party (unclassified)) | no application | PASS |
| D- | `j.6sc.co` | not docker-hub (third party (unclassified)) | no application | PASS |
| D- | `js.zi-scripts.com` | not docker-hub (third party (unclassified)) | no application | PASS |
| D- | `munchkin.marketo.net` | not docker-hub (third party (unclassified)) | no application | PASS |
| D- | `prod-publishers-content.s3.us-east-1.amazonaws.com` | not docker-hub (third party (unclassified)) | no application | PASS |
| D- | `siteintercept.qualtrics.com` | not docker-hub (third party (unclassified)) | no application | PASS |
| D- | `stats.g.doubleclick.net` | not docker-hub (third party) | `google-ads` | PASS |
| D- | `ws.zoominfo.com` | not docker-hub (third party (unclassified)) | no application | PASS |
| D- | `www.google-analytics.com` | not docker-hub (third party) | `google-analytics` | PASS |
| D- | `www.google.co.il` | not docker-hub (third party (unclassified)) | no application | PASS |
| D- | `www.google.com` | not docker-hub (shared vendor infra) | `google-base` | PASS |
| D- | `www.googletagmanager.com` | not docker-hub (third party) | `google-analytics` | PASS |
| D- | `www.gravatar.com` | not docker-hub (third party (unclassified)) | no application | PASS |
| D- | `zn2trismmfljkalnq-docker.siteintercept.qualtrics.com` | not docker-hub (third party (unclassified)) | no application | PASS |
| L- | `xdocker.com` | not docker-hub (label boundary) | no application | PASS |
| L- | `docker.com.example.invalid` | not docker-hub (suffix look-alike) | no application | PASS |
| L- | `xdocker.io` | not docker-hub (label boundary) | no application | PASS |
| L- | `docker.io.example.invalid` | not docker-hub (suffix look-alike) | no application | PASS |
| L- | `xdhi.io` | not docker-hub (label boundary) | no application | PASS |
| L- | `dhi.io.example.invalid` | not docker-hub (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Docker Docs, "Allowlist for Docker Desktop", `https://docs.docker.com/desktop/enterprise/allow-list.md` (the `/desktop/setup/allow-list/` page redirects there), accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("docker-hub", ..., ("docker.com", "docker.io", "dhi.io")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `docker.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `docker.com`, no subject organisation (domain-validated) (issuer Let's Encrypt) |
| `docker.io` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.docker.com`, no subject organisation (domain-validated) (issuer Amazon) |
| `dhi.io` | **L** resolves; TLSv1.3, ALPN `h2`, cert `dhi.io`, no subject organisation (domain-validated) (issuer Google Trust Services) |

## 10. Observed web-client hosts (dependency mapping)

- `https://hub.docker.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `hub.docker.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `790-ssb-375.mktoresp.com` | seen | third party (unclassified) | no application | not checked |  |
| `ad.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `analytics.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `api.segment.io` | seen | third party | `segment` | not checked |  |
| `b.6sc.co` | seen | third party (unclassified) | no application | not checked |  |
| `c.6sc.co` | seen | third party (unclassified) | no application | not checked |  |
| `cdn.cookielaw.org` | seen | third party | no application | not checked | OneTrust consent banner |
| `cdn.segment.com` | seen | third party | `segment` | not checked |  |
| `cdn.wootric.com` | seen | third party (unclassified) | no application | not checked |  |
| `desktop.docker.com` | seen | app-owned | `docker-hub` | not checked |  |
| `djeqr6to3dedg.cloudfront.net` | seen | third party (unclassified) | no application | not checked |  |
| `dockerstatic.com` | seen | app-owned (unmapped) | no application | not checked | Docker static assets (dockerstatic.com); ownership to be shown by certificate in live round 2 |
| `epsilon.6sense.com` | seen | third party (unclassified) | no application | not checked |  |
| `fonts.googleapis.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `fonts.gstatic.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `geolocation.onetrust.com` | seen | third party | no application | not checked | OneTrust consent geolocation |
| `googleads.g.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `hub.docker.com` | seen | app-owned | `docker-hub` | not checked |  |
| `ipv6.6sc.co` | seen | third party (unclassified) | no application | not checked |  |
| `j.6sc.co` | seen | third party (unclassified) | no application | not checked |  |
| `js.zi-scripts.com` | seen | third party (unclassified) | no application | not checked |  |
| `marlin-2.docker.com` | seen | app-owned | `docker-hub` | not checked |  |
| `munchkin.marketo.net` | seen | third party (unclassified) | no application | not checked |  |
| `prod-publishers-content.s3.us-east-1.amazonaws.com` | seen | third party (unclassified) | no application | not checked |  |
| `sessions-bugsnag.docker.com` | seen | app-owned | `docker-hub` | not checked |  |
| `siteintercept.qualtrics.com` | seen | third party (unclassified) | no application | not checked |  |
| `stats.g.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `ws.zoominfo.com` | seen | third party (unclassified) | no application | not checked |  |
| `www.google-analytics.com` | seen | third party | `google-analytics` | not checked |  |
| `www.google.co.il` | seen | third party (unclassified) | no application | not checked |  |
| `www.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `www.googletagmanager.com` | seen | third party | `google-analytics` | not checked |  |
| `www.gravatar.com` | seen | third party (unclassified) | no application | not checked |  |
| `zn2trismmfljkalnq-docker.siteintercept.qualtrics.com` | seen | third party (unclassified) | no application | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `docker-hub`: business-systems / software-development, client-server; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `790-ssb-375.mktoresp.com`, `b.6sc.co`, `c.6sc.co`, `cdn.cookielaw.org`, `cdn.wootric.com`, `djeqr6to3dedg.cloudfront.net`, `epsilon.6sense.com`, `geolocation.onetrust.com`, `google-ads`, `google-analytics`, `google-base`, `ipv6.6sc.co`, `j.6sc.co`, `js.zi-scripts.com`, `munchkin.marketo.net`, `prod-publishers-content.s3.us-east-1.amazonaws.com`, `segment`, `siteintercept.qualtrics.com`, `ws.zoominfo.com`, `www.google.co.il`, `www.gravatar.com`, `zn2trismmfljkalnq-docker.siteintercept.qualtrics.com`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
