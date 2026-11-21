# Zendesk

- Content-pack id today: `zendesk` (`zendesk.com`, `zdassets.com`)
- Status: **DONE** (no change), NAME
- Sources: accessed 2026-11-19; article updated 2026-11-17

## 1. What it is

Customer service platform.

## 2. Transport and ports

Not stated as ports. "Zendesk supports FQDN-based allowlists on a very limited basis" [S1].

## 3. Observable evidence

"assets.zendesk.com and static.zdassets.com must be reachable because Zendesk's web apps and related features load core static resources from those domains" [S1]. Customer instances are `{your-subdomain}.zendesk.com`. Some features use AWS S3 names (`uploaded-assets-*.s3.*.amazonaws.com`, `*-data-importer*.s3.*.amazonaws.com`).

## 4. Encrypted-traffic caveats

Subdomains of `zendesk.com` carry the customer's name; the catalog names the application only. The S3 names are wildcard patterns on shared S3, not vendor-named hosts, and are not proposed.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `zendesk.com`, `zdassets.com` | **N3** | Already mapped |

## 6. Synthetic test vectors

None (no catalog change).


<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K and M as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `static.zdassets.com` | one of `zendesk` | `zendesk` | PASS |
| O+ | `web-assets.zendesk.com` | one of `zendesk` | `zendesk` | PASS |
| O+ | `www.zendesk.com` | one of `zendesk` | `zendesk` | PASS |
| O+ | `www.zndsk.com` | one of `zendesk` | no application | GAP (unmapped) |
| D- | `15086586.fls.doubleclick.net` | not zendesk (third party) | `google-ads` | PASS |
| D- | `819-rrq-060.mktoresp.com` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `a.dpmsrv.com` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `a.usbrowserspeed.com` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `ad.doubleclick.net` | not zendesk (third party) | `google-ads` | PASS |
| D- | `adservice.google.com` | not zendesk (shared vendor infra) | `google-base` | PASS |
| D- | `alb.reddit.com` | not zendesk (shared vendor infra) | `reddit-base` | PASS |
| D- | `analytics.google.com` | not zendesk (shared vendor infra) | `google-base` | PASS |
| D- | `api.cr-relay.com` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `api.segment.io` | not zendesk (third party) | `segment` | PASS |
| D- | `api.vector.co` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `app.clearbit.com` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `b.6sc.co` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `bat.bing.com` | not zendesk (shared vendor infra) | `ms-base` | PASS |
| D- | `c.6sc.co` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `c.contentsquare.net` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `cdn.cookielaw.org` | not zendesk (third party) | no application | PASS |
| D- | `cdn.cr-relay.com` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `cdn.segment.com` | not zendesk (third party) | `segment` | PASS |
| D- | `cdn.vector.co` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `cm.g.doubleclick.net` | not zendesk (third party) | `google-ads` | PASS |
| D- | `collector-43043.us.tvsquared.com` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `d2v83son8kay5v.cloudfront.net` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `dsum-sec.casalemedia.com` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `epsilon.6sense.com` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `geolocation.onetrust.com` | not zendesk (third party) | no application | PASS |
| D- | `googleads.g.doubleclick.net` | not zendesk (third party) | `google-ads` | PASS |
| D- | `ib.adnxs.com` | not zendesk (third party) | `xandr` | PASS |
| D- | `insight.adsrvr.org` | not zendesk (third party) | `the-trade-desk` | PASS |
| D- | `ipv6.6sc.co` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `j.6sc.co` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `k-aeu1.contentsquare.net` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `match.adsrvr.org` | not zendesk (third party) | `the-trade-desk` | PASS |
| D- | `metadata-static-files.sfo2.cdn.digitaloceanspaces.com` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `munchkin.marketo.net` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `o1025743.ingest.sentry.io` | not zendesk (third party) | `sentry` | PASS |
| D- | `pixel.mathtag.com` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `pixel.rubiconproject.com` | not zendesk (third party) | `magnite` | PASS |
| D- | `px.ads.linkedin.com` | not zendesk (shared vendor infra) | `linkedin-base` | PASS |
| D- | `px4.ads.linkedin.com` | not zendesk (shared vendor infra) | `linkedin-base` | PASS |
| D- | `rtr.innovid.com` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `s-static.innovid.com` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `s.dpmsrv.com` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `secure.adnxs.com` | not zendesk (third party) | `xandr` | PASS |
| D- | `simage2.pubmatic.com` | not zendesk (third party) | `pubmatic` | PASS |
| D- | `snap.licdn.com` | not zendesk (shared vendor infra) | `linkedin-base` | PASS |
| D- | `stats.g.doubleclick.net` | not zendesk (third party) | `google-ads` | PASS |
| D- | `t.contentsquare.net` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `tag.clearbitscripts.com` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `unpkg.com` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `www.google.co.il` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `www.google.com` | not zendesk (shared vendor infra) | `google-base` | PASS |
| D- | `www.googleadservices.com` | not zendesk (third party) | `google-ads` | PASS |
| D- | `www.googletagmanager.com` | not zendesk (third party) | `google-analytics` | PASS |
| D- | `www.linkedin.com` | not zendesk (third party) | `linkedin` | PASS |
| D- | `www.redditstatic.com` | not zendesk (shared vendor infra) | `reddit-base` | PASS |
| D- | `x.bidswitch.net` | not zendesk (third party (unclassified)) | no application | PASS |
| D- | `x.clearbitjs.com` | not zendesk (third party (unclassified)) | no application | PASS |
| L- | `xzendesk.com` | not zendesk (label boundary) | no application | PASS |
| L- | `zendesk.com.example.invalid` | not zendesk (suffix look-alike) | no application | PASS |
| L- | `xzdassets.com` | not zendesk (label boundary) | no application | PASS |
| L- | `zdassets.com.example.invalid` | not zendesk (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Zendesk help, "Configuring your firewall for use with Zendesk", `https://support.zendesk.com/hc/en-us/articles/4408842860186-Configuring-your-firewall-for-use-with-Zendesk` (read through the Help Center articles API), accessed 2026-11-19.

## 8. Catalog delta and recommendation

None: the current entry matches the source.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 and 4 of 2026-11-21 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `research/live-results-2026-11-21-r4.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `zendesk.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `zendesk.com`, no subject organisation (domain-validated) (issuer Let's Encrypt) |
| `zdassets.com` | apex has no address (normal for a suffix entry); suffix **verified** through documented `static.zdassets.com` (round 2) |

## 10. Observed web-client hosts (dependency mapping)

- `https://www.zendesk.com/login/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP None (page.goto: Timeout 45000ms exceeded.), final host `www.zendesk.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `15086586.fls.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `819-rrq-060.mktoresp.com` | seen | third party (unclassified) | no application | not checked |  |
| `a.dpmsrv.com` | seen | third party (unclassified) | no application | not checked |  |
| `a.usbrowserspeed.com` | seen | third party (unclassified) | no application | not checked |  |
| `ad.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `adservice.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `alb.reddit.com` | seen | shared vendor infra | `reddit-base` | not checked |  |
| `analytics.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `api.cr-relay.com` | seen | third party (unclassified) | no application | not checked |  |
| `api.segment.io` | seen | third party | `segment` | not checked |  |
| `api.vector.co` | seen | third party (unclassified) | no application | not checked |  |
| `app.clearbit.com` | seen | third party (unclassified) | no application | not checked |  |
| `b.6sc.co` | seen | third party (unclassified) | no application | not checked |  |
| `bat.bing.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `c.6sc.co` | seen | third party (unclassified) | no application | not checked |  |
| `c.contentsquare.net` | seen | third party (unclassified) | no application | not checked |  |
| `cdn.cookielaw.org` | seen | third party | no application | not checked | OneTrust consent banner |
| `cdn.cr-relay.com` | seen | third party (unclassified) | no application | not checked |  |
| `cdn.segment.com` | seen | third party | `segment` | not checked |  |
| `cdn.vector.co` | seen | third party (unclassified) | no application | not checked |  |
| `cm.g.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `collector-43043.us.tvsquared.com` | seen | third party (unclassified) | no application | not checked |  |
| `d2v83son8kay5v.cloudfront.net` | seen | third party (unclassified) | no application | not checked |  |
| `dsum-sec.casalemedia.com` | seen | third party (unclassified) | no application | not checked |  |
| `epsilon.6sense.com` | seen | third party (unclassified) | no application | not checked |  |
| `geolocation.onetrust.com` | seen | third party | no application | not checked | OneTrust consent geolocation |
| `googleads.g.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `ib.adnxs.com` | seen | third party | `xandr` | not checked |  |
| `insight.adsrvr.org` | seen | third party | `the-trade-desk` | not checked |  |
| `ipv6.6sc.co` | seen | third party (unclassified) | no application | not checked |  |
| `j.6sc.co` | seen | third party (unclassified) | no application | not checked |  |
| `k-aeu1.contentsquare.net` | seen | third party (unclassified) | no application | not checked |  |
| `match.adsrvr.org` | seen | third party | `the-trade-desk` | not checked |  |
| `metadata-static-files.sfo2.cdn.digitaloceanspaces.com` | seen (some failed) | third party (unclassified) | no application | not checked |  |
| `munchkin.marketo.net` | seen | third party (unclassified) | no application | not checked |  |
| `o1025743.ingest.sentry.io` | seen | third party | `sentry` | not checked |  |
| `pixel.mathtag.com` | seen | third party (unclassified) | no application | not checked |  |
| `pixel.rubiconproject.com` | seen | third party | `magnite` | not checked |  |
| `px.ads.linkedin.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `px4.ads.linkedin.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `rtr.innovid.com` | seen | third party (unclassified) | no application | not checked |  |
| `s-static.innovid.com` | seen | third party (unclassified) | no application | not checked |  |
| `s.dpmsrv.com` | seen | third party (unclassified) | no application | not checked |  |
| `secure.adnxs.com` | seen | third party | `xandr` | not checked |  |
| `simage2.pubmatic.com` | seen | third party | `pubmatic` | not checked |  |
| `snap.licdn.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `static.zdassets.com` | seen | app-owned | `zendesk` | not checked |  |
| `stats.g.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `t.contentsquare.net` | seen | third party (unclassified) | no application | not checked |  |
| `tag.clearbitscripts.com` | seen | third party (unclassified) | no application | not checked |  |
| `unpkg.com` | seen | third party (unclassified) | no application | not checked |  |
| `web-assets.zendesk.com` | seen | app-owned | `zendesk` | not checked |  |
| `www.google.co.il` | seen | third party (unclassified) | no application | not checked |  |
| `www.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `www.googleadservices.com` | seen | third party | `google-ads` | not checked |  |
| `www.googletagmanager.com` | seen | third party | `google-analytics` | not checked |  |
| `www.linkedin.com` | seen | third party | `linkedin` | not checked |  |
| `www.redditstatic.com` | seen | shared vendor infra | `reddit-base` | not checked |  |
| `www.zendesk.com` | seen | app-owned | `zendesk` | not checked |  |
| `www.zndsk.com` | seen | app-owned (unmapped) | no application | not checked | Zendesk short domain; NOT mapped: round 3 certificate is domain-validated (no organisation, issuer Google Trust Services) |
| `x.bidswitch.net` | seen | third party (unclassified) | no application | not checked |  |
| `x.clearbitjs.com` | seen | third party (unclassified) | no application | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `zendesk`: business-systems / general-business, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `819-rrq-060.mktoresp.com`, `a.dpmsrv.com`, `a.usbrowserspeed.com`, `api.cr-relay.com`, `api.vector.co`, `app.clearbit.com`, `b.6sc.co`, `c.6sc.co`, `c.contentsquare.net`, `cdn.cookielaw.org`, `cdn.cr-relay.com`, `cdn.vector.co`, `collector-43043.us.tvsquared.com`, `d2v83son8kay5v.cloudfront.net`, `dsum-sec.casalemedia.com`, `epsilon.6sense.com`, `geolocation.onetrust.com`, `google-ads`, `google-analytics`, `google-base`, `ipv6.6sc.co`, `j.6sc.co`, `k-aeu1.contentsquare.net`, `linkedin`, `linkedin-base`, `magnite`, `metadata-static-files.sfo2.cdn.digitaloceanspaces.com`, `ms-base`, `munchkin.marketo.net`, `pixel.mathtag.com`, `pubmatic`, `reddit-base`, `rtr.innovid.com`, `s-static.innovid.com`, `s.dpmsrv.com`, `segment`, `sentry`, `t.contentsquare.net`, `tag.clearbitscripts.com`, `the-trade-desk`, `unpkg.com`, `www.google.co.il`, `x.bidswitch.net`, `x.clearbitjs.com`, `xandr`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
