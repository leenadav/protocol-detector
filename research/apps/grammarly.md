# Grammarly

- Content-pack id today: `grammarly` (`grammarly.com`, `grammarly.io`)
- Status: **READY**, NAME, batch J (`research/patches/batch-j-relayed-rows-12-18.patch`): `grammarly.net` added
- Sources: [G1] read by Hermes, relayed, 2026-11-19; [G2] read by Research Lab from the Hermes server, relayed by Hermes, 2026-11-20 (PRO-29); article updated 2026-11-11 (Zendesk API)

## 1. What it is

Writing assistant (browser extension, desktop and web).

## 2. Transport and ports

"80 and 443 opened" and a proxy that supports WebSockets [G2].

## 3. Observable evidence

[G2]: HTTPS services `*.grammarly.com`, `*.grammarly.io`, `*.grammarly.net`, `*.coda.io`; WebSockets `capi.grammarly.com` (wss paths `/fpws`, `/freews`, `/wstest`) and `dox.grammarly.com` (wss `/documents`). [G1] ("Network configuration blocks Grammarly services") has no list and links to [G2].

## 4. Encrypted-traffic caveats

`coda.io` is Coda, a separate product of the same company that the page lists among Grammarly's HTTPS services. Mapping it to `grammarly` would report Coda use as Grammarly, so it is **not** proposed here (a separate `coda` id can be researched later). The WebSocket paths are inside TLS and not visible to a passive gateway; only the host names are.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `grammarly.com`, `grammarly.io` | **N3** | Already mapped |
| SNI under `grammarly.net` | **N3** |  |
| `coda.io` | not mapped | Separate product of the same vendor |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L and J): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `capi.grammarly.com`, `dox.grammarly.com` | `grammarly` |
| P2 | SNI `x.grammarly.net` | `grammarly` (today unmapped) |
| N1 | SNI `coda.io`, `xgrammarly.net` | not `grammarly` |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O and P as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `app.grammarly.com` | one of `grammarly` | `grammarly` | PASS |
| O+ | `auth.grammarly.com` | one of `grammarly` | `grammarly` | PASS |
| O+ | `f-log-at.grammarly.io` | one of `grammarly` | `grammarly` | PASS |
| O+ | `gnar.grammarly.com` | one of `grammarly` | `grammarly` | PASS |
| O+ | `static-web.grammarly.com` | one of `grammarly` | `grammarly` | PASS |
| O+ | `website.femetrics.grammarly.io` | one of `grammarly` | `grammarly` | PASS |
| O+ | `www.grammarly.com` | one of `grammarly` | `grammarly` | PASS |
| D- | `11910764.fls.doubleclick.net` | not grammarly (third party) | `google-ads` | PASS |
| D- | `a.quora.com` | not grammarly (shared vendor infra) | `quora-base` | PASS |
| D- | `accounts.google.com` | not grammarly (shared vendor infra) | `google-accounts` | PASS |
| D- | `ad.doubleclick.net` | not grammarly (third party) | `google-ads` | PASS |
| D- | `adresults-19-adswizz.attribution.adswizz.com` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `adservice.google.com` | not grammarly (shared vendor infra) | `google-base` | PASS |
| D- | `analytics-ipv6.tiktokw.us` | not grammarly (third party) | no application | PASS |
| D- | `analytics.google.com` | not grammarly (shared vendor infra) | `google-base` | PASS |
| D- | `analytics.tiktok.com` | not grammarly (shared vendor infra) | `tiktok-base` | PASS |
| D- | `b.6sc.co` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `bat.bing.com` | not grammarly (shared vendor infra) | `ms-base` | PASS |
| D- | `c.6sc.co` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `c.bing.com` | not grammarly (shared vendor infra) | `ms-base` | PASS |
| D- | `c.clarity.ms` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `cdn.pdst.fm` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `cdn.taboola.com` | not grammarly (third party) | `taboola` | PASS |
| D- | `cm.g.doubleclick.net` | not grammarly (third party) | `google-ads` | PASS |
| D- | `collector-21641.us.tvsquared.com` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `connect.facebook.net` | not grammarly (shared vendor infra) | `meta-base` | PASS |
| D- | `d34r8q7sht0t9k.cloudfront.net` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `data.adxcel-ec2.com` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `dsum-sec.casalemedia.com` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `google.com` | not grammarly (shared vendor infra) | `google-base` | PASS |
| D- | `googleads.g.doubleclick.net` | not grammarly (third party) | `google-ads` | PASS |
| D- | `grammarly.pxf.io` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `ib.adnxs.com` | not grammarly (third party) | `xandr` | PASS |
| D- | `insight.adsrvr.org` | not grammarly (third party) | `the-trade-desk` | PASS |
| D- | `ipv4.podscribe.com` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `ipv6.6sc.co` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `j.6sc.co` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `js.adsrvr.org` | not grammarly (third party) | `the-trade-desk` | PASS |
| D- | `js.zi-scripts.com` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `match.adsrvr.org` | not grammarly (third party) | `the-trade-desk` | PASS |
| D- | `pixel.rubiconproject.com` | not grammarly (third party) | `magnite` | PASS |
| D- | `pixel.tapad.com` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `pixels.spotify.com` | not grammarly (shared vendor infra) | `spotify-base` | PASS |
| D- | `px.ads.linkedin.com` | not grammarly (shared vendor infra) | `linkedin-base` | PASS |
| D- | `px4.ads.linkedin.com` | not grammarly (shared vendor infra) | `linkedin-base` | PASS |
| D- | `q.quora.com` | not grammarly (shared vendor infra) | `quora-base` | PASS |
| D- | `r.clarity.ms` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `scripts.clarity.ms` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `secure.adnxs.com` | not grammarly (third party) | `xandr` | PASS |
| D- | `simage2.pubmatic.com` | not grammarly (third party) | `pubmatic` | PASS |
| D- | `snap.licdn.com` | not grammarly (shared vendor infra) | `linkedin-base` | PASS |
| D- | `stats.g.doubleclick.net` | not grammarly (third party) | `google-ads` | PASS |
| D- | `tags.w55c.net` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `transcend-cdn.com` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `trc.taboola.com` | not grammarly (third party) | `taboola` | PASS |
| D- | `utt.impactcdn.com` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `verifi.podscribe.com` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `ws-assets.zoominfo.com` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `ws.zoominfo.com` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `www.clarity.ms` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `www.facebook.com` | not grammarly (third party) | `facebook` | PASS |
| D- | `www.google-analytics.com` | not grammarly (third party) | `google-analytics` | PASS |
| D- | `www.google.co.il` | not grammarly (third party (unclassified)) | no application | PASS |
| D- | `www.google.com` | not grammarly (shared vendor infra) | `google-base` | PASS |
| D- | `www.googletagmanager.com` | not grammarly (third party) | `google-analytics` | PASS |
| D- | `www.linkedin.com` | not grammarly (third party) | `linkedin` | PASS |
| D- | `x.bidswitch.net` | not grammarly (third party (unclassified)) | no application | PASS |
| L- | `xgrammarly.com` | not grammarly (label boundary) | no application | PASS |
| L- | `grammarly.com.example.invalid` | not grammarly (suffix look-alike) | no application | PASS |
| L- | `xgrammarly.io` | not grammarly (label boundary) | no application | PASS |
| L- | `grammarly.io.example.invalid` | not grammarly (suffix look-alike) | no application | PASS |
| L- | `xgrammarly.net` | not grammarly (label boundary) | no application | PASS |
| L- | `grammarly.net.example.invalid` | not grammarly (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [G1] Grammarly Support, "Network configuration blocks Grammarly services", `https://support.grammarly.com/hc/en-us/articles/115000090271-Network-configuration-blocks-Grammarly-services`, read by Hermes, relayed, 2026-11-19.
- [G2] Grammarly Support, "WebSockets Support Q&A for System Administrators", `https://support.grammarly.com/hc/en-us/articles/115000090311-WebSockets-Support-Q-A-for-System-Administrators`, read by Research Lab from the Hermes server, relayed by Hermes, 2026-11-20 (PRO-29).

## 8. Catalog delta and recommendation

```python
("grammarly", ..., ("grammarly.com", "grammarly.io", "grammarly.net")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `grammarly.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `www.grammarly.com`, no subject organisation (domain-validated) (issuer Amazon) |
| `grammarly.io` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `grammarly.net` | round 3 (2026-11-21); **L** resolves; TLSv1.2, ALPN `h2`, cert `grammarly.net`, no subject organisation (domain-validated) (issuer Amazon) |

## 10. Observed web-client hosts (dependency mapping)

- `https://app.grammarly.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `www.grammarly.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `11910764.fls.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `a.quora.com` | seen | shared vendor infra | `quora-base` | not checked |  |
| `accounts.google.com` | seen | shared vendor infra | `google-accounts` |  |  |
| `ad.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `adresults-19-adswizz.attribution.adswizz.com` | seen | third party (unclassified) | no application | not checked |  |
| `adservice.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `analytics-ipv6.tiktokw.us` | seen | third party | no application | not checked | TikTok pixel |
| `analytics.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `analytics.tiktok.com` | seen | shared vendor infra | `tiktok-base` | not checked |  |
| `app.grammarly.com` | seen | app-owned | `grammarly` |  |  |
| `auth.grammarly.com` | seen | app-owned | `grammarly` | not checked |  |
| `b.6sc.co` | seen | third party (unclassified) | no application | not checked |  |
| `bat.bing.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `c.6sc.co` | seen | third party (unclassified) | no application | not checked |  |
| `c.bing.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `c.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `cdn.pdst.fm` | seen | third party (unclassified) | no application | not checked |  |
| `cdn.taboola.com` | seen | third party | `taboola` | not checked |  |
| `cm.g.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `collector-21641.us.tvsquared.com` | seen | third party (unclassified) | no application | not checked |  |
| `connect.facebook.net` | seen | shared vendor infra | `meta-base` | not checked |  |
| `d34r8q7sht0t9k.cloudfront.net` | seen | third party (unclassified) | no application | not checked |  |
| `data.adxcel-ec2.com` | seen | third party (unclassified) | no application | not checked |  |
| `dsum-sec.casalemedia.com` | seen | third party (unclassified) | no application | not checked |  |
| `f-log-at.grammarly.io` | seen | app-owned | `grammarly` | not checked |  |
| `gnar.grammarly.com` | seen | app-owned | `grammarly` | not checked |  |
| `google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `googleads.g.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `grammarly.pxf.io` | seen | third party (unclassified) | no application | not checked |  |
| `ib.adnxs.com` | seen | third party | `xandr` | not checked |  |
| `insight.adsrvr.org` | seen | third party | `the-trade-desk` | not checked |  |
| `ipv4.podscribe.com` | seen | third party (unclassified) | no application | not checked |  |
| `ipv6.6sc.co` | seen | third party (unclassified) | no application | not checked |  |
| `j.6sc.co` | seen | third party (unclassified) | no application | not checked |  |
| `js.adsrvr.org` | seen | third party | `the-trade-desk` | not checked |  |
| `js.zi-scripts.com` | seen | third party (unclassified) | no application | not checked |  |
| `match.adsrvr.org` | seen | third party | `the-trade-desk` | not checked |  |
| `pixel.rubiconproject.com` | seen | third party | `magnite` | not checked |  |
| `pixel.tapad.com` | seen | third party (unclassified) | no application | not checked |  |
| `pixels.spotify.com` | seen | shared vendor infra | `spotify-base` | not checked |  |
| `px.ads.linkedin.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `px4.ads.linkedin.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `q.quora.com` | seen | shared vendor infra | `quora-base` | not checked |  |
| `r.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `scripts.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `secure.adnxs.com` | seen | third party | `xandr` | not checked |  |
| `simage2.pubmatic.com` | seen | third party | `pubmatic` | not checked |  |
| `snap.licdn.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `static-web.grammarly.com` | seen | app-owned | `grammarly` | not checked |  |
| `stats.g.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `tags.w55c.net` | seen | third party (unclassified) | no application | not checked |  |
| `transcend-cdn.com` | seen | third party (unclassified) | no application | not checked |  |
| `trc.taboola.com` | seen | third party | `taboola` | not checked |  |
| `utt.impactcdn.com` | seen | third party (unclassified) | no application | not checked |  |
| `verifi.podscribe.com` | seen | third party (unclassified) | no application | not checked |  |
| `website.femetrics.grammarly.io` | seen | app-owned | `grammarly` | not checked |  |
| `ws-assets.zoominfo.com` | seen | third party (unclassified) | no application | not checked |  |
| `ws.zoominfo.com` | seen | third party (unclassified) | no application | not checked |  |
| `www.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `www.facebook.com` | seen | third party | `facebook` | not checked |  |
| `www.google-analytics.com` | seen | third party | `google-analytics` | not checked |  |
| `www.google.co.il` | seen | third party (unclassified) | no application | not checked |  |
| `www.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `www.googletagmanager.com` | seen | third party | `google-analytics` | not checked |  |
| `www.grammarly.com` | seen | app-owned | `grammarly` |  |  |
| `www.linkedin.com` | seen | third party | `linkedin` | not checked |  |
| `x.bidswitch.net` | seen | third party (unclassified) | no application | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `grammarly`: business-systems / office-programs, browser-based; characteristics `pervasive`; **risk 3**: present on most managed endpoints.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `adresults-19-adswizz.attribution.adswizz.com`, `analytics-ipv6.tiktokw.us`, `b.6sc.co`, `c.6sc.co`, `c.clarity.ms`, `cdn.pdst.fm`, `collector-21641.us.tvsquared.com`, `d34r8q7sht0t9k.cloudfront.net`, `data.adxcel-ec2.com`, `dsum-sec.casalemedia.com`, `facebook`, `google-accounts`, `google-ads`, `google-analytics`, `google-base`, `grammarly.pxf.io`, `ipv4.podscribe.com`, `ipv6.6sc.co`, `j.6sc.co`, `js.zi-scripts.com`, `linkedin`, `linkedin-base`, `magnite`, `meta-base`, `ms-base`, `pixel.tapad.com`, `pubmatic`, `quora-base`, `r.clarity.ms`, `scripts.clarity.ms`, `spotify-base`, `taboola`, `tags.w55c.net`, `the-trade-desk`, `tiktok-base`, `transcend-cdn.com`, `utt.impactcdn.com`, `verifi.podscribe.com`, `ws-assets.zoominfo.com`, `ws.zoominfo.com`, `www.clarity.ms`, `www.google.co.il`, `x.bidswitch.net`, `xandr`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
