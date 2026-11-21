# Figma

- Content-pack id today: `figma` (`figma.com`)
- Status: **READY**, NAME, batch D (Figma for Government only); other listed domains are PARTIAL
- Sources accessed: 2026-11-19

## 1. What it is

Design and collaboration tool.

## 2. Transport and ports

HTTPS [S1].

## 3. Observable evidence

Allowlist [S1]: `*.figma.com`, `*.figma.site`, `*.makeproxy-c.figma.site`, `*.makeproxy-m.figma.site`, `*.awswaf.com`, `*.esm.sh`, `*.jsdelivr.net`, `*.figma.app`, `*.arkoselabs.com`, `*.weavy.ai`, `*.figmaweave.com`, `*.prodregistryv2.org`; "For those on the Figma for Government solution": `*.figma-gov.com`, `*.figma-gov.site`, `*.makeproxy-c.figma-gov.site`.

## 4. Encrypted-traffic caveats

The page gives no purpose per domain. `figma.site` and `figma-gov.site` may host customers' published sites (tenant hosting), and `figma.app`, `weavy.ai` and `figmaweave.com` are unexplained, so none is proposed. Third parties: AWS WAF, esm.sh, jsDelivr, Arkose Labs.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `figma.com` | **N3** | Already mapped |
| `figma-gov.com` | **N3** | Named for Figma for Government |
| `figma.site`, `figma.app`, `figmaweave.com`, `weavy.ai` | **U** for purpose | Not mapped |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `www.figma-gov.com` | `figma` |
| N1 | SNI `x.figma.site` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K and M as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `errors.figma.com` | one of `figma` | `figma` | PASS |
| O+ | `marketing.figma.com` | one of `figma` | `figma` | PASS |
| O+ | `static.figma.com` | one of `figma` | `figma` | PASS |
| O+ | `www.figma.com` | one of `figma` | `figma` | PASS |
| D- | `15411044.fls.doubleclick.net` | not figma (third party) | `google-ads` | PASS |
| D- | `a.quora.com` | not figma (shared vendor infra) | `quora-base` | PASS |
| D- | `acdn.adnxs.com` | not figma (third party) | `xandr` | PASS |
| D- | `ad.doubleclick.net` | not figma (third party) | `google-ads` | PASS |
| D- | `adservice.google.com` | not figma (shared vendor infra) | `google-base` | PASS |
| D- | `alb.reddit.com` | not figma (shared vendor infra) | `reddit-base` | PASS |
| D- | `analytics.twitter.com` | not figma (shared vendor infra) | `x-base` | PASS |
| D- | `bat.bing.com` | not figma (shared vendor infra) | `ms-base` | PASS |
| D- | `bzr.openai.com` | not figma (third party) | no application | PASS |
| D- | `bzrcdn.openai.com` | not figma (third party) | no application | PASS |
| D- | `c.bing.com` | not figma (shared vendor infra) | `ms-base` | PASS |
| D- | `c.clarity.ms` | not figma (third party (unclassified)) | no application | PASS |
| D- | `connect.facebook.net` | not figma (shared vendor infra) | `meta-base` | PASS |
| D- | `d2hrivdxn8ekm8.cloudfront.net` | not figma (third party (unclassified)) | no application | PASS |
| D- | `e.clarity.ms` | not figma (third party (unclassified)) | no application | PASS |
| D- | `googleads.g.doubleclick.net` | not figma (third party) | `google-ads` | PASS |
| D- | `ib.adnxs.com` | not figma (third party) | `xandr` | PASS |
| D- | `nam.veta.naver.com` | not figma (third party (unclassified)) | no application | PASS |
| D- | `pixel-config.reddit.com` | not figma (shared vendor infra) | `reddit-base` | PASS |
| D- | `pixel.byspotify.com` | not figma (third party) | no application | PASS |
| D- | `pixels.spotify.com` | not figma (shared vendor infra) | `spotify-base` | PASS |
| D- | `prodregistryv2.org` | not figma (third party (unclassified)) | no application | PASS |
| D- | `px.ads.linkedin.com` | not figma (shared vendor infra) | `linkedin-base` | PASS |
| D- | `px4.ads.linkedin.com` | not figma (shared vendor infra) | `linkedin-base` | PASS |
| D- | `q.quora.com` | not figma (shared vendor infra) | `quora-base` | PASS |
| D- | `scripts.clarity.ms` | not figma (third party (unclassified)) | no application | PASS |
| D- | `segment.prod.bidr.io` | not figma (third party (unclassified)) | no application | PASS |
| D- | `snap.licdn.com` | not figma (shared vendor infra) | `linkedin-base` | PASS |
| D- | `ssl.pstatic.net` | not figma (third party (unclassified)) | no application | PASS |
| D- | `static.ads-twitter.com` | not figma (third party) | no application | PASS |
| D- | `t.co` | not figma (shared vendor infra) | `x-base` | PASS |
| D- | `tte-prod.telemetry.vaultdcr.com` | not figma (third party (unclassified)) | no application | PASS |
| D- | `wcs.naver.com` | not figma (third party (unclassified)) | no application | PASS |
| D- | `wcs.naver.net` | not figma (third party (unclassified)) | no application | PASS |
| D- | `www.clarity.ms` | not figma (third party (unclassified)) | no application | PASS |
| D- | `www.google.co.il` | not figma (third party (unclassified)) | no application | PASS |
| D- | `www.google.com` | not figma (shared vendor infra) | `google-base` | PASS |
| D- | `www.googleadservices.com` | not figma (third party) | `google-ads` | PASS |
| D- | `www.googletagmanager.com` | not figma (third party) | `google-analytics` | PASS |
| D- | `www.linkedin.com` | not figma (third party) | `linkedin` | PASS |
| D- | `www.redditstatic.com` | not figma (shared vendor infra) | `reddit-base` | PASS |
| L- | `xfigma.com` | not figma (label boundary) | no application | PASS |
| L- | `figma.com.example.invalid` | not figma (suffix look-alike) | no application | PASS |
| L- | `xfigma-gov.com` | not figma (label boundary) | no application | PASS |
| L- | `figma-gov.com.example.invalid` | not figma (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Figma Learn, "Adjust your network settings", `https://help.figma.com/hc/en-us/articles/19424714305943-Adjust-your-network-settings`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("figma", ..., ("figma.com", "figma-gov.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 and 4 of 2026-11-21 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `research/live-results-2026-11-21-r4.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `figma.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.figma.com`, no subject organisation (domain-validated) (issuer Amazon); HTTPS record offers `h3` (QUIC path) |
| `figma-gov.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.figma-gov.com`, no subject organisation (domain-validated) (issuer Amazon); HTTPS record offers `h3` (QUIC path) |

## 10. Observed web-client hosts (dependency mapping)

- `https://www.figma.com/login`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP None (page.goto: Timeout 45000ms exceeded.), final host `www.figma.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `15411044.fls.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `a.quora.com` | seen | shared vendor infra | `quora-base` | not checked |  |
| `acdn.adnxs.com` | seen | third party | `xandr` | not checked |  |
| `ad.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `adservice.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `alb.reddit.com` | seen | shared vendor infra | `reddit-base` | not checked |  |
| `analytics.twitter.com` | seen | shared vendor infra | `x-base` | not checked |  |
| `bat.bing.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `bzr.openai.com` | seen | third party | no application | not checked | OpenAI measurement host loaded by unrelated pages (not mapped: openai.com is a web front only) |
| `bzrcdn.openai.com` | seen | third party | no application | not checked | as above |
| `c.bing.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `c.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `connect.facebook.net` | seen | shared vendor infra | `meta-base` | not checked |  |
| `d2hrivdxn8ekm8.cloudfront.net` | seen | third party (unclassified) | no application | not checked |  |
| `e.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `errors.figma.com` | seen | app-owned | `figma` | not checked |  |
| `googleads.g.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `ib.adnxs.com` | seen | third party | `xandr` | not checked |  |
| `marketing.figma.com` | seen | app-owned | `figma` | not checked |  |
| `nam.veta.naver.com` | seen | third party (unclassified) | no application | not checked |  |
| `pixel-config.reddit.com` | seen | shared vendor infra | `reddit-base` | not checked |  |
| `pixel.byspotify.com` | seen | third party | no application | not checked | Spotify advertising pixel |
| `pixels.spotify.com` | seen | shared vendor infra | `spotify-base` | not checked |  |
| `prodregistryv2.org` | seen | third party (unclassified) | no application | not checked |  |
| `px.ads.linkedin.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `px4.ads.linkedin.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `q.quora.com` | seen | shared vendor infra | `quora-base` | not checked |  |
| `scripts.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `segment.prod.bidr.io` | seen | third party (unclassified) | no application | not checked |  |
| `snap.licdn.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `ssl.pstatic.net` | seen | third party (unclassified) | no application | not checked |  |
| `static.ads-twitter.com` | seen | third party | no application | not checked | X advertising tag |
| `static.figma.com` | seen | app-owned | `figma` | not checked |  |
| `t.co` | seen | shared vendor infra | `x-base` | not checked |  |
| `tte-prod.telemetry.vaultdcr.com` | seen | third party (unclassified) | no application | not checked |  |
| `wcs.naver.com` | seen | third party (unclassified) | no application | not checked |  |
| `wcs.naver.net` | seen | third party (unclassified) | no application | not checked |  |
| `www.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `www.figma.com` | seen | app-owned | `figma` | not checked |  |
| `www.google.co.il` | seen | third party (unclassified) | no application | not checked |  |
| `www.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `www.googleadservices.com` | seen | third party | `google-ads` | not checked |  |
| `www.googletagmanager.com` | seen | third party | `google-analytics` | not checked |  |
| `www.linkedin.com` | seen | third party | `linkedin` | not checked |  |
| `www.redditstatic.com` | seen | shared vendor infra | `reddit-base` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `figma`: business-systems / office-programs, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `bzr.openai.com`, `bzrcdn.openai.com`, `c.clarity.ms`, `d2hrivdxn8ekm8.cloudfront.net`, `e.clarity.ms`, `google-ads`, `google-analytics`, `google-base`, `linkedin`, `linkedin-base`, `meta-base`, `ms-base`, `nam.veta.naver.com`, `pixel.byspotify.com`, `prodregistryv2.org`, `quora-base`, `reddit-base`, `scripts.clarity.ms`, `segment.prod.bidr.io`, `spotify-base`, `ssl.pstatic.net`, `static.ads-twitter.com`, `tte-prod.telemetry.vaultdcr.com`, `wcs.naver.com`, `wcs.naver.net`, `www.clarity.ms`, `www.google.co.il`, `x-base`, `xandr`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `figma.com`, `figma-gov.com`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
