# Tracker and tag hosts of consumer apps embedded in other websites

- Content-pack id today: `facebook`, `twitter`, `linkedin`, `reddit`, `quora`, `tiktok`, `spotify`, `bing` (their names below match these apps today)
- Status: **READY**, NAME, batch K (`research/patches/batch-k-dependency-pass2.patch`): new vendor-level ids `meta-base`, `x-base`, `linkedin-base`, `reddit-base`, `quora-base`, `tiktok-base`, `spotify-base`; `ms-base` gains the Bing tag hosts and `static.microsoft`
- Sources: dependency mapping pass 2, run by Hermes on its server with a direct connection, 2026-11-20 (`research/observations/pass2-2026-11-20.tsv`); Hermes decision 4 (2026-11-20); IANA root zone database for `.microsoft`

## 1. What it is

Advertising, conversion and analytics tags of consumer platforms, which other companies' websites embed. A browser loading Slack's or Dropbox's sign-in page also contacts these hosts.

## 2. Transport and ports

HTTPS (TLS SNI). No ports beyond 443 were observed.

## 3. Observable evidence

Pass 2 loaded 59 public sign-in and web-client pages. These hosts belong to consumer apps but were loaded by **unrelated** pages (pages observed): `connect.facebook.net` (5: Grammarly, Dropbox, Figma, Notion, Perplexity); `px.ads.linkedin.com` (7), `px4.ads.linkedin.com` (6), `dc.ads.linkedin.com` (1), `snap.licdn.com` (7); `analytics.twitter.com` (3), `t.co` (3); `alb.reddit.com` (4), `pixel-config.reddit.com` (3), `www.redditstatic.com` (4); `a.quora.com`, `q.quora.com` (2 each); `analytics.tiktok.com` (1: Grammarly); `pixels.spotify.com` (2: Grammarly, Figma); `bat.bing.com` (6), `c.bing.com` (5, one of them Microsoft's own OneDrive page), `bat.bing.net` (1). Before K, each of these reported the consumer app (`facebook`, `linkedin`, `twitter`, `reddit`, `quora`, `tiktok`, `spotify`, `bing`), so a user opening Slack's sign-in page would have been reported as using LinkedIn, Reddit and Bing. `teams.public.onecdn.static.microsoft` (Teams page) is a Microsoft static CDN under the `.microsoft` brand TLD, whose manager is Microsoft Corporation (IANA root zone database, `https://www.iana.org/domains/root/db/microsoft.html`, read 2026-11-20).

## 4. Encrypted-traffic caveats

Hermes decision 4: a name that third-party pages load is shared vendor infrastructure and goes to a vendor-level id. Only the dedicated tag subtrees are moved. The main sites stay with their apps (`www.facebook.com`, `www.linkedin.com`, `twitter.com`, `www.reddit.com`), so **residual false positives remain** where a tag calls a main-site name: `www.linkedin.com` was loaded by 7 unrelated pages and `www.facebook.com` by 1. SNI cannot separate those from real use. `t.co` (X's link shortener) moves to `x-base`, because pages load it as a tag and a click-through is not X use either. `redditstatic.com` moves to `reddit-base`, since Reddit itself is still named by `reddit.com`. Unmapped tag hosts (`static.ads-twitter.com`, `pixel.byspotify.com`, `analytics-ipv6.tiktokw.us`) stay unmapped (no application), which is already correct.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| Moved tag subtrees | vendor-level id | Observed on unrelated pages (O, 2026-11-20) |
| `www.linkedin.com`, `www.facebook.com` | app (unchanged) | Residual false positive when loaded as a tag |
| `static.microsoft` | `ms-base` | Brand TLD managed by Microsoft (IANA) |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J and K): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `connect.facebook.net` | `meta-base` (today `facebook`) |
| P2 | SNI `px.ads.linkedin.com`, `snap.licdn.com` | `linkedin-base` (today `linkedin`) |
| P3 | SNI `t.co`, `analytics.twitter.com` | `x-base` (today `twitter`) |
| P4 | SNI `alb.reddit.com`, `www.redditstatic.com` | `reddit-base` (today `reddit`) |
| P5 | SNI `a.quora.com`, `analytics.tiktok.com`, `pixels.spotify.com` | `quora-base`, `tiktok-base`, `spotify-base` |
| P6 | SNI `bat.bing.com`, `teams.public.onecdn.static.microsoft` | `ms-base` (today `bing`, unmapped) |
| N1 | SNI `www.facebook.com`, `www.linkedin.com`, `x.com`, `www.reddit.com`, `open.spotify.com`, `www.bing.com` | the app (unchanged) |
| N2 | SNI `x.windows.static.microsoft` | `ms-virtual-desktop` (longer suffix) |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O and P as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xfacebook.net` | not meta-base/x-base/linkedin-base/reddit-base/quora-base/tiktok-base/spotify-base (label boundary) | no application | PASS |
| L- | `connect.facebook.net.example.invalid` | not meta-base/x-base/linkedin-base/reddit-base/quora-base/tiktok-base/spotify-base (suffix look-alike) | no application | PASS |
| L- | `xt.co` | not meta-base/x-base/linkedin-base/reddit-base/quora-base/tiktok-base/spotify-base (label boundary) | no application | PASS |
| L- | `t.co.example.invalid` | not meta-base/x-base/linkedin-base/reddit-base/quora-base/tiktok-base/spotify-base (suffix look-alike) | no application | PASS |
| L- | `xtwitter.com` | not meta-base/x-base/linkedin-base/reddit-base/quora-base/tiktok-base/spotify-base (label boundary) | no application | PASS |
| L- | `analytics.twitter.com.example.invalid` | not meta-base/x-base/linkedin-base/reddit-base/quora-base/tiktok-base/spotify-base (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [O] Dependency mapping pass 2, `research/observations/pass2-2026-11-20.tsv` (Hermes server, 2026-11-20).
- [D4] Hermes decision 4, 2026-11-20 (`research/backlog.md`).
- [IANA] IANA root zone database, `.microsoft`, `https://www.iana.org/domains/root/db/microsoft.html`, accessed 2026-11-20.

## 8. Catalog delta and recommendation

```python
("meta-base", "general-internet", "internet-utility", "browser-based", 2,
 "Meta tags and shared services embedded in other websites (not Facebook use)", (), ("connect.facebook.net",)),
# likewise x-base (t.co, analytics.twitter.com), linkedin-base (ads.linkedin.com, snap.licdn.com),
# reddit-base (redditstatic.com, alb.reddit.com, pixel-config.reddit.com), quora-base (a.quora.com, q.quora.com),
# tiktok-base (analytics.tiktok.com), spotify-base (pixels.spotify.com)
# twitter loses t.co; reddit loses redditstatic.com; ms-base gains bat.bing.com, c.bing.com, bat.bing.net, static.microsoft
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 6 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `connect.facebook.net` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `*.facebook.com`, subject organisation **Meta Platforms, Inc.** (issuer DigiCert Inc); HTTPS record offers `h3` (QUIC path) |
| `t.co` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `t.co`, no subject organisation (domain-validated) (issuer Let's Encrypt) |
| `analytics.twitter.com` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `*.twitter.com`, no subject organisation (domain-validated) (issuer Let's Encrypt) |
| `ads.linkedin.com` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `admin.pointdrive.linkedin.com`, subject organisation **Linkedin Corporation** (issuer DigiCert Inc); CNAME into shared front end `www.linkedin.com.cdn.cloudflare.net`: name usable, IPs never |
| `snap.licdn.com` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `*.licdn.com`, subject organisation **Linkedin Corporation** (issuer DigiCert Inc); CNAME into shared front end `a1916.dscg2.akamai.net`: name usable, IPs never |
| `redditstatic.com` | apex has no address (normal for a suffix entry); suffix **verified** through documented `www.redditstatic.com` (round 3, cdn) |
| `alb.reddit.com` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `*.reddit.com`, subject organisation **Reddit, Inc.** (issuer DigiCert Inc); CNAME into shared front end `dualstack.reddit.map.fastly.net`: name usable, IPs never |
| `pixel-config.reddit.com` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `*.reddit.com`, subject organisation **Reddit, Inc.** (issuer DigiCert Inc); CNAME into shared front end `reddit.map.fastly.net`: name usable, IPs never |
| `a.quora.com` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `quora.com`, no subject organisation (domain-validated) (issuer Google Trust Services); CNAME into shared front end `a.quora.com.cdn.cloudflare.net`: name usable, IPs never |
| `q.quora.com` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `quora.com`, no subject organisation (domain-validated) (issuer Google Trust Services); CNAME into shared front end `q.quora.com.cdn.cloudflare.net`: name usable, IPs never |
| `analytics.tiktok.com` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `*.tiktok.com`, no subject organisation (domain-validated) (issuer DigiCert Inc); CNAME into shared front end `e35058.api15.akamaiedge.net`: name usable, IPs never |
| `pixels.spotify.com` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `*.spotify.com`, subject organisation **Spotify AB** (issuer DigiCert Inc) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `meta-base`: general-internet / internet-utility, browser-based; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- `x-base`: general-internet / internet-utility, browser-based; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- `linkedin-base`: general-internet / internet-utility, browser-based; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- `reddit-base`: general-internet / internet-utility, browser-based; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- `quora-base`: general-internet / internet-utility, browser-based; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- `tiktok-base`: general-internet / internet-utility, browser-based; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- `spotify-base`: general-internet / internet-utility, browser-based; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- Functions separated by name: `meta-base` (Meta tags and shared services embedded in other websites (not Facebook use)), `x-base` (X (Twitter) tags and shared services embedded in other websites (not X use)), `linkedin-base` (LinkedIn tags and shared services embedded in other websites (not LinkedIn use)), `reddit-base` (Reddit tags and shared services embedded in other websites (not Reddit use)), `quora-base` (Quora tags and shared services embedded in other websites (not Quora use)), `tiktok-base` (TikTok tags and shared services embedded in other websites (not TikTok use)), `spotify-base` (Spotify tags and shared services embedded in other websites (not Spotify use)).
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `connect.facebook.net`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
