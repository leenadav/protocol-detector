# WeTransfer

- Content-pack id today: `wetransfer` (`wetransfer.com`, `wetransfer.net`)
- Status: **READY**, NAME, batch C (`research/patches/batch-c-name-based.patch`)
- Sources accessed: 2026-11-18. Article "Updated 22 October 2026"

## 1. What it is

Browser-based large-file transfer, a common exfiltration and shadow-IT concern.

## 2. Transport and ports

"WeTransfer uses HTTPS (port 443) for secure communication and the QUIC protocol for faster, more efficient
transfers. QUIC is the transport layer for HTTP/3 and runs over UDP" [S1]. Admins should allow TCP 443 and
UDP 443 [S1].

## 3. Observable evidence

From "How do I configure a firewall for WeTransfer?" [S1]:

| Section | Hosts (as listed) |
|---|---|
| Core WeTransfer domains | `wetransfer.com`, `www.`, `analytics-v2.`, `cdn.`, `donny.`, `experiments.`, `help.`, `lebowski.`, `privacy.`, `snowplow.`, `tagging.`, `auth.`, `auth-web.`, `portals.wetransfer.com` |
| WeTransfer.net domains | `wetransfer.net`, `backgrounds.`, `bsp-proxy.`, `ekstrom.`, `helios-assets.`, `nolan.`, `spaceship.`, `storm.`, `storm-eu-west-1.`, `tempest.wetransfer.net` |
| Short links | `we.tl` |
| Amazon S3 storage | `wt-prod-euwest1-storm.s3.amazonaws.com`, `wt-prod-euwest1-storm.s3-accelerate.amazonaws.com`, `wt-prod-euwest1-storm.s3.eu-west-1.amazonaws.com`, the same three for `wt-prod-useast1-storm`, plus generic `s3.amazonaws.com`, `s3.eu-west-1.amazonaws.com`, `s3.us-east-1.amazonaws.com`, `s3-accelerate.amazonaws.com` |
| Observability, background images, analytics and advertising | Datadog, Sentry, Unsplash, Google, Bing, Facebook, Twitter, ProfitWell, jsDelivr, OneTrust hosts (third parties) |

## 4. Encrypted-traffic caveats

- **Transfers can go to S3.** The six `wt-prod-*-storm` bucket hosts are named by WeTransfer [S1], so they
  are proposed as exact hosts (precedent: the GitHub Copilot `webpubsub.azure.com` hosts). Generic S3 hosts
  and `amazonaws.com` name no application (v0.65 rule).
- **QUIC.** Transfers over HTTP/3 leave the visibility-phase TCP path [S1].
- `help.wetransfer.com` and `www.wetransfer.com` are support and marketing. They are not proposed as web
  fronts here because the page lists them as core service domains without separating them.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `wetransfer.com`, `wetransfer.net` | **N3** | Includes marketing and help |
| SNI `we.tl` | **N3** short links | Opening a link, not necessarily a transfer |
| SNI of the six named S3 bucket hosts | **N3** (exact hosts) | Upload or download storage |
| Generic S3, third-party hosts | do not map | Shared |

## 6. Synthetic test vectors

Checked in scratch (batch C on `47b2743`): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `we.tl` | `wetransfer` (today unmapped) |
| P2 | SNI `wt-prod-euwest1-storm.s3-accelerate.amazonaws.com` | `wetransfer` |
| N1 | SNI `s3.amazonaws.com`, `other-bucket.s3.amazonaws.com` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N and O as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `auth.wetransfer.com` | one of `wetransfer` | `wetransfer` | PASS |
| O+ | `backgrounds.wetransfer.net` | one of `wetransfer` | `wetransfer` | PASS |
| O+ | `bsp-proxy.wetransfer.net` | one of `wetransfer` | `wetransfer` | PASS |
| O+ | `cdn.wetransfer.com` | one of `wetransfer` | `wetransfer` | PASS |
| O+ | `genie-assets.wetransfer.net` | one of `wetransfer` | `wetransfer` | PASS |
| O+ | `lebowski.wetransfer.com` | one of `wetransfer` | `wetransfer` | PASS |
| O+ | `nolan.wetransfer.net` | one of `wetransfer` | `wetransfer` | PASS |
| O+ | `tagging.wetransfer.com` | one of `wetransfer` | `wetransfer` | PASS |
| O+ | `wetransfer.com` | one of `wetransfer` | `wetransfer` | PASS |
| D- | `accounts.google.com` | not wetransfer (shared vendor infra) | `google-accounts` | PASS |
| D- | `bat.bing.com` | not wetransfer (shared vendor infra) | `ms-base` | PASS |
| D- | `c.bing.com` | not wetransfer (shared vendor infra) | `ms-base` | PASS |
| D- | `c.clarity.ms` | not wetransfer (third party (unclassified)) | no application | PASS |
| D- | `cdn.cookielaw.org` | not wetransfer (third party) | no application | PASS |
| D- | `ekr.zdassets.com` | not wetransfer (third party) | `zendesk` | PASS |
| D- | `geolocation.onetrust.com` | not wetransfer (third party) | no application | PASS |
| D- | `google.com` | not wetransfer (shared vendor infra) | `google-base` | PASS |
| D- | `js.stripe.com` | not wetransfer (third party) | `stripe` | PASS |
| D- | `m.stripe.com` | not wetransfer (third party) | `stripe` | PASS |
| D- | `m.stripe.network` | not wetransfer (third party) | `stripe` | PASS |
| D- | `pagead2.googlesyndication.com` | not wetransfer (third party) | `google-ads` | PASS |
| D- | `q.clarity.ms` | not wetransfer (third party (unclassified)) | no application | PASS |
| D- | `scripts.clarity.ms` | not wetransfer (third party (unclassified)) | no application | PASS |
| D- | `securepubads.g.doubleclick.net` | not wetransfer (third party) | `google-ads` | PASS |
| D- | `static.zdassets.com` | not wetransfer (third party) | `zendesk` | PASS |
| D- | `wetransfer.zendesk.com` | not wetransfer (third party) | `zendesk` | PASS |
| D- | `www.clarity.ms` | not wetransfer (third party (unclassified)) | no application | PASS |
| D- | `www.googletagmanager.com` | not wetransfer (third party) | `google-analytics` | PASS |
| L- | `xwetransfer.com` | not wetransfer (label boundary) | no application | PASS |
| L- | `wetransfer.com.example.invalid` | not wetransfer (suffix look-alike) | no application | PASS |
| L- | `xwetransfer.net` | not wetransfer (label boundary) | no application | PASS |
| L- | `wetransfer.net.example.invalid` | not wetransfer (suffix look-alike) | no application | PASS |
| L- | `xwe.tl` | not wetransfer (label boundary) | no application | PASS |
| L- | `we.tl.example.invalid` | not wetransfer (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] WeTransfer Help Center, "How do I configure a firewall for WeTransfer?",
  `https://wetransfer.com/help-center/troubleshooting/configure-firewall` (linked from "My firewall is blocking
  WeTransfer", `https://wetransfer.com/help-center/security-privacy/why-blocked`), "Updated 22 October 2026",
  accessed 2026-11-18.

## 8. Catalog delta and recommendation

```python
("wetransfer", "general-internet", "file-sharing", "browser-based", 3, "WeTransfer file transfer", ("transfers-files",),
 ("wetransfer.com", "wetransfer.net", "we.tl", "wt-prod-euwest1-storm.s3.amazonaws.com",
  "wt-prod-euwest1-storm.s3-accelerate.amazonaws.com", "wt-prod-euwest1-storm.s3.eu-west-1.amazonaws.com",
  "wt-prod-useast1-storm.s3.amazonaws.com", "wt-prod-useast1-storm.s3-accelerate.amazonaws.com",
  "wt-prod-useast1-storm.s3.us-east-1.amazonaws.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 6 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `wetransfer.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `wetransfer.com`, no subject organisation (domain-validated) (issuer Amazon) |
| `wetransfer.net` | resolves; TLS handshake failed (SSLError) in both rounds where checked: not a removal reason |
| `we.tl` | **L** resolves; TLSv1.3, ALPN `None`, cert `go.wetransfer.com`, no subject organisation (domain-validated) (issuer Amazon) |
| `wt-prod-euwest1-storm.s3.amazonaws.com` | **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `*.s3-eu-west-1.amazonaws.com`, no subject organisation (domain-validated) (issuer Amazon); CNAME into shared front end `s3-3-w.amazonaws.com`: name usable, IPs never |
| `wt-prod-euwest1-storm.s3-accelerate.amazonaws.com` | **L** resolves; TLSv1.3, ALPN `None`, cert `*.s3-accelerate.amazonaws.com`, no subject organisation (domain-validated) (issuer Amazon) |
| `wt-prod-euwest1-storm.s3.eu-west-1.amazonaws.com` | **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `*.s3-eu-west-1.amazonaws.com`, no subject organisation (domain-validated) (issuer Amazon); CNAME into shared front end `s3-r-w.eu-west-1.amazonaws.com`: name usable, IPs never |
| `wt-prod-useast1-storm.s3.amazonaws.com` | **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `s3.amazonaws.com`, no subject organisation (domain-validated) (issuer Amazon); CNAME into shared front end `s3-w.us-east-1.amazonaws.com`: name usable, IPs never |
| `wt-prod-useast1-storm.s3-accelerate.amazonaws.com` | **L** resolves; TLSv1.3, ALPN `None`, cert `*.s3-accelerate.amazonaws.com`, no subject organisation (domain-validated) (issuer Amazon) |
| `wt-prod-useast1-storm.s3.us-east-1.amazonaws.com` | **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `s3.amazonaws.com`, no subject organisation (domain-validated) (issuer Amazon); CNAME into shared front end `s3-r-w.us-east-1.amazonaws.com`: name usable, IPs never |

## 10. Observed web-client hosts (dependency mapping)

- `https://wetransfer.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `wetransfer.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `accounts.google.com` | seen | shared vendor infra | `google-accounts` |  |  |
| `auth.wetransfer.com` | seen | app-owned | `wetransfer` | not checked |  |
| `backgrounds.wetransfer.net` | seen | app-owned | `wetransfer` | not checked |  |
| `bat.bing.com` | seen (some failed) | shared vendor infra | `ms-base` | not checked |  |
| `bsp-proxy.wetransfer.net` | seen | app-owned | `wetransfer` | not checked |  |
| `c.bing.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `c.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `cdn.cookielaw.org` | seen | third party | no application | not checked | OneTrust consent banner |
| `cdn.wetransfer.com` | seen | app-owned | `wetransfer` |  |  |
| `ekr.zdassets.com` | seen | third party | `zendesk` | not checked |  |
| `genie-assets.wetransfer.net` | seen | app-owned | `wetransfer` | not checked |  |
| `geolocation.onetrust.com` | seen | third party | no application | not checked | OneTrust consent geolocation |
| `google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `js.stripe.com` | seen | third party | `stripe` | not checked |  |
| `lebowski.wetransfer.com` | seen | app-owned | `wetransfer` | not checked |  |
| `m.stripe.com` | seen | third party | `stripe` | not checked |  |
| `m.stripe.network` | seen | third party | `stripe` | not checked |  |
| `nolan.wetransfer.net` | seen | app-owned | `wetransfer` | not checked |  |
| `pagead2.googlesyndication.com` | seen | third party | `google-ads` | not checked |  |
| `q.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `scripts.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `securepubads.g.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `static.zdassets.com` | seen | third party | `zendesk` | not checked |  |
| `tagging.wetransfer.com` | seen (some failed) | app-owned | `wetransfer` | not checked |  |
| `wetransfer.com` | seen | app-owned | `wetransfer` |  |  |
| `wetransfer.zendesk.com` | seen | third party | `zendesk` | not checked |  |
| `www.clarity.ms` | seen (some failed) | third party (unclassified) | no application | not checked |  |
| `www.googletagmanager.com` | seen | third party | `google-analytics` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `wetransfer`: general-internet / file-sharing, browser-based; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `c.clarity.ms`, `cdn.cookielaw.org`, `geolocation.onetrust.com`, `google-accounts`, `google-ads`, `google-analytics`, `google-base`, `ms-base`, `q.clarity.ms`, `scripts.clarity.ms`, `stripe`, `www.clarity.ms`, `zendesk`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
