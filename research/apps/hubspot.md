# HubSpot (CRM app and HubSpot-hosted page services)

- Content-pack id today: `hubspot` (`hubspot.com`)
- Status: **READY**, NAME, batch P (`research/patches/batch-p-name-based.patch`): new vendor-level id `hubspot-base`
- Sources: [H] read in the research cloud (egress proxy), 2026-11-22; page "Last updated: November 19, 2026"

## 1. What it is

CRM, marketing, sales and service platform. Customers' websites and landing pages embed HubSpot's tracking code, forms, chat, calls-to-action and cookie banner, and HubSpot's CMS hosts customer pages and files.

## 2. Transport and ports

HTTPS (the page is a Content-Security-Policy list for HubSpot-hosted pages; it states no ports) [H].

## 3. Observable evidence

[H] "The following domains and directives should be included to ensure full functionality on HubSpot-hosted pages": ads `*.hsadspixel.net`; analytics `*.hs-analytics.net`; API calls `*.hubapi.com`; calls-to-action `js.hscta.net` and `js-eu1`, `js-na2`, `js-na3`, `js-ap1` `.hscta.net`, `js.hscta.com` and the same regional names under `hscta.com`, `no-cache.hubspot.com` with the S3 buckets `hubspot-no-cache-na2-prod`, `-na3-prod`, `-ap1-prod` (`.s3.amazonaws.com`), `hsctaimages.net` and `eu1`, `na2`, `na3`, `ap1` `.hsctaimages.net`; pop-ups and chatflows `*.hubspot.com`, `*.hs-sites.com`, `*.hs-sites-eu1.com`, `*.hs-sites-na2.com`, `*.hs-sites-na3.com`, `*.hs-sites-ap1.com`; content `static.hsappstatic.net`; conversations `*.usemessages.com`; cookie banner `*.hs-banner.com`; files `*.hubspotusercontent##.net` ("## can be 00, 10, 20, 30, or 40"), `*.hubspotusercontent-eu1.net`, `-na2`, `-na3`, `-ap1`, `*.hubspot.net`, `cdn2.hubspot.net`; videos `play.hubspotvideo.com` and `play-eu1`, `-na2`, `-na3`, `-ap1`; forms `*.hscollectedforms.net`, `*.hsleadflows.net`, `*.hsforms.net`, `*.hsforms.com`; tracking code `*.hs-scripts.com`; surveys `*.hubspotfeedback.com`, `feedback.hubapi.com`, regional `feedback-*.hubapi.com` and `feedback-*.hubspotservicehub.com`; and "Your domain connected to HubSpot".

## 4. Encrypted-traffic caveats

These hosts are what customers' own websites load, so they appear on pages that have nothing to do with a user working in HubSpot. Under decision 4 they go to the vendor-level id `hubspot-base` ("HubSpot tags and shared services embedded in other websites (not HubSpot use)"), like `meta-base` and `linkedin-base`; the app itself (`app.hubspot.com`) stays `hubspot`. `*.hubspot.com` is listed for pop-ups and chatflows too, so a page embedding those still reports `hubspot`: a residual false positive, as with `www.linkedin.com`. `hs-sites*.com` and `hubspotusercontent*.net` host customer content: the catalog names the vendor only. `hsappstatic.net` also serves the HubSpot app's own static assets (**N2** for "not HubSpot use"). `hubapi.com` also carries integrations' server-to-server API traffic (**N2**). Customer domains connected to HubSpot have no HubSpot name and are not identifiable. The three S3 hosts are exact vendor-named bucket names (the Asana precedent).

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `hubspot.com` | **N3** | Already mapped (`hubspot`) |
| SNI under the 30 dedicated HubSpot tag and hosting domains | **N3** for `hubspot-base` | Embedded on other sites |
| SNI under `hsappstatic.net`, `hubapi.com` | **N2** for `hubspot-base` | Also the app's assets and API |
| Exact three `hubspot-no-cache-*-prod.s3.amazonaws.com` | **N3** (exact) | CTA images |
| Customer domains connected to HubSpot | not mapped | No HubSpot name |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K, M, N, O and P): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `app.hubspot.com` | `hubspot` |
| P2 | SNI `js.hs-scripts.com`, `js.hs-analytics.net`, `forms.hsforms.com`, `js.usemessages.com`, `js.hs-banner.com` | `hubspot-base` (today unmapped) |
| P3 | SNI `f.hubspotusercontent20.net`, `acme.hs-sites.com`, `hubspot-no-cache-na2-prod.s3.amazonaws.com` | `hubspot-base` (today unmapped) |
| N1 | SNI `xhubapi.com`, `hubspotusercontent50.net`, `x.s3.amazonaws.com` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O and P as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xhubspot.com` | not hubspot/hubspot-base (label boundary) | no application | PASS |
| L- | `hubspot.com.example.invalid` | not hubspot/hubspot-base (suffix look-alike) | no application | PASS |
| L- | `xhsadspixel.net` | not hubspot/hubspot-base (label boundary) | no application | PASS |
| L- | `hsadspixel.net.example.invalid` | not hubspot/hubspot-base (suffix look-alike) | no application | PASS |
| L- | `xhs-analytics.net` | not hubspot/hubspot-base (label boundary) | no application | PASS |
| L- | `hs-analytics.net.example.invalid` | not hubspot/hubspot-base (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [H] HubSpot Knowledge Base, "SSL and domain security in HubSpot", `https://knowledge.hubspot.com/domains-and-urls/ssl-and-domain-security-in-hubspot`, read in the research cloud (egress proxy), 2026-11-22.

## 8. Catalog delta and recommendation

```python
("hubspot-base", "general-internet", "internet-utility", "browser-based", 2,
 "HubSpot tags and shared services embedded in other websites (not HubSpot use)", (),
 ("hsadspixel.net", "hs-analytics.net", "hubapi.com", "hscta.net", "hscta.com", "hsctaimages.net", "hs-sites.com",
  "hs-sites-eu1.com", "hs-sites-na2.com", "hs-sites-na3.com", "hs-sites-ap1.com", "hsappstatic.net", "usemessages.com",
  "hs-banner.com", "hubspotusercontent00.net", "hubspotusercontent10.net", "hubspotusercontent20.net",
  "hubspotusercontent30.net", "hubspotusercontent40.net", "hubspotusercontent-eu1.net", "hubspotusercontent-na2.net",
  "hubspotusercontent-na3.net", "hubspotusercontent-ap1.net", "hubspot.net", "hubspotvideo.com", "hscollectedforms.net",
  "hsleadflows.net", "hsforms.net", "hsforms.com", "hs-scripts.com", "hubspotfeedback.com", "hubspotservicehub.com",
  "hubspot-no-cache-na2-prod.s3.amazonaws.com", "hubspot-no-cache-na3-prod.s3.amazonaws.com",
  "hubspot-no-cache-ap1-prod.s3.amazonaws.com")),
```

`hubspot` is unchanged.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `hubspot.com` | round 7 (2026-11-22); **L** resolves; TLSv1.3, ALPN `h2`, TLS via documented probe `app.hubspot.com`, probe cert `hubspot.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `hsadspixel.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hs-analytics.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hubapi.com` | round 7 (2026-11-22); **L** resolves; TLSv1.3, ALPN `h2`, TLS via documented probe `feedback.hubapi.com`, probe cert `hubapi.com`, no subject organisation (domain-validated) (issuer Google Trust Services); verdict (PRO-167): stays **N2** (also integrations' API traffic) |
| `hscta.net` | apex has no address (normal for a suffix entry); suffix **verified** through documented `js.hscta.net` (round 7) |
| `hscta.com` | apex has no address (normal for a suffix entry); suffix **verified** through documented `js.hscta.com` (round 7) |
| `hsctaimages.net` | round 7 (2026-11-22); **L** resolves; TLSv1.3, ALPN `h2`, TLS via documented probe `eu1.hsctaimages.net`, probe cert `hsctaimages.net`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `hs-sites.com` | round 7 (2026-11-22); **L** resolves; TLSv1.3, ALPN `h2`, cert `hs-sites.com`, no subject organisation (domain-validated) (issuer Google Trust Services); HTTPS record offers `h3` (QUIC path) |
| `hs-sites-eu1.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hs-sites-na2.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hs-sites-na3.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hs-sites-ap1.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hsappstatic.net` | round 7 (2026-11-22); **L** resolves; TLSv1.3, ALPN `h2`, TLS via documented probe `static.hsappstatic.net`, probe cert `hsappstatic.net`, no subject organisation (domain-validated) (issuer Google Trust Services); verdict (PRO-167): stays **N2** (also the HubSpot app's own static assets) |
| `usemessages.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hs-banner.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hubspotusercontent00.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hubspotusercontent10.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hubspotusercontent20.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hubspotusercontent30.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hubspotusercontent40.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hubspotusercontent-eu1.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hubspotusercontent-na2.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hubspotusercontent-na3.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hubspotusercontent-ap1.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hubspot.net` | round 7 (2026-11-22); **L** resolves; TLSv1.3, ALPN `h2`, TLS via documented probe `cdn2.hubspot.net`, probe cert `hubspot.net`, no subject organisation (domain-validated) (issuer Google Trust Services); HTTPS record offers `h3` (QUIC path) |
| `hubspotvideo.com` | apex has no address (normal for a suffix entry); suffix **verified** through documented `play.hubspotvideo.com` (round 7) |
| `hscollectedforms.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hsleadflows.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hsforms.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hsforms.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hs-scripts.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hubspotfeedback.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-167): **neutral**: the name exists but has no address and the source names no host to probe, so it is not live-verified; the mapping rests on the vendor page |
| `hubspotservicehub.com` | apex has no address (normal for a suffix entry); suffix **verified** through documented `feedback-eu1.hubspotservicehub.com` (round 7) |
| `hubspot-no-cache-na2-prod.s3.amazonaws.com` | round 7 (2026-11-22); **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `*.s3-us-west-2.amazonaws.com`, no subject organisation (domain-validated) (issuer Amazon); CNAME into shared front end `s3-us-west-2-w.amazonaws.com`: name usable, IPs never |
| `hubspot-no-cache-na3-prod.s3.amazonaws.com` | round 7 (2026-11-22); **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `*.s3.ca-central-1.amazonaws.com`, no subject organisation (domain-validated) (issuer Amazon); CNAME into shared front end `s3-w.ca-central-1.amazonaws.com`: name usable, IPs never |
| `hubspot-no-cache-ap1-prod.s3.amazonaws.com` | round 7 (2026-11-22); **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `*.s3-ap-southeast-2.amazonaws.com`, no subject organisation (domain-validated) (issuer Amazon); CNAME into shared front end `s3-ap-southeast-2-w.amazonaws.com`: name usable, IPs never |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `hubspot`: business-systems / general-business, browser-based; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- `hubspot-base`: general-internet / internet-utility, browser-based; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- Functions separated by name: `hubspot` (HubSpot CRM), `hubspot-base` (HubSpot tags and shared services embedded in other websites (not HubSpot use)).
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `hs-sites.com`, `hubspot.net`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
