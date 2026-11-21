# Adobe Creative Cloud and account services

- Content-pack id today: `adobe-cloud` (`adobe.com`, `adobelogin.com`, `adobe.io`)
- Status: **READY**, NAME, batch H (`research/patches/batch-h-name-based.patch`)
- Sources: accessed 2026-11-19; page "Last updated on Nov 5, 2026"

## 1. What it is

Adobe's apps and services (Creative Cloud, Acrobat, Express) and Adobe accounts.

## 2. Transport and ports

"URLs and domains that must be accessible on port 443" [S1].

## 3. Observable evidence

"Minimal allowlist", "Adobe hosted domains" [S1]: `*.adobe.com`, `*.adobe.io`, `*.adobecc.com`, `*.adobecces.com`, `*.adobeccstatic.com`, `*.adobedtm.com`, `*.adobeexchange.com`, `*.adobegenuine.com`, `*.adobegov.com`, `*.adobe-identity.com`, `*.adobejanus.com`, `*.adobelogin.com`, `*.adobedc.net`, `*.adobeoobe.com`, `*.adobeprojectm.com`, `*.adobesc.com`, `*.adobe-services.com`, `*.adobess.com`, `*.adobesunbreak.com`, `*.adobetag.com`, `*.behance.net`, `*.ftcdn.net`, `*.typekit.com`, `*.typekit.net`, `slp-statics.astockcdn.net`; then AWS and other third-party names (`*.cloudfront.net`, S3 names, `firebase-settings.crashlytics.com`, `*.arkoselabs.com` and others). The page also has an exhaustive per-service list and a downloadable file.

## 4. Encrypted-traffic caveats

Not proposed, because other websites embed them, so a match would not mean the user is using an Adobe app: `adobedtm.com` and `adobetag.com` (Adobe tag manager scripts), `adobedc.net` (Adobe data collection), `typekit.net` (Adobe Fonts served to websites), `ftcdn.net` (Adobe Stock images), `behance.net` (Behance, a separate Adobe community product), `typekit.com` (Adobe Fonts) and the exact `slp-statics.astockcdn.net`. This lane's reading of what those domains serve is general knowledge, not from the page (`UNVERIFIED` there); leaving them out is the conservative choice. The page does not say what `adobejanus.com`, `adobeprojectm.com`, `adobess.com` or `adobesunbreak.com` serve; they are proposed because the page lists them as Adobe-hosted, at N2.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `adobe.com`, `adobe.io`, `adobelogin.com` | **N3** | Already mapped |
| SNI under `adobecc.com`, `adobecces.com`, `adobeccstatic.com`, `adobeexchange.com`, `adobegenuine.com`, `adobegov.com`, `adobe-identity.com`, `adobeoobe.com`, `adobesc.com`, `adobe-services.com` | **N3** |  |
| SNI under `adobejanus.com`, `adobeprojectm.com`, `adobess.com`, `adobesunbreak.com` | **N2** | Purpose not stated |
| `adobedtm.com`, `adobetag.com`, `adobedc.net`, `typekit.net`, `ftcdn.net`, `behance.net`, `typekit.com` | not mapped | Embedded in other websites or a separate product |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D, E, F, G and H): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `x.adobecc.com`, `prod.acp.adobeoobe.com`, `ad.adobe-identity.com`, `x.adobess.com`, `adobegov.com` | `adobe-cloud` (today unmapped) |
| P2 | SNI `ims-na1.adobelogin.com` | `adobe-cloud` |
| N1 | SNI `assets.adobedtm.com`, `use.typekit.net`, `x.adobedc.net`, `t.ftcdn.net` | unmapped |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J and K as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `account.adobe.com` | one of `adobe-cloud` | `adobe-cloud` | PASS |
| O+ | `www.adobe.com` | one of `adobe-cloud` | `adobe-cloud` | PASS |
| L- | `xadobe.com` | not adobe-cloud (label boundary) | no application | PASS |
| L- | `adobe.com.example.invalid` | not adobe-cloud (suffix look-alike) | no application | PASS |
| L- | `xadobelogin.com` | not adobe-cloud (label boundary) | no application | PASS |
| L- | `adobelogin.com.example.invalid` | not adobe-cloud (suffix look-alike) | no application | PASS |
| L- | `xadobe.io` | not adobe-cloud (label boundary) | no application | PASS |
| L- | `adobe.io.example.invalid` | not adobe-cloud (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Adobe Help Center, "Allow required domains for Adobe apps and services", `https://helpx.adobe.com/business/enterprise/manage-services/configure-services/network-endpoints.html` (where `https://helpx.adobe.com/enterprise/kb/network-endpoints.html` redirects), accessed 2026-11-19.

## 8. Catalog delta and recommendation

```python
("adobe-cloud", ..., ("adobe.com", "adobelogin.com", "adobe.io", "adobecc.com", "adobecces.com", "adobeccstatic.com",
 "adobeexchange.com", "adobegenuine.com", "adobegov.com", "adobe-identity.com", "adobejanus.com", "adobeoobe.com",
 "adobeprojectm.com", "adobesc.com", "adobe-services.com", "adobess.com", "adobesunbreak.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `adobe.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.adobe.com`, subject organisation **Adobe Inc** (issuer DigiCert Inc) |
| `adobelogin.com` | resolves; TLS handshake failed (SSLCertVerificationError) in both rounds where checked: not a removal reason |
| `adobe.io` | **L** resolves; TLSv1.3, ALPN `None`, cert `adobe.io`, subject organisation **Adobe Inc.** (issuer DigiCert Inc) |
| `adobecc.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `adobecces.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `adobeccstatic.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `adobeexchange.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `exchange.adobe.com`, subject organisation **Adobe Inc.** (issuer DigiCert Inc) |
| `adobegenuine.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `adobegov.com` | **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `*.adobegov.com`, subject organisation **Adobe Inc.** (issuer DigiCert Inc) |
| `adobe-identity.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `adobejanus.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `adobeoobe.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `adobeprojectm.com` | resolves; TLS handshake failed (SSLCertVerificationError) in both rounds where checked: not a removal reason |
| `adobesc.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `adobe-services.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `adobess.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `adobesunbreak.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |

## 10. Observed web-client hosts (dependency mapping)

- `https://account.adobe.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `account.adobe.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `account.adobe.com` | seen | app-owned | `adobe-cloud` |  |  |
| `www.adobe.com` | seen (some failed) | app-owned | `adobe-cloud` | cdn |  |

## 11. Attributes (App-ID model) and re-verify date

- `adobe-cloud`: business-systems / office-programs, client-server; characteristics `transfers-files`, `widely-used`; **risk 2**: moves files out of the organisation; widely used by enterprises.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
