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

### Method v2 vectors (checked 2026-11-19 against `c08773f` plus batches D to I and retrofit R)

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

**BLOCKED in the research environment** (2026-11-19): its egress proxy re-terminates TLS, so a handshake would show the proxy, and direct DNS is not permitted. The tool is `research/tools/live_verify.py`; it runs from an unproxied vantage point or, DNS only, through an approved DoH resolver. No host below carries an `L` result yet.

Names to verify (catalog domains of `adobe-cloud`): `adobe.com`, `adobelogin.com`, `adobe.io`, `adobecc.com`, `adobecces.com`, `adobeccstatic.com`, `adobeexchange.com`, `adobegenuine.com`, `adobegov.com`, `adobe-identity.com`, `adobejanus.com`, `adobeoobe.com`, `adobeprojectm.com`, `adobesc.com`, `adobe-services.com`, `adobess.com`, `adobesunbreak.com`.

## 10. Observed web-client hosts (dependency mapping)

- `https://account.adobe.com/`, loaded 2026-11-19 without signing in: HTTP 200, final host `account.adobe.com`.

Pass 1 is a lower bound. The proxy refuses hosts not on the allowlist ("failed" below), so hosts that only scripts from a refused host would contact are missing.

| Host | Requests (refused) | Class | Attribution today | Note |
|---|---|---|---|---|
| `account.adobe.com` | 3 (0) | app-owned | `adobe-cloud` |  |
| `www.adobe.com` | 1 (1) | app-owned | `adobe-cloud` |  |

## 11. Attributes (App-ID model) and re-verify date

- `adobe-cloud`: business-systems / office-programs, client-server; characteristics `transfers-files`, `widely-used`; **risk 2**: moves files out of the organisation; widely used by enterprises.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): ECH support unknown until a live HTTPS-record check (section 9); other modes as stated in sections 2 to 4.
- Re-verify by: **2027-02-17** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
