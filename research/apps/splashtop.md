# Splashtop

- Content-pack id today: `splashtop` (`splashtop.com`; web fronts apex and `www`)
- Status: **READY**, NAME, batch G (`research/patches/batch-g-name-based.patch`)
- Sources: read by Hermes, relayed, 2026-11-19; the page shows "Today, 11:24 AM" (2026-11-19)

## 1. What it is

Remote access and remote support ("all Splashtop Cloud-based solutions").

## 2. Transport and ports

Required: "Port 443 (TCP) Primary control channel & data relay". Optional: TCP 6783 for same-network direct connections; TCP 9527-9528 local loopback only; "Port 3479 (UDP) & All UDP ports. Splashtop uses QUIC for optimized end-to-end connections". Port 80 (HTTP) for downloads and update checks from CloudFront. "All Splashtop Cloud traffic is outbound only." [S1]

## 3. Observable evidence

Domains [S1]: all regions `*.api.splashtop.com` (API and session services), `*.relay.splashtop.com` (data relay), `update.splashtop.com` and `update-g3.splashtop.com` (auto-updates); EU `*.api.splashtop.eu`; OC `*.api.splashtop.nr`; for China, also `*.api.splashtop.cn` and `*.relay.splashtop.cn`. Installers and updates are hosted on Amazon CloudFront. "Splashtop remote connections use TLS over port 443" and "Splashtop supports RSA-based certificates only".

## 4. Encrypted-traffic caveats

Only the listed subtrees are proposed for the `.eu`, `.nr` and `.cn` domains (`api.splashtop.eu`, `api.splashtop.nr`, `api.splashtop.cn`, `relay.splashtop.cn`), not their apexes, which the page does not list. CloudFront download hosts are not named on the page and stay unattributed. The end-to-end QUIC path on UDP 3479 is not on UDP 443; whether its Initial carries a Splashtop server name is `UNVERIFIED`.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `splashtop.com` | **N3** | Already mapped |
| SNI under `api.splashtop.eu`, `api.splashtop.nr`, `api.splashtop.cn`, `relay.splashtop.cn` | **N3** |  |
| UDP 3479 QUIC | **U** | Not verified |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D, E, F and G): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `st-1.api.splashtop.eu`, `a.api.splashtop.nr`, `a.relay.splashtop.cn` | `splashtop` (today unmapped) |
| P2 | SNI `update-g3.splashtop.com` | `splashtop` |
| N1 | SNI `www.splashtop.eu` | unmapped (apex not listed) |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K and M as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `asset-g3.splashtop.com` | one of `splashtop` | `splashtop` | PASS |
| O+ | `files.splashtop.com` | one of `splashtop` | `splashtop` | PASS |
| O+ | `my.splashtop.com` | one of `splashtop` | `splashtop` | PASS |
| O+ | `rs-api.splashtop.com` | one of `splashtop` | `splashtop` | PASS |
| O+ | `rs-cdn.splashtop.com` | one of `splashtop` | `splashtop` | PASS |
| O+ | `rs-dataplane.splashtop.com` | one of `splashtop` | `splashtop` | PASS |
| O+ | `support-splashtopbusiness.splashtop.com` | one of `splashtop` | `splashtop` | PASS |
| O+ | `support-splashtoppersonal.splashtop.com` | one of `splashtop` | `splashtop` | PASS |
| O+ | `support-whiteboard.splashtop.com` | one of `splashtop` | `splashtop` | PASS |
| D- | `ad.doubleclick.net` | not splashtop (third party) | `google-ads` | PASS |
| D- | `bat.bing.com` | not splashtop (shared vendor infra) | `ms-base` | PASS |
| D- | `bat.bing.net` | not splashtop (shared vendor infra) | `ms-base` | PASS |
| D- | `cmp.osano.com` | not splashtop (third party (unclassified)) | no application | PASS |
| D- | `cta-service-cms2.hubspot.com` | not splashtop (third party) | `hubspot` | PASS |
| D- | `d.impct.site` | not splashtop (third party (unclassified)) | no application | PASS |
| D- | `fonts.gstatic.com` | not splashtop (shared vendor infra) | `google-base` | PASS |
| D- | `js.hs-banner.com` | not splashtop (third party (unclassified)) | no application | PASS |
| D- | `js.hs-scripts.com` | not splashtop (third party (unclassified)) | no application | PASS |
| D- | `js.hubspot.com` | not splashtop (third party) | `hubspot` | PASS |
| D- | `perf-na1.hsforms.com` | not splashtop (third party (unclassified)) | no application | PASS |
| D- | `utt.impactcdn.com` | not splashtop (third party (unclassified)) | no application | PASS |
| D- | `www.google.com` | not splashtop (shared vendor infra) | `google-base` | PASS |
| D- | `www.googletagmanager.com` | not splashtop (third party) | `google-analytics` | PASS |
| D- | `www.gstatic.com` | not splashtop (shared vendor infra) | `google-base` | PASS |
| D- | `www.recaptcha.net` | not splashtop (third party (unclassified)) | no application | PASS |
| L- | `xsplashtop.com` | not splashtop (label boundary) | no application | PASS |
| L- | `splashtop.com.example.invalid` | not splashtop (suffix look-alike) | no application | PASS |
| L- | `xsplashtop.eu` | not splashtop (label boundary) | no application | PASS |
| L- | `api.splashtop.eu.example.invalid` | not splashtop (suffix look-alike) | no application | PASS |
| L- | `xsplashtop.nr` | not splashtop (label boundary) | no application | PASS |
| L- | `api.splashtop.nr.example.invalid` | not splashtop (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Splashtop Business Support, "What Are the Firewall Exceptions and IP addresses of Splashtop Servers/Services?", `https://support-splashtopbusiness.splashtop.com/hc/en-us/articles/115001811966-What-Are-the-Firewall-Exceptions-and-IP-addresses-of-Splashtop-Servers-Services`, read by Hermes, relayed, 2026-11-19.

## 8. Catalog delta and recommendation

```python
("splashtop", ..., ("splashtop.com", "api.splashtop.eu", "api.splashtop.nr", "api.splashtop.cn", "relay.splashtop.cn"), ("splashtop.com", "www.splashtop.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `splashtop.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.splashtop.com`, no subject organisation (domain-validated) (issuer Amazon) |
| `api.splashtop.eu` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `api.splashtop.nr` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `api.splashtop.cn` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `relay.splashtop.cn` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |

## 10. Observed web-client hosts (dependency mapping)

- `https://my.splashtop.com/login`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `my.splashtop.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `ad.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `asset-g3.splashtop.com` | seen | app-owned | `splashtop` | not checked |  |
| `bat.bing.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `bat.bing.net` | seen | shared vendor infra | `ms-base` | not checked |  |
| `cmp.osano.com` | seen | third party (unclassified) | no application | not checked |  |
| `cta-service-cms2.hubspot.com` | seen | third party | `hubspot` | not checked |  |
| `d.impct.site` | seen | third party (unclassified) | no application | not checked |  |
| `files.splashtop.com` | seen | app-owned | `splashtop` | not checked |  |
| `fonts.gstatic.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `js.hs-banner.com` | seen | third party (unclassified) | no application | not checked |  |
| `js.hs-scripts.com` | seen | third party (unclassified) | no application | not checked |  |
| `js.hubspot.com` | seen | third party | `hubspot` | not checked |  |
| `my.splashtop.com` | seen | app-owned | `splashtop` | not checked |  |
| `perf-na1.hsforms.com` | seen | third party (unclassified) | no application | not checked |  |
| `rs-api.splashtop.com` | seen | app-owned | `splashtop` | not checked |  |
| `rs-cdn.splashtop.com` | seen | app-owned | `splashtop` | not checked |  |
| `rs-dataplane.splashtop.com` | seen | app-owned | `splashtop` | not checked |  |
| `support-splashtopbusiness.splashtop.com` | seen | app-owned | `splashtop` | not checked |  |
| `support-splashtoppersonal.splashtop.com` | seen | app-owned | `splashtop` | not checked |  |
| `support-whiteboard.splashtop.com` | seen | app-owned | `splashtop` | not checked |  |
| `utt.impactcdn.com` | seen | third party (unclassified) | no application | not checked |  |
| `www.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `www.googletagmanager.com` | seen | third party | `google-analytics` | not checked |  |
| `www.gstatic.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `www.recaptcha.net` | seen | third party (unclassified) | no application | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `splashtop`: networking / remote-access, client-server; characteristics `tunnels-other-applications`, `prone-to-misuse`; **risk 4**: carries other traffic or remote control; commonly misused (unsanctioned remote access, data exfiltration).
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `cmp.osano.com`, `d.impct.site`, `google-ads`, `google-analytics`, `google-base`, `hubspot`, `js.hs-banner.com`, `js.hs-scripts.com`, `ms-base`, `perf-na1.hsforms.com`, `utt.impactcdn.com`, `www.recaptcha.net`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
