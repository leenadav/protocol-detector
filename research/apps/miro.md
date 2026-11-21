# Miro

- Content-pack id today: `miro` (`miro.com`)
- Status: **READY**, NAME, batch G (`research/patches/batch-g-name-based.patch`)
- Sources: read by Hermes, relayed, 2026-11-19; the pages show no date

## 1. What it is

Online whiteboard and visual collaboration.

## 2. Transport and ports

"The Miro application - specifically the board pages - requires WebSocket connections" on "port 80 and 443 (SSL)". Proxy notes: "Destination port: 443 (SSL)", "Protocol: HTTPS", "TLS: 1.2. (We're hosted in AWS and use AWS Security Policies...)" [S1].

## 3. Observable evidence

"Miro domains reference" [S2], global production domains: `*.miro.com` ("Include derivatives, for example: *.api.miro.com | *.svc.miro.com"), `*.miro-apps.com`, `mirostatic.com`, `*.mirostatic.com`, `onlinewhiteboard.com`, `realtimeboard.com`, `*.realtimeboard.com`, `webwhiteboard.com`. Regional: `*.au.miro.com`, `*.au01.miro.com`, `*.jp.miro.com`, `*.jp01.miro.com`, `*.us.miro.com`, `*.us01.miro.com` (all under `miro.com`). Production tooling domains are third-party services (`api.stigg.io`, `braze.eu`, `browser.sentry-cdn.io`, `cdn.cookielaw.org`, `fonts.googleapis.com`, `fonts.gstatic.com`, `miroapp.github.io`, `realtimeboardhelp.zendesk.com`, `*.sentry.io`, `split.io`).

## 4. Encrypted-traffic caveats

Third-party tooling domains are not proposed. `realtimeboardhelp.zendesk.com` and `miroapp.github.io` are vendor-named hosts on shared platforms (Zendesk help desk, GitHub Pages); they are support and docs pages, not the product, so they stay with their platforms. The page notes that apps built for Miro "may rely on external domains"; `miro-apps.com` is listed by Miro as its own production domain. The proxy note says Miro uses TLS 1.2, so the TLS 1.2 ServerHello profile applies to its servers (see `protocol/tls-serverhello-legacy.md`).

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `miro.com` | **N3** | Already mapped |
| SNI under `miro-apps.com`, `mirostatic.com`, `realtimeboard.com`, `onlinewhiteboard.com`, `webwhiteboard.com` | **N3** | `onlinewhiteboard.com` and `webwhiteboard.com` are listed as exact names; suffix matching also covers their subdomains |
| `realtimeboardhelp.zendesk.com` | not Miro | Stays `zendesk` |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D, E, F and G): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `x.miro-apps.com`, `mirostatic.com`, `realtimeboard.com`, `webwhiteboard.com`, `onlinewhiteboard.com` | `miro` (today unmapped) |
| P2 | SNI `api.us.miro.com` | `miro` |
| N1 | SNI `realtimeboardhelp.zendesk.com` | `zendesk` |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K and M as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `eventhub.eu01.miro.com` | one of `miro` | `miro` | PASS |
| O+ | `miro.com` | one of `miro` | `miro` | PASS |
| O+ | `mirostatic.com` | one of `miro` | `miro` | PASS |
| O+ | `static-website.miro.com` | one of `miro` | `miro` | PASS |
| D- | `accounts.google.com` | not miro (shared vendor infra) | `google-accounts` | PASS |
| D- | `appleid.cdn-apple.com` | not miro (shared vendor infra) | `apple-base` | PASS |
| D- | `fonts.gstatic.com` | not miro (shared vendor infra) | `google-base` | PASS |
| D- | `google.com` | not miro (shared vendor infra) | `google-base` | PASS |
| D- | `widget.intercom.io` | not miro (third party) | `intercom` | PASS |
| D- | `www.google.com` | not miro (shared vendor infra) | `google-base` | PASS |
| D- | `www.gstatic.com` | not miro (shared vendor infra) | `google-base` | PASS |
| L- | `xmiro.com` | not miro (label boundary) | no application | PASS |
| L- | `miro.com.example.invalid` | not miro (suffix look-alike) | no application | PASS |
| L- | `xmiro-apps.com` | not miro (label boundary) | no application | PASS |
| L- | `miro-apps.com.example.invalid` | not miro (suffix look-alike) | no application | PASS |
| L- | `xmirostatic.com` | not miro (label boundary) | no application | PASS |
| L- | `mirostatic.com.example.invalid` | not miro (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Miro Help Center, "Add Miro to allowed apps", `https://help.miro.com/hc/en-us/articles/360017572694-Add-Miro-to-allowed-apps`, read by Hermes, relayed, 2026-11-19.
- [S2] Miro Help Center, "Miro domains reference", `https://help.miro.com/hc/en-us/articles/20857452690706-Miro-domains-reference`, read by Hermes, relayed, 2026-11-19.

## 8. Catalog delta and recommendation

```python
("miro", ..., ("miro.com", "miro-apps.com", "mirostatic.com", "onlinewhiteboard.com", "realtimeboard.com", "webwhiteboard.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and round 4 of 2026-11-21 where it has the name (`research/live-results-2026-11-21-r4.tsv`, partial relay; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `miro.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `miro.com`, no subject organisation (domain-validated) (issuer Amazon); HTTPS record offers `h3` (QUIC path) |
| `miro-apps.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `mirostatic.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `mirostatic.com`, no subject organisation (domain-validated) (issuer Amazon); HTTPS record offers `h3` (QUIC path) |
| `onlinewhiteboard.com` | resolves; TLS handshake failed (TimeoutError) in both rounds where checked: not a removal reason |
| `realtimeboard.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `digital-twin-mcp.eu01.miro.com`, no subject organisation (domain-validated) (issuer Amazon) |
| `webwhiteboard.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `digital-twin-mcp.eu01.miro.com`, no subject organisation (domain-validated) (issuer Amazon) |

## 10. Observed web-client hosts (dependency mapping)

- `https://miro.com/login/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `miro.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `accounts.google.com` | seen | shared vendor infra | `google-accounts` |  |  |
| `appleid.cdn-apple.com` | seen | shared vendor infra | `apple-base` | not checked |  |
| `eventhub.eu01.miro.com` | seen | app-owned | `miro` | not checked |  |
| `fonts.gstatic.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `miro.com` | seen | app-owned | `miro` | h3 |  |
| `mirostatic.com` | seen | app-owned | `miro` | h3 |  |
| `static-website.miro.com` | seen | app-owned | `miro` | not checked |  |
| `widget.intercom.io` | seen | third party | `intercom` | not checked |  |
| `www.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `www.gstatic.com` | seen | shared vendor infra | `google-base` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `miro`: business-systems / office-programs, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `apple-base`, `google-accounts`, `google-base`, `intercom`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `miro.com`, `mirostatic.com`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
