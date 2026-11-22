# TeamViewer

- Content-pack id today: `teamviewer` (`teamviewer.com`; web fronts `teamviewer.com`, `www.teamviewer.com`)
- Status: **DONE**, NAME-BASED: no catalog change needed. The port-5938 protocol is unpublished: no PROTOCOL item possible
- Sources accessed: 2026-11-18. Page "Last Modified: Jul 17, 2026"

## 1. What it is

A commercial remote-access, remote-support and device-management product. Same operator concern as
AnyDesk. The pack already has risk 4, `prone-to-misuse`, `used-by-malware`.

## 2. Transport and ports

As published [S1], "in order of preference":

1. "TCP/UDP port 5938", "the primary port used by TeamViewer". "Your firewall should allow outbound TCP and
   UDP traffic to `master*.teamviewer.com` and `router*.teamviewer.com`."
2. "TCP port 443", "Used if port 5938 is not allowed", and also for custom module deployment and
   update checks. "iOS apps do not use port 443."
3. "TCP port 80", "Used only as a last resort if both 5938 and 443 are unavailable."

Also: "TeamViewer 13 no longer supports TCP port 443 as a fallback connection method" [S1].
Connections are outbound from both devices "to TeamViewer servers or directly to each other
(peer-to-peer)". In peer-to-peer mode "different ports" may appear [S1].

## 3. Observable evidence

- **Host names**: "all TeamViewer IPs resolve to: `*.teamviewer.com`". "These servers use dynamic IP
  ranges, so a fixed list cannot be provided" [S1]. Named hosts: `master*.teamviewer.com`,
  `router*.teamviewer.com` (connection), `configdl.teamviewer.com` (configuration download),
  `webapi.teamviewer.com` (account assignment and API) [S1].
- **Third-party hosts** for the newer UI: `www.recaptcha.net`, `www.gstatic.com`, `cdn.cookielaw.org` [S1].
  They are not TeamViewer evidence.
- **Port 5938 wire format**: TeamViewer publishes no protocol description. `UNVERIFIED` whether
  it is TLS, and so whether the detector would see a ClientHello at all. The fallback on 443 and 80:
  also unpublished, `UNVERIFIED`.

## 4. Encrypted-traffic caveats

- Over a CONNECT proxy the client reaches the proxy on its own port. Whether TeamViewer's client
  uses a configured HTTP proxy, and which CONNECT target it asks for, is not on the page read.
  `UNVERIFIED`.
- If the 5938 or 443 transport is not TLS, the detector reports a non-TLS outcome (named-only or
  unknown), and the CONNECT target is the only name.
- `*.teamviewer.com` covers both the product and the public website (the pack's web fronts).

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI or CONNECT host `master*`/`router*.teamviewer.com` | **N3** remote session | The prefix pattern is the vendor's, and the label boundary needs care: `router5.teamviewer.com` |
| `configdl.`/`webapi.teamviewer.com` | **N2** management | Configuration and API, not a live session |
| Other `*.teamviewer.com` | **N2** | Includes the web portal and downloads |
| CONNECT to TCP 5938 | supporting fact | Port alone never names an app |

## 6. Synthetic test vectors

TLS cases only. No 5938 payload vectors can be written without a primary source:

| # | Input | Expected |
|---|---|---|
| P1 | SNI `router12.teamviewer.com` (synthetic number), TCP 443 | `teamviewer` (session) |
| P2 | SNI `webapi.teamviewer.com` | `teamviewer` |
| N1 | SNI `www.teamviewer.com` | web front |
| N2 | SNI `router12.teamviewer.com.example.invalid`, `notteamviewer.com` | no application |
| N3 | Non-TLS bytes through CONNECT to port 5938 | not identified (never named from the port) |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N and O as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `login.teamviewer.com` | one of `teamviewer` | `teamviewer` | PASS |
| O+ | `wsp.teamviewer.com` | one of `teamviewer` | `teamviewer` | PASS |
| O+ | `www.teamviewer.com` | one of `teamviewer` | `teamviewer` | PASS |
| D- | `fonts.gstatic.com` | not teamviewer (shared vendor infra) | `google-base` | PASS |
| D- | `geolocation.onetrust.com` | not teamviewer (third party) | no application | PASS |
| D- | `www.gstatic.com` | not teamviewer (shared vendor infra) | `google-base` | PASS |
| D- | `www.recaptcha.net` | not teamviewer (third party (unclassified)) | no application | PASS |
| L- | `xteamviewer.com` | not teamviewer (label boundary) | no application | PASS |
| L- | `teamviewer.com.example.invalid` | not teamviewer (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] TeamViewer Knowledge Base, "Ports and URLs used by TeamViewer",
  `https://www.teamviewer.com/en/global/support/knowledge-base/teamviewer-remote/troubleshooting/ports-used-by-teamviewer/`
  (redirected from the `teamviewer-classic` path), "Last Modified: Jul 17, 2026", accessed 2026-11-18.

## 8. Catalog delta and recommendation

1. Names: no change. `teamviewer.com` is verified.
2. Optional precision: name session hosts (`master*`, `router*`) apart from management hosts. Label
   *prefix* patterns are not part of the v0.65 matcher (whole labels only), so this would be a matcher
   change. Not recommended for the visibility phase.
3. Do not attempt a 5938 structural profile: the protocol is unpublished, and the README source policy
   forbids reconstructing it from third-party dissectors.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 5 of 2026-11-21 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `teamviewer.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.teamviewer.com`, no subject organisation (domain-validated) (issuer Sectigo Limited) |

## 10. Observed web-client hosts (dependency mapping)

- `https://login.teamviewer.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `login.teamviewer.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `fonts.gstatic.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `geolocation.onetrust.com` | seen | third party | no application | not checked | OneTrust consent geolocation |
| `login.teamviewer.com` | seen | app-owned | `teamviewer` | not checked |  |
| `wsp.teamviewer.com` | seen (some failed) | app-owned | `teamviewer` | not checked |  |
| `www.gstatic.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `www.recaptcha.net` | seen | third party (unclassified) | no application | not checked |  |
| `www.teamviewer.com` | seen | app-owned | `teamviewer` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `teamviewer`: networking / remote-access, client-server; characteristics `tunnels-other-applications`, `prone-to-misuse`, `used-by-malware`; **risk 4**: carries other traffic or remote control; commonly misused (unsanctioned remote access, data exfiltration); seen in malware campaigns.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `geolocation.onetrust.com`, `google-base`, `www.recaptcha.net`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
