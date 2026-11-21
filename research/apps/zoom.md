# Zoom

- Content-pack id today: `zoom` (`zoom.us`, `zoom.com`, `zoomgov.com`)
- Status: **DONE**, NAME-BASED: no catalog change needed. `zoomgov.com` provenance is unverified
- Sources accessed: 2026-11-18. Page "This article was updated 2026-10-07"

## 1. What it is

Video meetings, webinars, chat, phone and contact-centre services. It is common in enterprise
traffic and bandwidth-heavy (the pack marks it `excessive-bandwidth`).

## 2. Transport and ports

From "Zoom network firewall or proxy server settings" [S1], outbound:

| Rule set | Protocol | Ports | Destination (as published) |
|---|---|---|---|
| Firewall rules for Zoom (clients and browser) | TCP | 80, 443 | `*.zoom.us`, `*.zoom.com`, plus third-party `cdn.cookielaw.org`, `googletagmanager.com`, `gstatic.com`, `googleapis.com`, `*.hcaptcha.com` |
| same | UDP | 443 | `*.zoom.us`, `*.zoom.com` |
| Meetings and Webinars | TCP | 443, 8801, 8802 | IP ranges (for example `137.66.128.0/17`, `168.140.0.0/17`) |
| Meetings and Webinars | UDP | 3478, 3479, 8801 to 8810 | IP ranges (same) |
| Support and Community | TCP | 80, 443 | `*.zoom.us`, `*.zoom.com`, `*.zoomstatus.com` |

Zoom announces IP range changes on Zoom Status and publishes "IP ranges txt files" [S1].
"UDP port 3478 is utilized for Traversal Using Relays around NAT (TURN) support" [S1].

## 3. Observable evidence

- **SNI** under `zoom.us` or `zoom.com` on TCP 443: the client and web signalling path [S1].
- **Meeting transport** to TCP 8801/8802 or UDP 8801 to 8810: published by IP range only, with no host
  name [S1]. Over a CONNECT proxy, a client that falls back to TCP 443 is visible as TLS. Whether its
  SNI is a `zoom.us` name is `UNVERIFIED` (not on the page).
- TURN on UDP 3478 [S1] is a standard protocol the detector already recognises (`stun` family), but it
  is UDP, outside the visibility phase.
- No ALPN information is published. `UNVERIFIED`.

## 4. Encrypted-traffic caveats

- **UDP and QUIC**: UDP 443 to `*.zoom.us`/`*.zoom.com` is allowed [S1]. Such traffic, and all UDP media,
  is off the visibility-phase path.
- **Third-party hosts** on the same rule (`gstatic.com`, `googleapis.com`, `googletagmanager.com`,
  `cdn.cookielaw.org`, `*.hcaptcha.com`) belong to other operators and must not name Zoom.
- **Government cloud**: `zoomgov.com` is in the pack, but the page read here does not list it.
  `UNVERIFIED` by this lane (Zoom may document it on a separate government page, not read).

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `zoom.us`, `zoom.com` | **N3** Zoom | Includes the web portal, marketing and sign-in: "Zoom" but not "in a meeting" |
| SNI under `zoomstatus.com` | **N1** | Status page only |
| CONNECT to 8801/8802 with IP in published ranges | supporting fact | Port and IP never name an app alone |
| `zoomgov.com` | **U** | Not on the page read |

Risk: reporting "Zoom meeting" from SNI overstates. The log should say "Zoom", and meeting
media mostly bypasses the TCP proxy path.

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `us05web.zoom.us` (synthetic label), ALPN `http/1.1` | `zoom` |
| P2 | SNI `zoom.com` | `zoom` |
| N1 | SNI `www.gstatic.com` | `google-base`, never Zoom |
| N2 | SNI `zoom.us.example.invalid`, `notzoom.us` | no application |
| N3 | `ech_outer()` with outer SNI `zoom.us` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J and K as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `app.zoom.us` | one of `zoom` | `zoom` | PASS |
| O+ | `log-gateway.zoom.us` | one of `zoom` | `zoom` | PASS |
| O+ | `st1.zoom.us` | one of `zoom` | `zoom` | PASS |
| O+ | `us.telemetry.zoom.us` | one of `zoom` | `zoom` | PASS |
| O+ | `us01st-cf.zoom.us` | one of `zoom` | `zoom` | PASS |
| D- | `www.googletagmanager.com` | not zoom (third party) | `google-analytics` | PASS |
| L- | `xzoom.us` | not zoom (label boundary) | no application | PASS |
| L- | `zoom.us.example.invalid` | not zoom (suffix look-alike) | no application | PASS |
| L- | `xzoom.com` | not zoom (label boundary) | no application | PASS |
| L- | `zoom.com.example.invalid` | not zoom (suffix look-alike) | no application | PASS |
| L- | `xzoomgov.com` | not zoom (label boundary) | no application | PASS |
| L- | `zoomgov.com.example.invalid` | not zoom (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Zoom Support, "Zoom network firewall or proxy server settings" (KB0060548),
  `https://support.zoom.com/hc/en/article?id=zm_kb&sysparm_article=KB0060548`, updated 2026-10-07,
  accessed 2026-11-18 (rendered page text).

## 8. Catalog delta and recommendation

1. Names `zoom.us` and `zoom.com` are verified. No change.
2. Add `zoomstatus.com` as a web front ("provider affiliation only"), if it is wanted at all.
3. `zoomgov.com`: record as unverified until a Zoom government-cloud source is read (next batch).
4. Later phase: the published IP ranges and ports could corroborate UDP media once UDP is on the
   observed path. Not now.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `zoom.us` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.zoom.us`, subject organisation **Zoom Communications, Inc.** (issuer DigiCert Inc) |
| `zoom.com` | **L** resolves; TLSv1.2, ALPN `http/1.1`, cert `*.zoom.com`, subject organisation **Zoom Communications, Inc.** (issuer DigiCert Inc) |
| `zoomgov.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.zoomgov.com`, subject organisation **Zoom Communications, Inc.** (issuer DigiCert Inc) |

## 10. Observed web-client hosts (dependency mapping)

- `https://app.zoom.us/wc`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `app.zoom.us`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `app.zoom.us` | seen | app-owned | `zoom` |  |  |
| `log-gateway.zoom.us` | seen | app-owned | `zoom` | not checked |  |
| `st1.zoom.us` | seen | app-owned | `zoom` |  |  |
| `us.telemetry.zoom.us` | seen | app-owned | `zoom` | not checked |  |
| `us01st-cf.zoom.us` | seen | app-owned | `zoom` |  |  |
| `www.googletagmanager.com` | seen | third party | `google-analytics` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `zoom`: collaboration / voip-video, client-server; characteristics `widely-used`, `excessive-bandwidth`; **risk 2**: widely used by enterprises; high bandwidth.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `google-analytics`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
