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
