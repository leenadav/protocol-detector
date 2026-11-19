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

## 7. Sources

- [S1] Miro Help Center, "Add Miro to allowed apps", `https://help.miro.com/hc/en-us/articles/360017572694-Add-Miro-to-allowed-apps`, read by Hermes, relayed, 2026-11-19.
- [S2] Miro Help Center, "Miro domains reference", `https://help.miro.com/hc/en-us/articles/20857452690706-Miro-domains-reference`, read by Hermes, relayed, 2026-11-19.

## 8. Catalog delta and recommendation

```python
("miro", ..., ("miro.com", "miro-apps.com", "mirostatic.com", "onlinewhiteboard.com", "realtimeboard.com", "webwhiteboard.com")),
```
