# LogMeIn Resolve (formerly GoTo Resolve)

- Content-pack id today: none (`logmein` covers `logmein.com`, `logmeininc.com`)
- Status: **READY**, NAME, batch G: new id `logmein-resolve`
- Sources: read by Hermes, relayed, 2026-11-19; "Article last updated: 14 May, 2026". The requested `support.goto.com/resolve/...` URL redirected to `support.logmein.com`

## 1. What it is

Remote support, remote monitoring and management (RMM) and MDM, sold by GoTo as LogMeIn Resolve.

## 2. Transport and ports

TCP 443 for most services; `*.gotoresolve.com` also UDP 15000 (WebRTC); `turn-media.gotoresolve.com` UDP 3489 and TCP 443; `turn.gotoresolve.com` UDP 3489 (file transfer); `devices-iot.console.gotoresolve.com` TCP 8883 (Android unattended app) [S1].

## 3. Observable evidence

Required domains [S1]: `*.console.gotoresolve.com` ("cdn.console", "reporting.console", "sessions.console"), `*.gotoresolve.com`, `*.services.gotoresolve.com` ("zerotrust-frontend.services", "zerotrust.services"; RMM client downloads), `authentication.logmeininc.com` (login), `devices-iot.console.gotoresolve.com`, `helpdesk.me` ("Various Resolve services are hosted under this domain"), `logmein.com` (main site), `.mdm.gotoresolve.com`, `remoteexecution.gotoresolveuserfiles.com` (global data residency file steps), `gtre-remoteexecution-userfiles-prod-eu.azureedge.net` (EU data residency), `turn-media.gotoresolve.com`, `turn.gotoresolve.com`. GoTo Admin-specific domains: `admin.goto.com`, `api.goto.com`, `feedback.goto.com`, `iam.servers.getgo.com`, `commerce.servers.getgo.com`, `avatars.servers.getgo.com`, `admin.logmeininc.com`, `authentication.logmeininc.com`, `api.jive.com`, and third-party services (`api.segment.io`, `cdn.segment.com`, `cdn.pendo.io`, a `sentry.io` ingest host, `api-js.mixpanel.com`, `cdn.disability.illinois.edu`, `siteintercept.qualtrics.com`).

## 4. Encrypted-traffic caveats

Media goes over WebRTC and TURN on UDP 15000 and 3489, which carry no server name. TCP 8883 is the registered MQTT-over-TLS port (IANA `secure-mqtt`); a TLS ClientHello there would still carry `devices-iot.console.gotoresolve.com` as its server name (`UNVERIFIED` on traffic). The `azureedge.net` host is one exact vendor-named name on a shared CDN; the CDN itself names no application. Login (`authentication.logmeininc.com`) is shared GoTo/LogMeIn sign-in and stays `logmein`. The GoTo Admin hosts under `goto.com` and `servers.getgo.com` are for the Engine lane's vendor-level `goto` id (decided 2026-11-19) and are not in this patch; `api.jive.com` (GoTo Connect) and the third parties are not proposed. `helpdesk.me` is a generic-sounding name; the page attributes it to Resolve, with no other owner verified (N2).

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `gotoresolve.com`, `gotoresolveuserfiles.com` | **N3** |  |
| SNI `gtre-remoteexecution-userfiles-prod-eu.azureedge.net` | **N3** (exact) | EU file steps only |
| SNI under `helpdesk.me` | **N2** | Generic name; owner taken from the page only |
| `authentication.logmeininc.com` | `logmein` | Shared GoTo/LogMeIn sign-in |
| UDP 15000, 3489 | **U** | No name |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D, E, F and G): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `cdn.console.gotoresolve.com`, `devices-iot.console.gotoresolve.com` | `logmein-resolve` |
| P2 | SNI `remoteexecution.gotoresolveuserfiles.com`, `helpdesk.me` | `logmein-resolve` |
| P3 | SNI `gtre-remoteexecution-userfiles-prod-eu.azureedge.net` | `logmein-resolve` |
| N1 | SNI `other.azureedge.net` | unmapped (shared CDN) |
| N2 | SNI `authentication.logmeininc.com` | `logmein` |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R and L)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `auth.console.gotoresolve.com` | one of `logmein-resolve` | `logmein-resolve` | PASS |
| O+ | `console.gotoresolve.com` | one of `logmein-resolve` | `logmein-resolve` | PASS |
| O+ | `tdn.console.gotoresolve.com` | one of `logmein-resolve` | `logmein-resolve` | PASS |
| D- | `cdn.amplitude.com` | not logmein-resolve (third party) | `amplitude` | PASS |
| D- | `o173976.ingest.sentry.io` | not logmein-resolve (third party) | `sentry` | PASS |
| L- | `xgotoresolve.com` | not logmein-resolve (label boundary) | no application | PASS |
| L- | `gotoresolve.com.example.invalid` | not logmein-resolve (suffix look-alike) | no application | PASS |
| L- | `xgotoresolveuserfiles.com` | not logmein-resolve (label boundary) | no application | PASS |
| L- | `gotoresolveuserfiles.com.example.invalid` | not logmein-resolve (suffix look-alike) | no application | PASS |
| L- | `xhelpdesk.me` | not logmein-resolve (label boundary) | no application | PASS |
| L- | `helpdesk.me.example.invalid` | not logmein-resolve (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] LogMeIn Support, "Allowlisting and LogMeIn Resolve", `https://support.logmein.com/resolve/help/allowlisting-and-goto-resolve` (redirect target of `https://support.goto.com/resolve/help/allowlisting-and-goto-resolve`), read by Hermes, relayed, 2026-11-19.

## 8. Catalog delta and recommendation

```python
("logmein-resolve", "networking", "remote-access", "client-server", 4, "LogMeIn Resolve remote support",
 ("tunnels-other-applications", "prone-to-misuse"),
 ("gotoresolve.com", "gotoresolveuserfiles.com", "helpdesk.me", "gtre-remoteexecution-userfiles-prod-eu.azureedge.net")),
```

For the `goto` vendor id (Engine lane): the page lists `admin.goto.com`, `api.goto.com`, `feedback.goto.com` and `iam.`, `commerce.`, `avatars.servers.getgo.com` as GoTo Admin hosts.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `gotoresolve.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `www.gotoresolve.com` (SAN covers name: True) |
| `gotoresolveuserfiles.com` | apex has no address (normal for a suffix entry); documented probe `remoteexecution.gotoresolveuserfiles.com` queued for round 2 |
| `helpdesk.me` | **L** resolves; TLSv1.3, ALPN `h2`, cert `helpdesk.me` (SAN covers name: True) |
| `gtre-remoteexecution-userfiles-prod-eu.azureedge.net` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.azureedge.net` (SAN covers name: True); CNAME into shared front end `mr-afd-azuredge.tm-azurefd.net`: name usable, IPs never |

## 10. Observed web-client hosts (dependency mapping)

- `https://console.gotoresolve.com/`, loaded 2026-11-19 without signing in: HTTP 200, final host `chromewebdata`.

Pass 1 is a lower bound. The proxy refuses hosts not on the allowlist ("failed" below), so hosts that only scripts from a refused host would contact are missing.

| Host | Requests (refused) | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `auth.console.gotoresolve.com` | 1 (1) | app-owned | `logmein-resolve` |  |  |
| `cdn.amplitude.com` | 1 (1) | third party | `amplitude` | not checked |  |
| `console.gotoresolve.com` | 36 (0) | app-owned | `logmein-resolve` |  |  |
| `o173976.ingest.sentry.io` | 1 (1) | third party | `sentry` | not checked |  |
| `tdn.console.gotoresolve.com` | 1 (0) | app-owned | `logmein-resolve` | cdn |  |

## 11. Attributes (App-ID model) and re-verify date

- `logmein-resolve`: networking / remote-access, client-server; characteristics `tunnels-other-applications`, `prone-to-misuse`; **risk 4**: carries other traffic or remote control; commonly misused (unsanctioned remote access, data exfiltration).
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `amplitude`, `sentry`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
