# Microsoft Copilot (formerly Microsoft 365 Copilot and Copilot Chat)

- Content-pack id today: `ms-copilot` (`copilot.microsoft.com`)
- Status: **READY**, NAME-BASED, batch A (`research/patches/batch-a-name-based.patch`, base `claude/go-migration` `6b280a6`), for `copilot.cloud.microsoft`. Microsoft states that no complete per-feature host list exists, and in-app Copilot stays unobservable
- Implemented: content release 2026.11.3 on `claude/go-migration` (`baa07b9`); verified in the pack at `47b2743`, 2026-11-18
- Sources accessed: 2026-11-18. Page "Last updated on 11/05/2026"

## 1. What it is

Microsoft's generative-AI assistant inside Microsoft 365. Microsoft states: "Microsoft 365 Copilot is
now named Microsoft Copilot, and Microsoft 365 Copilot Chat is now named Microsoft Copilot Chat. The
primary URL for accessing the updated Copilot app is changing to copilot.cloud.microsoft" [S1].
Copilot also runs inside other apps (Teams, Outlook, Word, ...) [S1]. That in-app use travels on
those apps' own connections.

## 2. Transport and ports

- HTTPS and WebSocket Secure (WSS). Microsoft requires "full WebSocket Secure (WSS) connectivity from
  user devices running Microsoft 365 applications to these domains: `*.office.com`,
  `*.cloud.microsoft`, `copilot.cloud.microsoft`" [S1].
- Microsoft says Copilot "experiences use Microsoft 365 network connections and endpoints" [S1].
  Ports therefore follow the Microsoft 365 endpoint rows (`microsoft-365.md`; row 184, `*.cloud.microsoft`, TCP 443 and UDP 443).

## 3. Observable evidence

- **TLS SNI `copilot.cloud.microsoft`**: named by Microsoft as the Copilot app's primary URL [S1].
- `*.cloud.microsoft` and `*.office.com` are named for Copilot **and** are the Microsoft 365 suite
  domains [S1; microsoft-365.md rows 147 and 184].
- `[*.]safelinks.protection.outlook.com`: Copilot Chat checks links with Safe Links before opening them,
  which needs third-party cookies for this domain [S1]. It is Defender for Office 365 traffic, not
  Copilot traffic.
- No Copilot-specific ALPN, port or handshake structure is published. `UNVERIFIED`: any claim that
  Copilot uses a particular WebSocket host beyond the three domains above (search results mention
  `substrate.office.com`; it was not found on the primary page read here).

## 4. Encrypted-traffic caveats

- The WSS upgrade happens inside TLS [R-6455], so on the CONNECT path only the SNI is seen.
- Microsoft states: "Microsoft doesn't support allowing only selected Microsoft 365 application URLs
  within the *.cloud.microsoft domain. Allow the entire domain" [S1]. Their own guidance therefore
  treats the domain as one unit.
- In-app Copilot (Copilot in Word, Teams, Outlook) uses those apps' connections, so it is
  indistinguishable from ordinary use of the app without decryption.
- Microsoft states: "Microsoft 365 services are dynamic and don't provide a fixed list of individual
  fully qualified domain names for every Copilot feature and scenario" [S1].

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI `copilot.cloud.microsoft` | **N3** for "Copilot app" | Microsoft advises tenant restrictions instead of blocking the host "to prevent personal Microsoft account sign-in" [S1]. This lane infers that personal and work accounts reach the same name; the page does not state it outright. |
| SNI `copilot.microsoft.com` (current pack) | **U** | Not named on the primary page read. Keep it, but its provenance is unverified by this lane. |
| `*.cloud.microsoft`, `*.office.com` | **N2**, suite only | Never "Copilot". |
| Copilot inside Word, Teams, Outlook | not observable | Requires decryption (Culvert, outside this phase). |

Operator caution: reporting "Copilot use" from SNI undercounts in-app Copilot and cannot separate
licensed from personal use. Logs should say "Copilot app connection", not "Copilot use".

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `copilot.cloud.microsoft`, ALPN `h2`, `http/1.1` | Copilot application (today: unmapped) |
| P2 | SNI `copilot.microsoft.com` | `ms-copilot` (unchanged) |
| N1 | SNI `word.cloud.microsoft` (synthetic label under the suite domain) | suite (`ms-office365`), never Copilot |
| N2 | SNI `copilot.cloud.microsoft.example.invalid` | no application |
| N3 | `ech_outer()` with outer SNI `copilot.cloud.microsoft` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K and M as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `copilot.com` | one of `ms-copilot` | `ms-copilot` | PASS |
| O+ | `copilot.microsoft.com` | one of `ms-copilot` | `ms-copilot` | PASS |
| D- | `b.clarity.ms` | not ms-copilot (third party (unclassified)) | no application | PASS |
| D- | `browser.events.data.microsoft.com` | not ms-copilot (shared vendor infra) | `ms-telemetry` | PASS |
| D- | `res.cdn.office.net` | not ms-copilot (shared vendor infra) | `ms-base` | PASS |
| D- | `scripts.clarity.ms` | not ms-copilot (third party (unclassified)) | no application | PASS |
| D- | `uhf.microsoft.com` | not ms-copilot (shared vendor infra) | `ms-base` | PASS |
| D- | `wcpstatic.microsoft.com` | not ms-copilot (shared vendor infra) | `ms-base` | PASS |
| D- | `www.clarity.ms` | not ms-copilot (third party (unclassified)) | no application | PASS |
| L- | `xmicrosoft.com` | not ms-copilot (label boundary) | no application | PASS |
| L- | `copilot.microsoft.com.example.invalid` | not ms-copilot (suffix look-alike) | no application | PASS |
| L- | `xcloud.microsoft` | not ms-copilot (label boundary) | no application | PASS |
| L- | `copilot.cloud.microsoft.example.invalid` | not ms-copilot (suffix look-alike) | no application | PASS |
| L- | `xcopilot.com` | not ms-copilot (label boundary) | no application | PASS |
| L- | `copilot.com.example.invalid` | not ms-copilot (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Microsoft Learn, "Microsoft Copilot requirements",
  `https://learn.microsoft.com/en-us/copilot/plan/microsoft-copilot-requirements` (redirected from
  `https://learn.microsoft.com/en-us/microsoft-365/copilot/microsoft-365-copilot-requirements`), sections
  "Microsoft 365 and Copilot endpoints", "The cloud.microsoft domain", "WebSockets requirements",
  "Wildcards, FQDNs, and subdomains"; page "Last updated on 11/05/2026"; accessed 2026-11-18.
- [R-6455] RFC 6455 sections 1.3 and 4.1 (README, shared facts).

## 8. Catalog delta and recommendation

Exact entry in batch A (`research/patches/batch-a-name-based.patch`, base `claude/go-migration` `6b280a6`):

```python
("ms-copilot", "business-systems", "generative-ai", "browser-based", 3, "Microsoft Copilot", ("transfers-files",),
 ("copilot.microsoft.com", "copilot.cloud.microsoft")),
```

`copilot.cloud.microsoft` is longer than the suite-level `cloud.microsoft` (`ms-office365`, same batch),
so it wins. The provenance of `copilot.microsoft.com` remains unverified by this lane. Do not map
`safelinks.protection.outlook.com` to Copilot: batch A names it `ms-exchange-online-protection`.

**Patch R decision (2026-11-21, live round 2):** `copilot.com` enters `ms-copilot` at **O**. The vendor's own web client redirects there (pass 1 and pass 2), and its certificate's subject organisation is **Microsoft Corporation** (issuer Microsoft Corporation). That meets Hermes's decision 3 (ownership by certificate subject).

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 and 4 of 2026-11-21 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `research/live-results-2026-11-21-r4.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `copilot.microsoft.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `copilot.microsoft.com`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation); CNAME into shared front end `copilot.microsoft.com.cdn.cloudflare.net`: name usable, IPs never; HTTPS record offers `h3` (QUIC path) |
| `copilot.cloud.microsoft` | **L** resolves; TLSv1.3, ALPN `h2`, cert `copilot.cloud.microsoft`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation) |
| `copilot.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `copilot.com`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation) |

## 10. Observed web-client hosts (dependency mapping)

- `https://copilot.microsoft.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `copilot.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `b.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `browser.events.data.microsoft.com` | seen | shared vendor infra | `ms-telemetry` | not checked |  |
| `copilot.com` | seen | app-owned | `ms-copilot` |  |  |
| `copilot.microsoft.com` | seen | app-owned | `ms-copilot` | cdn,h3 |  |
| `res.cdn.office.net` | seen | shared vendor infra | `ms-base` | cdn,h3 |  |
| `scripts.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `uhf.microsoft.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `wcpstatic.microsoft.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `www.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `ms-copilot`: business-systems / generative-ai, browser-based; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `b.clarity.ms`, `ms-base`, `ms-telemetry`, `scripts.clarity.ms`, `www.clarity.ms`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `copilot.microsoft.com`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
