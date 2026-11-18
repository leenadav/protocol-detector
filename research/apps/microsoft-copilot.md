# Microsoft Copilot (formerly Microsoft 365 Copilot and Copilot Chat)

- Content-pack id today: `ms-copilot` (`copilot.microsoft.com`)
- Status: **READY**, NAME-BASED, batch A (`research/patches/batch-a-name-based.patch`, base `claude/go-migration` `6b280a6`), for `copilot.cloud.microsoft`. Microsoft states that no complete per-feature host list exists, and in-app Copilot stays unobservable
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
