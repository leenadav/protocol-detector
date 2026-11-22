# Microsoft 365 (Exchange Online, SharePoint/OneDrive for Business, Teams, Office)

- Content-pack ids today: `ms-office365`, `outlook-web`, `sharepoint-online`, `ms-teams`, `ms-onedrive`, `azure-ad`, `skype`, `ms-base`
- Status: **READY**, NAME-BASED, batch A (`research/patches/batch-a-name-based.patch`, base `claude/go-migration` `6b280a6`). Teams media over UDP is recorded for a later phase only
- Implemented: content release 2026.11.3 on `claude/go-migration` (`baa07b9`); verified in the pack at `47b2743`, 2026-11-18
- Sources accessed: 2026-11-18. Endpoint data version `2026103000` (worldwide instance)

## 1. What it is

Microsoft's hosted productivity suite: Exchange Online (mail, calendar), SharePoint Online and
OneDrive for Business (file storage and sharing), Teams (chat, meetings, calling), the Office web and
desktop apps, and the Microsoft Entra sign-in they all depend on. Microsoft publishes its network
endpoints as a machine-readable web service, grouped into **service areas** (`Exchange`, `SharePoint`,
`Skype` = Teams, `Common`) and **categories** (`Optimize`, `Allow`, `Default`) [S1, S2].

## 2. Transport and ports

From the endpoint web service, worldwide, version 2026103000 [S1, S3]:

| id | Service area | Category | TCP | UDP | Host names (as published) |
|---|---|---|---|---|---|
| 1 | Exchange | Optimize | 80, 443 | 443 | `outlook.cloud.microsoft`, `outlook.office.com`, `outlook.office365.com` |
| 2 | Exchange | Allow (not required) | 143, 587, 993, 995 | | `outlook.office365.com`, `smtp.office365.com` (note: "POP3, IMAP4, SMTP Client traffic") |
| 8 | Exchange | Default | 80, 443 | | `*.outlook.com`, `autodiscover.*.onmicrosoft.com` |
| 9 | Exchange | Allow | 443 | | `*.protection.outlook.com` |
| 10 | Exchange | Allow | 25 | | `*.mail.protection.outlook.com`, `*.mx.microsoft` |
| 11 | Skype (Teams) | Optimize | | 3478, 3479, 3480, 3481 | IP ranges only, no host names |
| 12 | Skype (Teams) | Allow | 80, 443 | 443 | `*.lync.com`, `*.teams.cloud.microsoft`, `*.teams.microsoft.com`, `teams.cloud.microsoft`, `teams.microsoft.com` |
| 127 | Skype (Teams) | Default | 80, 443 | | `*.skype.com` |
| 31 | SharePoint | Optimize | 80, 443 | 443 | `*.sharepoint.com` |
| 32 | SharePoint | Default (not required) | 443 | | `storage.live.com` (note: OneDrive for Business supportability, telemetry, APIs, embedded links) |
| 37 | SharePoint | Default | 80, 443 | | `*.sharepointonline.com`, `spoprod-a.akamaihd.net` |
| 39 | SharePoint | Default | 80, 443 | | `*.svc.ms` |
| 46 | Common | Allow | 80, 443 | | `*.officeapps.live.com`, `*.online.office.com`, `office.live.com` |
| 47 | Common | Default | 80, 443 | 443 | `*.office.net` |
| 56 | Common | Allow | 80, 443 | | 22 sign-in and directory hosts, among them `login.microsoftonline.com`, `login.microsoft.com`, `login.windows.net`, `*.auth.microsoft.com`, `*.msftidentity.com`, `graph.microsoft.com` |
| 147 | Common | Default | 80, 443 | | `*.office.com`, `www.microsoft365.com` |
| 184 | Common | Default | 443 | 443 | `*.cloud.microsoft` |
| 193 | Common | Default | 443 | 443 | `*.static.microsoft`, `*.usercontent.microsoft` |
| 50, 78 | Common | Default (not required) | 80, 443 | | `*.microsoft.com`, `*.msocdn.com`, `*.onmicrosoft.com` (note on 78: "Some Office 365 features require endpoints within these domains (including CDNs)") |
| 125 | Common | Default | 80, 443 | | public CA CRL/OCSP hosts (`*.digicert.com`, `crl.globalsign.com`, ...) |

UDP 443 appears on the Optimize/Allow web rows (1, 12, 31) and on 47, 184 and 193. That traffic is
QUIC and is outside the visibility phase. The Teams media ports (id 11, UDP 3478 to 3481) are
published only as IP ranges [S1].

## 3. Observable evidence

- **TLS SNI** on TCP 443 is the main evidence. The table above is the authoritative name set. The
  web service defines `category` as "the connectivity category for the endpoint set" with the valid
  values `Optimize`, `Allow` and `Default`, and says to follow the highest-priority category when an
  address appears in several [S2]. The category is a routing priority, not a statement of how
  specific a name is, so it is not used to set confidence here.
- **ALPN**: Microsoft publishes no ALPN guidance. The registry values `h2` and `http/1.1` [R-IANA]
  say nothing specific to Microsoft and are not evidence of the application.
- **Ports 143/993/995/587 to `outlook.office365.com` and `smtp.office365.com`** (id 2): the detector
  already identifies IMAP, POP3 and SMTP structurally (family `S`). Inside a CONNECT tunnel the
  SMTP/IMAP greeting plus the proxy's CONNECT target gives Exchange Online client mail. SMTP is in
  the visibility-phase profile; IMAP and POP3 are "next candidates" in the working plan.
- **Certificate names**: not visible in TLS 1.3 [R-8446]. In TLS 1.2 the detector's certificate
  watch could read them, but Microsoft publishes no certificate SAN list, so a SAN match would be
  `UNVERIFIED`.
- **DNS**: the published names are what a client resolves. The proxy sees the CONNECT host, not DNS.

## 4. Encrypted-traffic caveats

- **QUIC**: several rows allow UDP 443 [S1]. A client that moves to QUIC leaves the TCP path the
  visibility phase observes.
- **ECH**: Microsoft publishes nothing on ECH. If an outer ClientHello is ever seen, the catalog
  rule already refuses to map it (PROTOCOLS.md v0.65).
- **Shared infrastructure**: rows 50 and 78 list `*.microsoft.com` and `*.onmicrosoft.com` as
  Microsoft 365 dependencies, but those wildcards also serve unrelated Microsoft products. `*.cloud.microsoft`
  (184) carries several Microsoft 365 apps at once (see `microsoft-copilot.md`). `spoprod-a.akamaihd.net`
  (37) is a host on a shared CDN domain.
- **Tenant names**: `<tenant>.sharepoint.com` and `autodiscover.<tenant>.onmicrosoft.com` contain the
  customer's tenant label. The application name may be logged; the tenant label is an opaque
  identifier and must not be emitted as identity (AGENTS.md).

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `sharepoint.com`, `outlook.office365.com`, `outlook.office.com`, `outlook.cloud.microsoft`, `teams.microsoft.com`, `teams.cloud.microsoft`, `lync.com` | **N3** | Vendor-published, product-specific. A client can still assert any SNI (domain fronting); the SNI is an offer. |
| SNI under `office.com`, `office.net`, `officeapps.live.com`, `cloud.microsoft` | **N2** | Shared by several Microsoft 365 apps. This names the suite, not one app. |
| `*.protection.outlook.com` | **N2** (Exchange Online Protection) | Not mailbox access. Today it falls under `outlook.com` and is named `outlook-web` (section 8). |
| `*.microsoft.com`, `*.onmicrosoft.com`, `*.msocdn.com`, CA CRL/OCSP | **N1**, do not map | Shared with all of Microsoft and with public CAs. |
| UDP 3478 to 3481 to published ranges (Teams media) | **N1**, later phase | IP ranges only. STUN on those ports is also used by unrelated WebRTC services. |

Risk: `*.outlook.com` (row 8) covers both consumer Outlook.com and Exchange Online. Row 97 lists
`login.live.com` and `account.live.com` as the *consumer* Outlook.com integration. Personal and
corporate mail cannot be told apart by SNI alone. `UNVERIFIED`: no Microsoft source separates them
by host name.

## 6. Synthetic test vectors

Built with `client_hello_with([...])` (server_name ext 0, ALPN ext 16), TCP 443 unless stated:

| # | Input | Expected |
|---|---|---|
| P1 | SNI `contoso.sharepoint.com`, ALPN `h2` | `sharepoint-online`; the tenant label must not appear in evidence or reasons |
| P2 | SNI `outlook.cloud.microsoft` | Exchange Online web (today: no mapping; see section 8) |
| P3 | SNI `teams.cloud.microsoft` | `ms-teams` (today: no mapping) |
| P4 | SNI `eur.protection.outlook.com` | Exchange Online Protection (today: `outlook-web`) |
| P5 | SMTP greeting then `EHLO` through CONNECT to `smtp.office365.com:587` | family `smtp`; application only from the proxy's CONNECT target, never from the greeting text |
| N1 | SNI `sharepoint.com.example.invalid` | no Microsoft application (label boundary) |
| N2 | SNI `notsharepoint.com` | no Microsoft application |
| N3 | `ech_outer()` ClientHello with outer SNI `outlook.cloud.microsoft` | no application (ECH outer rule) |
| N4 | SNI `www.microsoft.com` | `ms-base` only, never a Microsoft 365 app |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N and O as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `config.teams.microsoft.com` | one of `ms-office365`, `ms-teams`, `outlook-web`, `sharepoint-online` | `ms-teams` | PASS |
| O+ | `m365.cloud.microsoft` | one of `ms-office365`, `ms-teams`, `outlook-web`, `sharepoint-online` | `ms-office365` | PASS |
| O+ | `teams.microsoft.com` | one of `ms-office365`, `ms-teams`, `outlook-web`, `sharepoint-online` | `ms-teams` | PASS |
| O+ | `www.office.com` | one of `ms-office365`, `ms-teams`, `outlook-web`, `sharepoint-online` | `ms-office365` | PASS |
| D- | `aadcdn.msauth.net` | not ms-office365/ms-teams/outlook-web/sharepoint-online (shared vendor infra (unmapped)) | no application | PASS |
| D- | `admin.microsoft.com` | not ms-office365/ms-teams/outlook-web/sharepoint-online (shared vendor infra) | `ms-base` | PASS |
| D- | `browser.events.data.microsoft.com` | not ms-office365/ms-teams/outlook-web/sharepoint-online (shared vendor infra) | `ms-telemetry` | PASS |
| D- | `config.edge.skype.com` | not ms-office365/ms-teams/outlook-web/sharepoint-online (third party) | `skype` | PASS |
| D- | `e.clarity.ms` | not ms-office365/ms-teams/outlook-web/sharepoint-online (third party (unclassified)) | no application | PASS |
| D- | `eu-mobile.events.data.microsoft.com` | not ms-office365/ms-teams/outlook-web/sharepoint-online (shared vendor infra) | `ms-telemetry` | PASS |
| D- | `login.live.com` | not ms-office365/ms-teams/outlook-web/sharepoint-online (shared vendor infra) | `azure-ad` | PASS |
| D- | `login.microsoftonline.com` | not ms-office365/ms-teams/outlook-web/sharepoint-online (shared vendor infra) | `azure-ad` | PASS |
| D- | `res.cdn.office.net` | not ms-office365/ms-teams/outlook-web/sharepoint-online (shared vendor infra) | `ms-base` | PASS |
| D- | `scripts.clarity.ms` | not ms-office365/ms-teams/outlook-web/sharepoint-online (third party (unclassified)) | no application | PASS |
| D- | `teams.events.data.microsoft.com` | not ms-office365/ms-teams/outlook-web/sharepoint-online (shared vendor infra) | `ms-telemetry` | PASS |
| D- | `teams.public.onecdn.static.microsoft` | not ms-office365/ms-teams/outlook-web/sharepoint-online (shared vendor infra) | `ms-base` | PASS |
| D- | `uhf.microsoft.com` | not ms-office365/ms-teams/outlook-web/sharepoint-online (shared vendor infra) | `ms-base` | PASS |
| D- | `wcpstatic.microsoft.com` | not ms-office365/ms-teams/outlook-web/sharepoint-online (shared vendor infra) | `ms-base` | PASS |
| D- | `www.clarity.ms` | not ms-office365/ms-teams/outlook-web/sharepoint-online (third party (unclassified)) | no application | PASS |
| L- | `xoffice.com` | not ms-office365/ms-teams/outlook-web/sharepoint-online (label boundary) | no application | PASS |
| L- | `office.com.example.invalid` | not ms-office365/ms-teams/outlook-web/sharepoint-online (suffix look-alike) | no application | PASS |
| L- | `xoffice365.com` | not ms-office365/ms-teams/outlook-web/sharepoint-online (label boundary) | no application | PASS |
| L- | `office365.com.example.invalid` | not ms-office365/ms-teams/outlook-web/sharepoint-online (suffix look-alike) | no application | PASS |
| L- | `xoffice.net` | not ms-office365/ms-teams/outlook-web/sharepoint-online (label boundary) | no application | PASS |
| L- | `office.net.example.invalid` | not ms-office365/ms-teams/outlook-web/sharepoint-online (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Microsoft 365 endpoints web service, worldwide instance:
  `https://endpoints.office.com/endpoints/worldwide?clientrequestid=<uuid>` (JSON; ids, service areas,
  categories, ports, URLs and notes quoted above), accessed 2026-11-18.
- [S2] Microsoft Learn, "Microsoft 365 IP Address and URL web service":
  `https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service?view=o365-worldwide`,
  accessed 2026-11-18 (describes the service, instances, categories and versioning).
- [S3] Version endpoint `https://endpoints.office.com/version/worldwide?clientrequestid=<uuid>` returned
  `{"instance":"Worldwide","serviceArea":"O365Default","latest":"2026103000"}`, accessed 2026-11-18.
- [R-8446] RFC 8446 section 2. [R-IANA] IANA ALPN Protocol IDs. (See README, shared facts.)

## 8. Catalog delta and recommendation

| Name (published) | Current pack | Proposed |
|---|---|---|
| `outlook.cloud.microsoft` (id 1) | unmapped (no `cloud.microsoft` suffix) | add, `outlook-web` |
| `teams.cloud.microsoft` (id 12) | unmapped | add, `ms-teams` |
| `lync.com` (id 12) | unmapped | add, `ms-teams` (Teams service area) |
| `protection.outlook.com` (id 9, 10) | falls under `outlook.com` and is named `outlook-web` | add a longer suffix that names Exchange Online Protection (new id, or no app). Port 25 MX traffic is server-to-server, not webmail |
| `sharepointonline.com`, `svc.ms` (ids 37, 39) | unmapped | add, `sharepoint-online` |
| `microsoft365.com` (id 147) | unmapped | add, `ms-office365` |
| `onmicrosoft.com`, `microsoft.com`, `msocdn.com` (50, 78) | `microsoft.com` is `ms-base` | keep as is: too broad to name Microsoft 365 |
| `cloud.microsoft` (184) | unmapped | add as `ms-office365` (suite level, N2), so that the longer `outlook.`/`teams.`/`copilot.` entries win |

Exact entries in batch A (`research/patches/batch-a-name-based.patch`, base `claude/go-migration` `6b280a6`):

```python
("ms-teams", ..., ("teams.microsoft.com", "teams.live.com", "teams.cdn.office.net", "teams.cloud.microsoft", "lync.com")),
("outlook-web", ..., ("outlook.office365.com", "outlook.office.com", "outlook.live.com", "outlook.com", "outlook.cloud.microsoft")),
("ms-exchange-online-protection", "collaboration", "email", "client-server", 1,
 "Microsoft Exchange Online Protection (mail filtering, Safe Links)", ("widely-used",),
 ("protection.outlook.com", "mx.microsoft")),
("ms-office365", ..., ("office.com", "office365.com", "office.net", "officeapps.live.com", "microsoft365.com", "cloud.microsoft")),
("sharepoint-online", ..., ("sharepoint.com", "sharepointonline.com", "svc.ms")),
```

`...` stands for the unchanged fields of the existing tuple. The patch has them in full. The metadata of
the new `ms-exchange-online-protection` (risk 1, `widely-used`, `client-server`) is this lane's proposal;
the Engine lane may adjust it.

Process note for the Engine lane: the web service is versioned and machine-readable [S2]. The catalog
could record the data version it was built from (here `2026103000`) as its provenance, instead of
the current generic "operator-owned-domain" basis.

**Decision applied (2026-11-20, Hermes decision 4):** `cdn.office.net` is shared Microsoft asset infrastructure.
Third-party pages load it: GoTo's web app loads `res.cdn.office.net`, whose CNAME goes into Akamai (`edgesuite.net`)
and whose certificate is `*.public.cdn.office.net`. Patch L moves `cdn.office.net` to the vendor-level `ms-base`.
`teams.cdn.office.net` stays `ms-teams` (longer suffix), and the rest of `office.net` stays `ms-office365`.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 5 of 2026-11-21 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `office.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `m365.cloud.microsoft`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation) |
| `office365.com` | **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `akaoffice.trafficmanager.net`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation) |
| `office.net` | apex has no address (normal for a suffix entry); suffix **verified** through documented `res.cdn.office.net` (round 2, cdn,h3) |
| `officeapps.live.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `officeapps.live.com`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation); CNAME into shared front end `wac-0003.wac-msedge.net`: name usable, IPs never |
| `microsoft365.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `m365.cloud.microsoft`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation) |
| `cloud.microsoft` | **L** resolves; TLSv1.3, ALPN `h2`, cert `cloud.microsoft`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation) |
| `teams.microsoft.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `teams.microsoft.com`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation) |
| `teams.live.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `teams.live.com`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation) |
| `teams.cdn.office.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `teams.cloud.microsoft` | **L** resolves; TLSv1.3, ALPN `h2`, cert `teams.cloud.microsoft`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation) |
| `lync.com` | resolves; TLS handshake failed (SSLCertVerificationError) in both rounds where checked: not a removal reason |
| `outlook.office365.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `outlook.com`, subject organisation **Microsoft Corporation** (issuer DigiCert Inc) |
| `outlook.office.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `outlook.com`, subject organisation **Microsoft Corporation** (issuer DigiCert Inc) |
| `outlook.live.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `outlook.com`, subject organisation **Microsoft Corporation** (issuer DigiCert Inc) |
| `outlook.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `outlook.com`, subject organisation **Microsoft Corporation** (issuer DigiCert Inc) |
| `outlook.cloud.microsoft` | **L** resolves; TLSv1.3, ALPN `h2`, cert `outlook.cloud.microsoft`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation) |
| `sharepoint.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `svc.ms`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation) |
| `sharepointonline.com` | resolves; TLS handshake failed (TimeoutError) in both rounds where checked: not a removal reason |
| `svc.ms` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |

## 10. Observed web-client hosts (dependency mapping)

- `https://www.office.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `m365.cloud.microsoft`.
- `https://teams.microsoft.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `login.microsoftonline.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `aadcdn.msauth.net` | seen | shared vendor infra (unmapped) | no application | not checked | Microsoft Entra sign-in CDN |
| `admin.microsoft.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `browser.events.data.microsoft.com` | seen (some failed) | shared vendor infra | `ms-telemetry` | not checked |  |
| `config.edge.skype.com` | seen | third party | `skype` | not checked |  |
| `config.teams.microsoft.com` | seen | app-owned | `ms-teams` | not checked |  |
| `e.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `eu-mobile.events.data.microsoft.com` | seen | shared vendor infra | `ms-telemetry` | not checked |  |
| `login.live.com` | seen | shared vendor infra | `azure-ad` | not checked |  |
| `login.microsoftonline.com` | seen | shared vendor infra | `azure-ad` | not checked |  |
| `m365.cloud.microsoft` | seen | app-owned | `ms-office365` | not checked |  |
| `res.cdn.office.net` | seen | shared vendor infra | `ms-base` | cdn,h3 |  |
| `scripts.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `teams.events.data.microsoft.com` | seen (some failed) | shared vendor infra | `ms-telemetry` | not checked |  |
| `teams.microsoft.com` | seen | app-owned | `ms-teams` |  |  |
| `teams.public.onecdn.static.microsoft` | seen | shared vendor infra | `ms-base` | not checked |  |
| `uhf.microsoft.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `wcpstatic.microsoft.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `www.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `www.office.com` | seen | app-owned | `ms-office365` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `ms-office365`: business-systems / office-programs, browser-based; characteristics `widely-used`, `transfers-files`; **risk 2**: widely used by enterprises; moves files out of the organisation.
- `ms-teams`: collaboration / voip-video, client-server; characteristics `widely-used`, `transfers-files`; **risk 2**: widely used by enterprises; moves files out of the organisation.
- `outlook-web`: collaboration / email, browser-based; characteristics `widely-used`, `transfers-files`; **risk 2**: widely used by enterprises; moves files out of the organisation.
- `sharepoint-online`: business-systems / office-programs, browser-based; characteristics `widely-used`, `transfers-files`; **risk 2**: widely used by enterprises; moves files out of the organisation.
- Functions separated by name: `ms-office365` (Microsoft 365 web applications), `ms-teams` (Microsoft Teams chat and meetings), `outlook-web` (Outlook web mail (Microsoft 365 and Outlook.com)), `sharepoint-online` (SharePoint Online sites and files).
- Variant: business (consumer Outlook.com and Skype are separate ids).
- Dependencies (observed, never attributed to this app): `azure-ad`, `e.clarity.ms`, `ms-base`, `ms-telemetry`, `scripts.clarity.ms`, `skype`, `www.clarity.ms`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `office.net`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
