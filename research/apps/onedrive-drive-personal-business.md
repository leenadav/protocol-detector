# OneDrive and Google Drive: personal vs business

- Content-pack ids today: `ms-onedrive` (`onedrive.live.com`, `onedrive.com`, `1drv.com`, `1drv.ms`), `sharepoint-online` (`sharepoint.com`, plus batch A), `google-drive` (`drive.google.com`, `docs.google.com`, `drive.usercontent.google.com`)
- Status: OneDrive **READY**, NAME, batch B (`research/patches/batch-b-name-based.patch`). Google Drive: personal vs business **not separable** (no change for the split; host additions are in `google-workspace.md`)
- Implemented: content release 2026.11.4 on `claude/go-migration` (`6ab434d`); verified in the pack at `47b2743`, 2026-11-18
- Sources accessed: 2026-11-18

## 1. What it is

The question operators ask: is a file upload going to a **personal** cloud drive (exfiltration risk)
or to the organization's tenant?

## 2. Transport and ports

- OneDrive consumer: "TCP 80, TCP 443" for every listed endpoint [S1].
- OneDrive for Business: Microsoft 365 SharePoint rows (`*.sharepoint.com`, TCP 80/443, UDP 443) [S2; microsoft-365.md].
- Google Drive: hosts on "443/HTTPS" (Sites also 80) [S3].

## 3. Observable evidence

**OneDrive consumer.** "This reference article lists all endpoints used by the consumer version of
Microsoft OneDrive", with a pointer to the Microsoft 365 list for "OneDrive in Microsoft 365" [S1].
Hosts [S1]: `onedrive.com`, `*.onedrive.com`, `onedrive.live.com`, `login.live.com`, `g.live.com`,
`*.officeapps.live.com`, `odc.officeapps.live.com`, `*.files.1drv.com`, `*.onedrive.live.com`,
`storage.live.com`, `*.storage.live.com`, `*.groups.office.live.com`, `*.groups.photos.live.com`,
`*.groups.skydrive.live.com`, `favorites.live.com`, `oauth.live.com`, `photos.live.com`,
`skydrive.live.com`, `storage.msn.com`, `*.storage.msn.com`.

**OneDrive for Business** lives on the tenant's `*.sharepoint.com` names [S2, row 31]. The Microsoft
365 list also names `storage.live.com` for "OneDrive for Business: supportability, telemetry, APIs, and
embedded email links" [S2, row 32]. So `storage.live.com` serves **both** and separates nothing.

**Google Drive** [S3]: `drive.google.com`, `*.drive.google.com`, `googledrive.com`,
`drive.usercontent.google.com`, `drive-data-export.usercontent.google.com`,
`drive-data-export-eu.usercontent.google.com`, `docs.google.com`, `*.docs.google.com`, `sheets.google.com`,
`slides.google.com`, plus shared Google hosts (`www.google.com`, `*.googleapis.com`, `*.gstatic.com`,
`*.googleusercontent.com`, ...). The page lists one set of hosts for Drive, with no personal or
Workspace variant.

## 4. Encrypted-traffic caveats

- OneDrive consumer vs business is visible in SNI: `onedrive.live.com` and the other consumer hosts vs
  `<tenant>.sharepoint.com`. The tenant label must not be logged (opaque identifier, AGENTS.md).
- Google Drive personal vs Workspace is **not** visible in SNI from any source read. Any control
  that separates them is outside the visibility phase and not researched here.
- `login.live.com` and the `officeapps.live.com` hosts are shared with other Microsoft consumer and
  Office services. They do not name OneDrive.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `onedrive.live.com`, `onedrive.com`, `1drv.com`, `skydrive.live.com`, `photos.live.com`, `storage.msn.com` | **N3** OneDrive consumer | `photos.live.com` may also serve other consumer photo features (`UNVERIFIED`) |
| SNI under `sharepoint.com` | **N3** SharePoint or OneDrive for Business | Cannot separate SharePoint sites from OneDrive for Business |
| `storage.live.com` | **N1** | Both consumer and business [S1, S2] |
| Google Drive hosts | **N3** Drive | Personal vs business not separable |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `skydrive.live.com`, `photos.live.com`, `x.storage.msn.com` | `ms-onedrive` (today `ms-base`) |
| P2 | SNI `x.files.1drv.com` | `ms-onedrive` (unchanged) |
| P3 | SNI `contoso-my.sharepoint.com` | `sharepoint-online`; the tenant label is not in the output |
| N1 | SNI `storage.live.com` | `ms-base` (shared; never "personal") |
| N2 | SNI `login.live.com` | `azure-ad` (unchanged) |
| N3 | `ech_outer()` with outer SNI `onedrive.live.com` | no application |

Checked with `attribution_for_host` in scratch (batch A plus B): all as expected, except N3, which needs the full engine.

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O and P as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `drive.google.com` | one of `ms-onedrive`, `google-drive` | `google-drive` | PASS |
| O+ | `onedrive.live.com` | one of `ms-onedrive`, `google-drive` | `ms-onedrive` | PASS |
| D- | `accdn-vip.lpsnmedia.net` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `accounts.google.com` | not ms-onedrive/google-drive (shared vendor infra) | `google-accounts` | PASS |
| D- | `api.company-target.com` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `assets.adobedtm.com` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `browser.events.data.microsoft.com` | not ms-onedrive/google-drive (shared vendor infra) | `ms-telemetry` | PASS |
| D- | `c.bing.com` | not ms-onedrive/google-drive (shared vendor infra) | `ms-base` | PASS |
| D- | `c.clarity.ms` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `c.s-microsoft.com` | not ms-onedrive/google-drive (shared vendor infra (unmapped)) | no application | PASS |
| D- | `cdn-dynmedia-1.microsoft.com` | not ms-onedrive/google-drive (shared vendor infra) | `ms-base` | PASS |
| D- | `dpm.demdex.net` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `dsum-sec.casalemedia.com` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `edge.adobedc.net` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `id.rlcdn.com` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `image2.pubmatic.com` | not ms-onedrive/google-drive (third party) | `pubmatic` | PASS |
| D- | `js.monitor.azure.com` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `l.clarity.ms` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `login.live.com` | not ms-onedrive/google-drive (shared vendor infra) | `azure-ad` | PASS |
| D- | `login.microsoftonline.com` | not ms-onedrive/google-drive (shared vendor infra) | `azure-ad` | PASS |
| D- | `lpcdn-vip.lpsnmedia.net` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `lpcdn.lpsnmedia.net` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `lptag.liveperson.net` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `msftenterprise.sc.omtrdc.net` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `partners.tremorhub.com` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `pixel.rubiconproject.com` | not ms-onedrive/google-drive (third party) | `magnite` | PASS |
| D- | `play.vidyard.com` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `publisher.liveperson.net` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `rum.hlx.page` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `s.company-target.com` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `scripts.clarity.ms` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `segments.company-target.com` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `ssl.gstatic.com` | not ms-onedrive/google-drive (shared vendor infra) | `google-base` | PASS |
| D- | `static-assets.fs.liveperson.com` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `tag-logger.demandbase.com` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `tag.demandbase.com` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `target.microsoft.com` | not ms-onedrive/google-drive (shared vendor infra) | `ms-base` | PASS |
| D- | `uhf-exp-fd-gbcrdgggfbggh0g3.b02.azurefd.net` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `uhf.microsoft.com` | not ms-onedrive/google-drive (shared vendor infra) | `ms-base` | PASS |
| D- | `va-vip.v.liveperson.net` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `wcpstatic.microsoft.com` | not ms-onedrive/google-drive (shared vendor infra) | `ms-base` | PASS |
| D- | `www.clarity.ms` | not ms-onedrive/google-drive (third party (unclassified)) | no application | PASS |
| D- | `www.microsoft.com` | not ms-onedrive/google-drive (shared vendor infra) | `ms-base` | PASS |
| L- | `xlive.com` | not ms-onedrive/google-drive (label boundary) | no application | PASS |
| L- | `onedrive.live.com.example.invalid` | not ms-onedrive/google-drive (suffix look-alike) | no application | PASS |
| L- | `xonedrive.com` | not ms-onedrive/google-drive (label boundary) | no application | PASS |
| L- | `onedrive.com.example.invalid` | not ms-onedrive/google-drive (suffix look-alike) | no application | PASS |
| L- | `x1drv.com` | not ms-onedrive/google-drive (label boundary) | no application | PASS |
| L- | `1drv.com.example.invalid` | not ms-onedrive/google-drive (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Microsoft Learn, "Required URLs and ports for OneDrive consumer",
  `https://learn.microsoft.com/en-us/sharepoint/required-urls-and-ports`, "Last updated on 03/27/2025",
  accessed 2026-11-18.
- [S2] Microsoft 365 endpoints web service, version 2026103000 (see microsoft-365.md [S1]), rows 31 and 32.
- [S3] Google Workspace Help, "Drive and Sites firewall and proxy settings",
  `https://knowledge.workspace.google.com/admin/drive/drive-and-sites-firewall-and-proxy-settings?hl=en`,
  accessed 2026-11-18.

## 8. Catalog delta and recommendation

```python
("ms-onedrive", "general-internet", "file-sharing", "browser-based", 3, "Microsoft OneDrive (consumer) file storage",
 ("widely-used", "transfers-files"), ("onedrive.live.com", "onedrive.com", "1drv.com", "1drv.ms", "skydrive.live.com",
                                      "photos.live.com", "storage.msn.com")),
```

The description changes to say "consumer", which records the personal/business distinction already
present in the catalog (`ms-onedrive` vs `sharepoint-online`). `storage.live.com` stays with `ms-base`.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 6 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `onedrive.live.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `onedrive.com`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation) |
| `onedrive.com` | **L** resolves; TLSv1.3, ALPN `None`, cert `onedrive.com`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation) |
| `1drv.com` | resolves; TLS handshake failed (SSLCertVerificationError) in both rounds where checked: not a removal reason |
| `1drv.ms` | **L** resolves; TLSv1.3, ALPN `h2`, cert `storage.live.com`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation) |
| `skydrive.live.com` | **L** resolves; TLSv1.3, ALPN `None`, cert `onedrive.com`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation); CNAME into shared front end `cosmic-westeurope-ns-5cf19e8e66cb.trafficmanager.net`: name usable, IPs never |
| `photos.live.com` | **L** resolves; TLSv1.3, ALPN `None`, cert `onedrive.com`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation); CNAME into shared front end `cosmic-westeurope-ns-5cf19e8e66cb.trafficmanager.net`: name usable, IPs never |
| `storage.msn.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `storage.live.com`, subject organisation **Microsoft Corporation** (issuer Microsoft Corporation) |
| `drive.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.google.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `docs.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.google.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `drive.usercontent.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.usercontent.google.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `googledrive.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.googleusercontent.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `sheets.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.google.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `slides.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.google.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `drive-data-export.usercontent.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.usercontent.google.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `drive-data-export-eu.usercontent.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.usercontent.google.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |

## 10. Observed web-client hosts (dependency mapping)

- `https://onedrive.live.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `www.microsoft.com`.
- `https://drive.google.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `accounts.google.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `accdn-vip.lpsnmedia.net` | seen | third party (unclassified) | no application | not checked |  |
| `accounts.google.com` | seen | shared vendor infra | `google-accounts` |  |  |
| `api.company-target.com` | seen | third party (unclassified) | no application | not checked |  |
| `assets.adobedtm.com` | seen | third party (unclassified) | no application | not checked |  |
| `browser.events.data.microsoft.com` | seen | shared vendor infra | `ms-telemetry` | not checked |  |
| `c.bing.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `c.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `c.s-microsoft.com` | seen | shared vendor infra (unmapped) | no application | not checked | Microsoft shared assets |
| `cdn-dynmedia-1.microsoft.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `dpm.demdex.net` | seen | third party (unclassified) | no application | not checked |  |
| `drive.google.com` | seen | app-owned | `google-drive` |  |  |
| `dsum-sec.casalemedia.com` | seen | third party (unclassified) | no application | not checked |  |
| `edge.adobedc.net` | seen | third party (unclassified) | no application | not checked |  |
| `id.rlcdn.com` | seen | third party (unclassified) | no application | not checked |  |
| `image2.pubmatic.com` | seen | third party | `pubmatic` | not checked |  |
| `js.monitor.azure.com` | seen | third party (unclassified) | no application | not checked |  |
| `l.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `login.live.com` | seen | shared vendor infra | `azure-ad` | not checked |  |
| `login.microsoftonline.com` | seen | shared vendor infra | `azure-ad` | not checked |  |
| `lpcdn-vip.lpsnmedia.net` | seen | third party (unclassified) | no application | not checked |  |
| `lpcdn.lpsnmedia.net` | seen | third party (unclassified) | no application | not checked |  |
| `lptag.liveperson.net` | seen | third party (unclassified) | no application | not checked |  |
| `msftenterprise.sc.omtrdc.net` | seen | third party (unclassified) | no application | not checked |  |
| `onedrive.live.com` | seen | app-owned | `ms-onedrive` |  |  |
| `partners.tremorhub.com` | seen | third party (unclassified) | no application | not checked |  |
| `pixel.rubiconproject.com` | seen | third party | `magnite` | not checked |  |
| `play.vidyard.com` | seen | third party (unclassified) | no application | not checked |  |
| `publisher.liveperson.net` | seen | third party (unclassified) | no application | not checked |  |
| `rum.hlx.page` | seen | third party (unclassified) | no application | not checked |  |
| `s.company-target.com` | seen | third party (unclassified) | no application | not checked |  |
| `scripts.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `segments.company-target.com` | seen | third party (unclassified) | no application | not checked |  |
| `ssl.gstatic.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `static-assets.fs.liveperson.com` | seen | third party (unclassified) | no application | not checked |  |
| `tag-logger.demandbase.com` | seen | third party (unclassified) | no application | not checked |  |
| `tag.demandbase.com` | seen | third party (unclassified) | no application | not checked |  |
| `target.microsoft.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `uhf-exp-fd-gbcrdgggfbggh0g3.b02.azurefd.net` | seen | third party (unclassified) | no application | not checked |  |
| `uhf.microsoft.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `va-vip.v.liveperson.net` | seen | third party (unclassified) | no application | not checked |  |
| `wcpstatic.microsoft.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `www.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `www.microsoft.com` | seen | shared vendor infra | `ms-base` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `ms-onedrive`: general-internet / file-sharing, browser-based; characteristics `widely-used`, `transfers-files`; **risk 3**: widely used by enterprises; moves files out of the organisation.
- `google-drive`: general-internet / file-sharing, browser-based; characteristics `widely-used`, `transfers-files`; **risk 3**: widely used by enterprises; moves files out of the organisation.
- Functions separated by name: `ms-onedrive` (Microsoft OneDrive (consumer) file storage), `google-drive` (Google Drive and Docs).
- Variant: consumer and business separated by name (`onedrive.live.com` vs `*.sharepoint.com`).
- Dependencies (observed, never attributed to this app): `accdn-vip.lpsnmedia.net`, `api.company-target.com`, `assets.adobedtm.com`, `azure-ad`, `c.clarity.ms`, `dpm.demdex.net`, `dsum-sec.casalemedia.com`, `edge.adobedc.net`, `google-accounts`, `google-base`, `id.rlcdn.com`, `js.monitor.azure.com`, `l.clarity.ms`, `lpcdn-vip.lpsnmedia.net`, `lpcdn.lpsnmedia.net`, `lptag.liveperson.net`, `magnite`, `ms-base`, `ms-telemetry`, `msftenterprise.sc.omtrdc.net`, `partners.tremorhub.com`, `play.vidyard.com`, `publisher.liveperson.net`, `pubmatic`, `rum.hlx.page`, `s.company-target.com`, `scripts.clarity.ms`, `segments.company-target.com`, `static-assets.fs.liveperson.com`, `tag-logger.demandbase.com`, `tag.demandbase.com`, `uhf-exp-fd-gbcrdgggfbggh0g3.b02.azurefd.net`, `va-vip.v.liveperson.net`, `www.clarity.ms`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
