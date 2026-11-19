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

### Method v2 vectors (checked 2026-11-19 against `c08773f` plus batches D to I and retrofit R)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `drive.google.com` | one of `ms-onedrive`, `google-drive` | `google-drive` | PASS |
| D- | `accounts.google.com` | not ms-onedrive/google-drive (shared vendor infra) | `google-accounts` | PASS |
| D- | `ssl.gstatic.com` | not ms-onedrive/google-drive (shared vendor infra) | `google-base` | PASS |
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

**BLOCKED in the research environment** (2026-11-19): its egress proxy re-terminates TLS, so a handshake would show the proxy, and direct DNS is not permitted. The tool is `research/tools/live_verify.py`; it runs from an unproxied vantage point or, DNS only, through an approved DoH resolver. No host below carries an `L` result yet.

Names to verify (catalog domains of `ms-onedrive`, `google-drive`): `onedrive.live.com`, `onedrive.com`, `1drv.com`, `1drv.ms`, `skydrive.live.com`, `photos.live.com`, `storage.msn.com`, `drive.google.com`, `docs.google.com`, `drive.usercontent.google.com`, `googledrive.com`, `sheets.google.com`, `slides.google.com`, `drive-data-export.usercontent.google.com`, `drive-data-export-eu.usercontent.google.com`.

## 10. Observed web-client hosts (dependency mapping)

- `https://drive.google.com/`, loaded 2026-11-19 without signing in: HTTP 200, final host `accounts.google.com`.
- `https://onedrive.live.com/`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

Pass 1 is a lower bound. The proxy refuses hosts not on the allowlist ("failed" below), so hosts that only scripts from a refused host would contact are missing.

| Host | Requests (refused) | Class | Attribution today | Note |
|---|---|---|---|---|
| `accounts.google.com` | 4 (0) | shared vendor infra | `google-accounts` |  |
| `drive.google.com` | 1 (0) | app-owned | `google-drive` |  |
| `ssl.gstatic.com` | 1 (1) | shared vendor infra | `google-base` |  |

## 11. Attributes (App-ID model) and re-verify date

- `ms-onedrive`: general-internet / file-sharing, browser-based; characteristics `widely-used`, `transfers-files`; **risk 3**: widely used by enterprises; moves files out of the organisation.
- `google-drive`: general-internet / file-sharing, browser-based; characteristics `widely-used`, `transfers-files`; **risk 3**: widely used by enterprises; moves files out of the organisation.
- Functions separated by name: `ms-onedrive` (Microsoft OneDrive (consumer) file storage), `google-drive` (Google Drive and Docs).
- Variant: consumer and business separated by name (`onedrive.live.com` vs `*.sharepoint.com`).
- Dependencies (observed, never attributed to this app): `google-accounts`, `google-base`.
- Evasive (ECH, DoH, proxy modes): ECH support unknown until a live HTTPS-record check (section 9); other modes as stated in sections 2 to 4.
- Re-verify by: **2027-02-17** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
