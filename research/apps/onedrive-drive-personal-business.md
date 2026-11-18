# OneDrive and Google Drive: personal vs business

- Content-pack ids today: `ms-onedrive` (`onedrive.live.com`, `onedrive.com`, `1drv.com`, `1drv.ms`), `sharepoint-online` (`sharepoint.com`, plus batch A), `google-drive` (`drive.google.com`, `docs.google.com`, `drive.usercontent.google.com`)
- Status: OneDrive **READY**, NAME, batch B (`research/patches/batch-b-name-based.patch`). Google Drive: personal vs business **not separable** (no change for the split; host additions are in `google-workspace.md`)
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
