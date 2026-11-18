# Google Workspace: Drive, Docs editors, Gmail, Chat, Meet

- Content-pack ids today: `google-drive`, `gmail` (`mail.google.com`, `gmail.com`), `google-chat` (`chat.google.com`), `google-meet` (`meet.google.com`), `google-base`
- Status: **READY**, NAME, batch B (Drive and Docs editor hosts). Gmail and Chat are DONE (verified, no change). One Meet attribution risk is recorded with no change proposed
- Implemented: content release 2026.11.4 on `claude/go-migration` (`6ab434d`); verified in the pack at `47b2743`, 2026-11-18
- Sources accessed: 2026-11-18

## 1. What it is

Google's productivity suite. The generative-AI hosts are in `google-gemini.md`. Personal vs business Drive is in `onedrive-drive-personal-business.md`.

## 2. Transport and ports

TCP 443 (HTTPS) for the service URLs and TCP 80 for CRL/OCSP [S1]. Drive and Sites hosts on
"443/HTTPS" [S2].

## 3. Observable evidence

- User-facing hosts [S1]: `drive.google.com`, `docs.google.com`, `sheets.google.com`, `slides.google.com`,
  `sites.google.com`, `meet.google.com`, `calendar.google.com`, `keep.google.com`, `script.google.com`;
  mail `https://mail.google.com/mail`; Chat `https://chat.google.com` and `https://mail.google.com/chat`.
- Drive and Docs editors [S2]: see `onedrive-drive-personal-business.md` section 3.
- Meet, "(Optional) URLs for additional control" [S1]: `https://*.googlevideo.com/*`,
  `https://*.youtube-nocookie.com/*`, `https://*.ytimg.com/*`.

## 4. Encrypted-traffic caveats

- **Gmail and Chat share `mail.google.com`** [S1] (`/mail` vs `/chat` paths). On the CONNECT path
  Chat-in-Gmail is reported as `gmail`. Not fixable without decryption.
- **Meet media hosts are YouTube's hosts** [S1]. `googlevideo.com`, `ytimg.com` and
  `youtube-nocookie.com` are `youtube` in the pack, so Meet traffic to them is logged as `youtube`. The
  names cannot be split, so no change is proposed. The attribution risk is recorded for operators.
- One Google IP range set serves every URL [S1, google-gemini.md S2].

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| `drive.google.com`, `docs.google.com`, `sheets.google.com`, `slides.google.com`, `googledrive.com`, `drive-data-export[-eu].usercontent.google.com` | **N3** Drive and Docs | |
| `mail.google.com` | **N2** | Gmail and Chat |
| `chat.google.com`, `meet.google.com` | **N3** | |
| `googlevideo.com`, `ytimg.com`, `youtube-nocookie.com` | **N2** | YouTube or Meet |
| `*.googleapis.com`, `*.gstatic.com`, `*.googleusercontent.com` | **N1** | All of Google |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `sheets.google.com`, `slides.google.com`, `googledrive.com` | `google-drive` (today `google-base`, or unmapped for `googledrive.com`) |
| P2 | SNI `drive-data-export-eu.usercontent.google.com` | `google-drive` |
| P3 | SNI `mail.google.com` | `gmail` |
| R1 | SNI `r1.googlevideo.com` | `youtube` (documents the Meet risk) |
| N1 | SNI `x.usercontent.google.com` | `google-base` |
| N2 | SNI `drive.google.com.example.invalid` | no application |

Checked in scratch (batch A plus B): all as expected.

## 7. Sources

- [S1] Google Workspace Help, "Set up a Google Workspace host name allowlist" (see google-gemini.md [S1]), accessed 2026-11-18.
- [S2] Google Workspace Help, "Drive and Sites firewall and proxy settings",
  `https://knowledge.workspace.google.com/admin/drive/drive-and-sites-firewall-and-proxy-settings?hl=en`, accessed 2026-11-18.

## 8. Catalog delta and recommendation

```python
("google-drive", "general-internet", "file-sharing", "browser-based", 3, "Google Drive and Docs",
 ("widely-used", "transfers-files"), ("drive.google.com", "docs.google.com", "drive.usercontent.google.com", "googledrive.com",
                                      "sheets.google.com", "slides.google.com", "drive-data-export.usercontent.google.com",
                                      "drive-data-export-eu.usercontent.google.com")),
```

`sites.google.com`, `calendar.google.com` and `keep.google.com` have no application id. Adding ids is
possible later; that is a catalog-scope choice, not proposed now.
