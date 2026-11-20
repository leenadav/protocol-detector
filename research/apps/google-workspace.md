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

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R and L)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xgoogle.com` | not gmail/google-drive/google-meet/google-accounts (label boundary) | no application | PASS |
| L- | `mail.google.com.example.invalid` | not gmail/google-drive/google-meet/google-accounts (suffix look-alike) | no application | PASS |
| L- | `xgmail.com` | not gmail/google-drive/google-meet/google-accounts (label boundary) | no application | PASS |
| L- | `gmail.com.example.invalid` | not gmail/google-drive/google-meet/google-accounts (suffix look-alike) | no application | PASS |
| L- | `xgooglemail.com` | not gmail/google-drive/google-meet/google-accounts (label boundary) | no application | PASS |
| L- | `googlemail.com.example.invalid` | not gmail/google-drive/google-meet/google-accounts (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

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

**Gmail via `googlemail.com` (2026-11-20).** In the D09 email captures, every unnamed TLS session was Gmail
under `googlemail.com`: `smtp.googlemail.com:465` (250 sessions), `imap.googlemail.com:993` (26) and
`pop.googlemail.com:995` (18) across 6 captures (aggregate counts only). Gmail Help states: "Messages sent to
@gmail.com and @googlemail.com are the same. Some countries use @googlemail.com instead"
(`https://support.google.com/mail/answer/10313`, accessed 2026-11-20). Patch L adds `googlemail.com` to `gmail`
at **N2**: the page establishes the domain as Gmail's, but not its server names.

**Decision applied (Hermes decision 4):** `play.google.com` is loaded by the Gemini page as shared Google
infrastructure, and an SNI cannot separate Play Store use from that. Patch L removes it from `google-play`, so it
falls to vendor-level `google-base`; `google-play` keeps `play.googleapis.com`.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `mail.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `mail.google.com` (SAN covers name: True) |
| `gmail.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `gmail.com` (SAN covers name: True) |
| `googlemail.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `drive.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.google.com` (SAN covers name: True) |
| `docs.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.google.com` (SAN covers name: True) |
| `drive.usercontent.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.usercontent.google.com` (SAN covers name: True) |
| `googledrive.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.googleusercontent.com` (SAN covers name: True) |
| `sheets.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.google.com` (SAN covers name: True) |
| `slides.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.google.com` (SAN covers name: True) |
| `drive-data-export.usercontent.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.usercontent.google.com` (SAN covers name: True) |
| `drive-data-export-eu.usercontent.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.usercontent.google.com` (SAN covers name: True) |
| `meet.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.google.com` (SAN covers name: True) |
| `accounts.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `accounts.google.com` (SAN covers name: True) |

## 10. Observed web-client hosts (dependency mapping)

- `https://mail.google.com/`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).
- `https://meet.google.com/`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

## 11. Attributes (App-ID model) and re-verify date

- `gmail`: collaboration / email, browser-based; characteristics `widely-used`, `transfers-files`; **risk 2**: widely used by enterprises; moves files out of the organisation.
- `google-drive`: general-internet / file-sharing, browser-based; characteristics `widely-used`, `transfers-files`; **risk 3**: widely used by enterprises; moves files out of the organisation.
- `google-meet`: collaboration / voip-video, browser-based; characteristics `widely-used`; **risk 2**: widely used by enterprises.
- `google-accounts`: business-systems / auth-service, browser-based; characteristics `widely-used`; **risk 1**: widely used by enterprises.
- Functions separated by name: `gmail` (Gmail web mail), `google-drive` (Google Drive and Docs), `google-meet` (Google Meet video meetings), `google-accounts` (Google account sign-in).
- Variant: not separated by name: consumer Gmail and Workspace share `mail.google.com`.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
