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

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M and N as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `accounts.google.com` | one of `gmail`, `google-drive`, `google-meet`, `google-accounts` | `google-accounts` | PASS |
| O+ | `mail.google.com` | one of `gmail`, `google-drive`, `google-meet`, `google-accounts` | `gmail` | PASS |
| O+ | `meet.google.com` | one of `gmail`, `google-drive`, `google-meet`, `google-accounts` | `google-meet` | PASS |
| D- | `2507573.fls.doubleclick.net` | not gmail/google-drive/google-meet/google-accounts (third party) | `google-ads` | PASS |
| D- | `ad.doubleclick.net` | not gmail/google-drive/google-meet/google-accounts (third party) | `google-ads` | PASS |
| D- | `adservice.google.com` | not gmail/google-drive/google-meet/google-accounts (shared vendor infra) | `google-base` | PASS |
| D- | `analytics.google.com` | not gmail/google-drive/google-meet/google-accounts (shared vendor infra) | `google-base` | PASS |
| D- | `apps.google.com` | not gmail/google-drive/google-meet/google-accounts (shared vendor infra) | `google-base` | PASS |
| D- | `fonts.googleapis.com` | not gmail/google-drive/google-meet/google-accounts (shared vendor infra) | `google-base` | PASS |
| D- | `fonts.gstatic.com` | not gmail/google-drive/google-meet/google-accounts (shared vendor infra) | `google-base` | PASS |
| D- | `googleads.g.doubleclick.net` | not gmail/google-drive/google-meet/google-accounts (third party) | `google-ads` | PASS |
| D- | `lh3.googleusercontent.com` | not gmail/google-drive/google-meet/google-accounts (shared vendor infra) | `google-base` | PASS |
| D- | `ssl.google-analytics.com` | not gmail/google-drive/google-meet/google-accounts (third party) | `google-analytics` | PASS |
| D- | `ssl.gstatic.com` | not gmail/google-drive/google-meet/google-accounts (shared vendor infra) | `google-base` | PASS |
| D- | `stats.g.doubleclick.net` | not gmail/google-drive/google-meet/google-accounts (third party) | `google-ads` | PASS |
| D- | `storage.googleapis.com` | not gmail/google-drive/google-meet/google-accounts (shared vendor infra) | `google-base` | PASS |
| D- | `workspace.google.com` | not gmail/google-drive/google-meet/google-accounts (shared vendor infra) | `google-base` | PASS |
| D- | `www.google.co.il` | not gmail/google-drive/google-meet/google-accounts (third party (unclassified)) | no application | PASS |
| D- | `www.google.com` | not gmail/google-drive/google-meet/google-accounts (shared vendor infra) | `google-base` | PASS |
| D- | `www.googletagmanager.com` | not gmail/google-drive/google-meet/google-accounts (third party) | `google-analytics` | PASS |
| D- | `www.gstatic.com` | not gmail/google-drive/google-meet/google-accounts (shared vendor infra) | `google-base` | PASS |
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

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 5 of 2026-11-21 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `mail.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `mail.google.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `gmail.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `gmail.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `googlemail.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `googlemail.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `drive.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.google.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `docs.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.google.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `drive.usercontent.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.usercontent.google.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `googledrive.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.googleusercontent.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `sheets.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.google.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `slides.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.google.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `drive-data-export.usercontent.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.usercontent.google.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `drive-data-export-eu.usercontent.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.usercontent.google.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `meet.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.google.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `accounts.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `accounts.google.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |

## 10. Observed web-client hosts (dependency mapping)

- `https://mail.google.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `accounts.google.com`.
- `https://meet.google.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `workspace.google.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `2507573.fls.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `accounts.google.com` | seen | app-owned | `google-accounts` |  |  |
| `ad.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `adservice.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `analytics.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `apps.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `fonts.googleapis.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `fonts.gstatic.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `googleads.g.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `lh3.googleusercontent.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `mail.google.com` | seen | app-owned | `gmail` |  |  |
| `meet.google.com` | seen | app-owned | `google-meet` |  |  |
| `ssl.google-analytics.com` | seen | third party | `google-analytics` | not checked |  |
| `ssl.gstatic.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `stats.g.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `storage.googleapis.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `workspace.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `www.google.co.il` | seen | third party (unclassified) | no application | not checked |  |
| `www.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `www.googletagmanager.com` | seen | third party | `google-analytics` | not checked |  |
| `www.gstatic.com` | seen | shared vendor infra | `google-base` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `gmail`: collaboration / email, browser-based; characteristics `widely-used`, `transfers-files`; **risk 2**: widely used by enterprises; moves files out of the organisation.
- `google-drive`: general-internet / file-sharing, browser-based; characteristics `widely-used`, `transfers-files`; **risk 3**: widely used by enterprises; moves files out of the organisation.
- `google-meet`: collaboration / voip-video, browser-based; characteristics `widely-used`; **risk 2**: widely used by enterprises.
- `google-accounts`: business-systems / auth-service, browser-based; characteristics `widely-used`; **risk 1**: widely used by enterprises.
- Functions separated by name: `gmail` (Gmail web mail), `google-drive` (Google Drive and Docs), `google-meet` (Google Meet video meetings), `google-accounts` (Google account sign-in).
- Variant: not separated by name: consumer Gmail and Workspace share `mail.google.com`.
- Dependencies (observed, never attributed to this app): `google-ads`, `google-analytics`, `google-base`, `www.google.co.il`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
