# Box

- Content-pack id today: `box` (`box.com`, `boxcloud.com`, `box.net`)
- Status: **BLOCKED**, NAME. Box's firewall article redirects to a sign-in page (`box.zendesk.com/access`), and this lane does not sign in to vendor portals
- Sources accessed: 2026-11-18

## 1. What it is

Enterprise cloud content management and file sharing.

## 2. Transport and ports

`UNVERIFIED`. The article that would state them could not be read.

## 3. Observable evidence

`UNVERIFIED`. The article "Configuring A Firewall For Box Applications and Services" (Box support
article 33552262497683) returned HTTP 302 to a sign-in page on 2026-11-18. Its contents are not paraphrased
here, not even from search snippets.

## 4. Encrypted-traffic caveats

Not assessed.

## 5. Confidence and false-positive risks

| Observable | Level |
|---|---|
| Current pack names | **U** |

## 6. Synthetic test vectors

Pending sources.

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L and J)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `account.box.com` | one of `box` | `box` | PASS |
| O+ | `cdn01.boxcdn.net` | one of `box` | `box` | PASS |
| L- | `xbox.com` | not box (label boundary) | `xbox-live` | PASS |
| L- | `box.com.example.invalid` | not box (suffix look-alike) | no application | PASS |
| L- | `xboxcloud.com` | not box (label boundary) | no application | PASS |
| L- | `boxcloud.com.example.invalid` | not box (suffix look-alike) | no application | PASS |
| L- | `xbox.net` | not box (label boundary) | no application | PASS |
| L- | `box.net.example.invalid` | not box (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [BLOCKED] `https://support.box.com/hc/en-us/articles/33552262497683-Configuring-A-Firewall-For-Box-Applications-and-Services`:
  redirect to sign-in, 2026-11-18.

## 8. Catalog delta and recommendation

None yet. **Request to Hermes**: the article text, copied by Lee from a signed-in or normal browser
session, as was done for OpenAI.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `box.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `box.com` (SAN covers name: True) |
| `boxcloud.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.boxcloud.com` (SAN covers name: True) |
| `box.net` | **L** resolves; TLSv1.3, ALPN `h2`, cert `box.net` (SAN covers name: True) |
| `boxcdn.net` | apex has no address (normal for a suffix entry); suffix **verified** through documented `cdn01.boxcdn.net` (TLS TLSv1.3, cert `cdn01.boxcdn.net`, cdn,h3) |

## 10. Observed web-client hosts (dependency mapping)

- `https://account.box.com/login`, loaded 2026-11-19 without signing in: HTTP 200, final host `account.box.com`.

Pass 1 is a lower bound. The proxy refuses hosts not on the allowlist ("failed" below), so hosts that only scripts from a refused host would contact are missing.

| Host | Requests (refused) | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `account.box.com` | 1 (0) | app-owned | `box` |  |  |
| `cdn01.boxcdn.net` | 5 (5) | app-owned | `box` | cdn,h3 |  |

## 11. Attributes (App-ID model) and re-verify date

- `box`: general-internet / file-sharing, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `boxcdn.net`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
