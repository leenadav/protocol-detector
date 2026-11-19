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

### Method v2 vectors (checked 2026-11-19 against `c08773f` plus batches D to I and retrofit R)

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

**BLOCKED in the research environment** (2026-11-19): its egress proxy re-terminates TLS, so a handshake would show the proxy, and direct DNS is not permitted. The tool is `research/tools/live_verify.py`; it runs from an unproxied vantage point or, DNS only, through an approved DoH resolver. No host below carries an `L` result yet.

Names to verify (catalog domains of `box`): `box.com`, `boxcloud.com`, `box.net`, `boxcdn.net`.

## 10. Observed web-client hosts (dependency mapping)

- `https://account.box.com/login`, loaded 2026-11-19 without signing in: HTTP 200, final host `account.box.com`.

Pass 1 is a lower bound. The proxy refuses hosts not on the allowlist ("failed" below), so hosts that only scripts from a refused host would contact are missing.

| Host | Requests (refused) | Class | Attribution today | Note |
|---|---|---|---|---|
| `account.box.com` | 1 (0) | app-owned | `box` |  |
| `cdn01.boxcdn.net` | 5 (5) | app-owned | `box` |  |

## 11. Attributes (App-ID model) and re-verify date

- `box`: general-internet / file-sharing, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): ECH support unknown until a live HTTPS-record check (section 9); other modes as stated in sections 2 to 4.
- Re-verify by: **2027-02-17** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
