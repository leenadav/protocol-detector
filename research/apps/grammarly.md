# Grammarly

- Content-pack id today: `grammarly` (`grammarly.com`, `grammarly.io`)
- Status: **BLOCKED** (no endpoint list in the source), NAME, low priority
- Sources: read by Hermes, relayed, 2026-11-19; the page shows no date

## 1. What it is

Writing assistant (browser extension, desktop and web).

## 2. Transport and ports

The page says only that a network administrator "can enable a specific web socket port" [S1]; no port is named.

## 3. Observable evidence

The relayed article body has no domain or endpoint list. It links a "WebSockets Support Q&A for System Administrators" article, which was not relayed [S1].

## 4. Encrypted-traffic caveats

Not assessed beyond the README's shared facts.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| Current pack names | **U** | Not verified by this lane |

## 6. Synthetic test vectors

None (no catalog change).


<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R and L)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `app.grammarly.com` | one of `grammarly` | `grammarly` | PASS |
| O+ | `www.grammarly.com` | one of `grammarly` | `grammarly` | PASS |
| L- | `xgrammarly.com` | not grammarly (label boundary) | no application | PASS |
| L- | `grammarly.com.example.invalid` | not grammarly (suffix look-alike) | no application | PASS |
| L- | `xgrammarly.io` | not grammarly (label boundary) | no application | PASS |
| L- | `grammarly.io.example.invalid` | not grammarly (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Grammarly Support, "Network configuration blocks Grammarly services", `https://support.grammarly.com/hc/en-us/articles/115000090271-Network-configuration-blocks-Grammarly-services`, read by Hermes, relayed, 2026-11-19.

## 8. Catalog delta and recommendation

None. Next: the linked "WebSockets Support Q&A for System Administrators" article (URL unknown to this lane).

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `grammarly.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `www.grammarly.com` (SAN covers name: True) |
| `grammarly.io` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |

## 10. Observed web-client hosts (dependency mapping)

- `https://app.grammarly.com/`, loaded 2026-11-19 without signing in: HTTP None (page.goto: net::ERR_TUNNEL_CONNECTION_FAILED at https://app.grammarly.com/), final host `chromewebdata`.

Pass 1 is a lower bound. The proxy refuses hosts not on the allowlist ("failed" below), so hosts that only scripts from a refused host would contact are missing.

| Host | Requests (refused) | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `app.grammarly.com` | 1 (0) | app-owned | `grammarly` |  |  |
| `www.grammarly.com` | 1 (1) | app-owned | `grammarly` |  |  |

## 11. Attributes (App-ID model) and re-verify date

- `grammarly`: business-systems / office-programs, browser-based; characteristics `pervasive`; **risk 3**: present on most managed endpoints.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
