# Cursor (AI code editor)

- Content-pack id today: `cursor` (`cursor.com`, `cursor.sh`)
- Status: **READY**, NAME, batch D
- Sources accessed: 2026-11-19

## 1. What it is

An AI-assisted code editor with hosted models and cloud agents.

## 2. Transport and ports

HTTPS. "Cursor uses HTTP/2 bidirectional streaming by default" and falls back to "HTTP/1.1 Server-Sent Events (SSE)" [S1].

## 3. Observable evidence

Allowlist [S1]: `*.cursor.sh`, `*.cursor-cdn.com`, `*.cursorapi.com`, `*.cursorvm.com`, `*.*.cursorvm.com`; SSL-inspection exclusions add `marketplace.cursorapi.com`, `authenticate.cursor.sh`, `authenticator.cursor.sh`, `cursor.com` and `*.cursor.com`. "Sign-in also uses `accounts.spacex.ai`, `accounts.x.ai`, and related auth hosts" [S1].

## 4. Encrypted-traffic caveats

**Attribution risk:** `accounts.x.ai` is under `x.ai`, which the pack maps to `xai-grok`, so a Cursor sign-in is logged as xAI Grok. It is recorded here with no change proposed (the host also serves xAI's own users). `accounts.spacex.ai` is not in the pack.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `cursor.sh`, `cursorapi.com`, `cursor-cdn.com`, `cursorvm.com` | **N3** Cursor |  |
| `accounts.x.ai` | **N2** | Shared with xAI |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `api2.cursor.sh`, `marketplace.cursorapi.com`, `x.cursor-cdn.com`, `a.b.cursorvm.com` | `cursor` |
| R1 | SNI `accounts.x.ai` | `xai-grok` (the recorded risk) |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L and J)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `cursor.com` | one of `cursor` | `cursor` | PASS |
| D- | `api.workos.com` | not cursor (third party) | no application | PASS |
| L- | `xcursor.com` | not cursor (label boundary) | no application | PASS |
| L- | `cursor.com.example.invalid` | not cursor (suffix look-alike) | no application | PASS |
| L- | `xcursor.sh` | not cursor (label boundary) | no application | PASS |
| L- | `cursor.sh.example.invalid` | not cursor (suffix look-alike) | no application | PASS |
| L- | `xcursorapi.com` | not cursor (label boundary) | no application | PASS |
| L- | `cursorapi.com.example.invalid` | not cursor (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Cursor docs, "Network configuration", `https://cursor.com/docs/enterprise/network-configuration.md`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("cursor", ..., ("cursor.com", "cursor.sh", "cursorapi.com", "cursor-cdn.com", "cursorvm.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `cursor.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `cursor.com` (SAN covers name: True) |
| `cursor.sh` | **L** resolves; TLSv1.3, ALPN `h2`, cert `cursor.sh` (SAN covers name: True) |
| `cursorapi.com` | apex has no address (normal for a suffix entry); documented probe `marketplace.cursorapi.com` queued for round 2 |
| `cursor-cdn.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `cursor-cdn.com` (SAN covers name: True) |
| `cursorvm.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |

## 10. Observed web-client hosts (dependency mapping)

- `https://cursor.com/dashboard`, loaded 2026-11-19 without signing in: HTTP None (page.goto: net::ERR_TUNNEL_CONNECTION_FAILED at https://cursor.com/dashboard), final host `chromewebdata`.

Pass 1 is a lower bound. The proxy refuses hosts not on the allowlist ("failed" below), so hosts that only scripts from a refused host would contact are missing.

| Host | Requests (refused) | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `api.workos.com` | 1 (1) | third party | no application | not checked | WorkOS, third-party sign-in provider |
| `cursor.com` | 2 (0) | app-owned | `cursor` |  |  |

## 11. Attributes (App-ID model) and re-verify date

- `cursor`: business-systems / generative-ai, browser-based; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `api.workos.com`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
