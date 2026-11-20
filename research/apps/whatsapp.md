# WhatsApp

- Content-pack id today: `whatsapp` (`whatsapp.com`, `whatsapp.net`)
- Status: **BLOCKED**, NAME. Low priority; research continues when the source is reachable
- Sources accessed: 2026-11-18

## 1. What it is

WhatsApp. See the catalog entry for its category.

## 2. Transport and ports

`UNVERIFIED`: the primary source could not be read.

## 3. Observable evidence

The FAQ page `https://faq.whatsapp.com/1299035810920553` rendered empty on 2026-11-18. The article id came from a search result and was not confirmed to be the network article.

## 4. Encrypted-traffic caveats

Not assessed beyond the README's shared facts.

## 5. Confidence and false-positive risks

| Observable | Level |
|---|---|
| Current pack names | **U** (not verified by this lane) |

## 6. Synthetic test vectors

Pending a readable source.

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L and J)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xwhatsapp.com` | not whatsapp (label boundary) | no application | PASS |
| L- | `whatsapp.com.example.invalid` | not whatsapp (suffix look-alike) | no application | PASS |
| L- | `xwhatsapp.net` | not whatsapp (label boundary) | no application | PASS |
| L- | `whatsapp.net.example.invalid` | not whatsapp (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- `https://faq.whatsapp.com/1299035810920553`: empty render, 2026-11-18

## 8. Catalog delta and recommendation

None. Next: Find the correct WhatsApp network-requirements article and retry.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `whatsapp.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.whatsapp.net` (SAN covers name: True) |
| `whatsapp.net` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.whatsapp.net` (SAN covers name: True) |

## 10. Observed web-client hosts (dependency mapping)

- `https://web.whatsapp.com/`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

## 11. Attributes (App-ID model) and re-verify date

- `whatsapp`: collaboration / instant-messaging, client-server; characteristics `widely-used`, `transfers-files`, `evasive`; **risk 3**: widely used by enterprises; moves files out of the organisation; designed to avoid inspection (relays, proxies or circumvention modes).
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
