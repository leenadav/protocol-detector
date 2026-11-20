# Notion

- Content-pack id today: `notion` (`notion.so`, `notion.site`)
- Status: **READY**, NAME, batch D
- Sources accessed: 2026-11-19

## 1. What it is

Workspace and documents app.

## 2. Transport and ports

HTTPS; fixed outgoing IP blocks are published [S1].

## 3. Observable evidence

"Notion IP addresses and domains" [S1]: `notion.com`, `notion.site`, `notion-custom.com`, `app.notion.com`, `api.notion.com`, `img.notionusercontent.com`, `notionusercontent.com`, `secure.notion-static.com`, `audioprocessor.app.notion.com`.

## 4. Encrypted-traffic caveats

`notion-custom.com` is not proposed: its name suggests customers' custom domains (tenant hosting), and the page does not say what it serves (`UNVERIFIED`). Only the exact `secure.notion-static.com` is proposed, not the whole `notion-static.com` domain.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `notion.com`, `notion.so`, `notionusercontent.com`; exact `secure.notion-static.com` | **N3** |  |
| `notion-custom.com` | **U** | Not mapped |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `www.notion.com`, `img.notionusercontent.com`, `secure.notion-static.com` | `notion` |
| N1 | SNI `x.notion-static.com`, `x.notion-custom.com` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R and L)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xnotion.so` | not notion (label boundary) | no application | PASS |
| L- | `notion.so.example.invalid` | not notion (suffix look-alike) | no application | PASS |
| L- | `xnotion.site` | not notion (label boundary) | no application | PASS |
| L- | `notion.site.example.invalid` | not notion (suffix look-alike) | no application | PASS |
| L- | `xnotion.com` | not notion (label boundary) | no application | PASS |
| L- | `notion.com.example.invalid` | not notion (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Notion Help, "Notion IP addresses & domains to allowlist", `https://www.notion.com/help/allowlist-ip`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("notion", ..., ("notion.so", "notion.site", "notion.com", "notionusercontent.com", "secure.notion-static.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `notion.so` | **L** resolves; TLSv1.3, ALPN `h2`, cert `notion.so` (SAN covers name: True) |
| `notion.site` | **L** resolves; TLSv1.3, ALPN `h2`, cert `notion.site` (SAN covers name: True) |
| `notion.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `notion.com` (SAN covers name: True) |
| `notionusercontent.com` | apex has no address (normal for a suffix entry); documented probe `img.notionusercontent.com` queued for round 2 |
| `secure.notion-static.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |

## 10. Observed web-client hosts (dependency mapping)

- `https://www.notion.so/login`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

## 11. Attributes (App-ID model) and re-verify date

- `notion`: business-systems / office-programs, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
