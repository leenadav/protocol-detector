# Figma

- Content-pack id today: `figma` (`figma.com`)
- Status: **READY**, NAME, batch D (Figma for Government only); other listed domains are PARTIAL
- Sources accessed: 2026-11-19

## 1. What it is

Design and collaboration tool.

## 2. Transport and ports

HTTPS [S1].

## 3. Observable evidence

Allowlist [S1]: `*.figma.com`, `*.figma.site`, `*.makeproxy-c.figma.site`, `*.makeproxy-m.figma.site`, `*.awswaf.com`, `*.esm.sh`, `*.jsdelivr.net`, `*.figma.app`, `*.arkoselabs.com`, `*.weavy.ai`, `*.figmaweave.com`, `*.prodregistryv2.org`; "For those on the Figma for Government solution": `*.figma-gov.com`, `*.figma-gov.site`, `*.makeproxy-c.figma-gov.site`.

## 4. Encrypted-traffic caveats

The page gives no purpose per domain. `figma.site` and `figma-gov.site` may host customers' published sites (tenant hosting), and `figma.app`, `weavy.ai` and `figmaweave.com` are unexplained, so none is proposed. Third parties: AWS WAF, esm.sh, jsDelivr, Arkose Labs.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `figma.com` | **N3** | Already mapped |
| `figma-gov.com` | **N3** | Named for Figma for Government |
| `figma.site`, `figma.app`, `figmaweave.com`, `weavy.ai` | **U** for purpose | Not mapped |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `www.figma-gov.com` | `figma` |
| N1 | SNI `x.figma.site` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L and J)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xfigma.com` | not figma (label boundary) | no application | PASS |
| L- | `figma.com.example.invalid` | not figma (suffix look-alike) | no application | PASS |
| L- | `xfigma-gov.com` | not figma (label boundary) | no application | PASS |
| L- | `figma-gov.com.example.invalid` | not figma (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Figma Learn, "Adjust your network settings", `https://help.figma.com/hc/en-us/articles/19424714305943-Adjust-your-network-settings`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("figma", ..., ("figma.com", "figma-gov.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `figma.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.figma.com` (SAN covers name: True); HTTPS record offers `h3` (QUIC path) |
| `figma-gov.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.figma-gov.com` (SAN covers name: True); HTTPS record offers `h3` (QUIC path) |

## 10. Observed web-client hosts (dependency mapping)

- `https://www.figma.com/login`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

## 11. Attributes (App-ID model) and re-verify date

- `figma`: business-systems / office-programs, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `figma.com`, `figma-gov.com`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
