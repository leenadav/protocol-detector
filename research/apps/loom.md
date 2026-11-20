# Loom

- Content-pack id today: none
- Status: **READY**, NAME, batch F: new id `loom`
- Sources accessed: 2026-11-19. Article "Updated on April 30, 2026"

## 1. What it is

Video messaging and screen recording (an Atlassian product).

## 2. Transport and ports

`wss` and HTTPS on 443 (the article also lists 80) [S1].

## 3. Observable evidence

"Domains, Protocols and Ports required for Loom" [S1]: `*.loom.com`, `www.loom.com`, `proxy.loom.com`,
`record.loom.com`, `location.loom.com`, `cdn.loom.com`, `packages.loom.com`, `luna.loom.com`,
`loom-media-production.s3-accelerate.amazonaws.com`, `object-store.atlassian.com`, plus third parties
(`icanhazip.com`, `cdn.segment.com`, `*.intercom.io`, `*.s3.us-west-2.amazonaws.com`, `*.logs.datadoghq.com`).

## 4. Encrypted-traffic caveats

Recordings upload to S3. Only the named bucket host is proposed, never the generic regional S3 wildcard.
`object-store.atlassian.com` already resolves to `atlassian`.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `loom.com` | **N3** | |
| SNI `loom-media-production.s3-accelerate.amazonaws.com` | **N3** (exact) | Media uploads |
| `object-store.atlassian.com` | `atlassian` | Shared Atlassian storage |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `www.loom.com`, `record.loom.com` | `loom` |
| P2 | SNI `loom-media-production.s3-accelerate.amazonaws.com` | `loom` |
| N1 | SNI `object-store.atlassian.com` | `atlassian` |

Checked in scratch (`c08773f` plus D, E and F).

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L and J)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xloom.com` | not loom (label boundary) | no application | PASS |
| L- | `loom.com.example.invalid` | not loom (suffix look-alike) | no application | PASS |
| L- | `xamazonaws.com` | not loom (label boundary) | no application | PASS |
| L- | `loom-media-production.s3-accelerate.amazonaws.com.example.invalid` | not loom (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Atlassian Support (Loom), "Domains, Protocols and Ports required for Loom to work on your servers",
  `https://support.atlassian.com/loom/kb/domains-protocols-and-ports-required-for-loom-to-work-on-your-servers/`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

```python
("loom", "collaboration", "voip-video", "browser-based", 2, "Loom video messaging",
 ("transfers-files",), ("loom.com", "loom-media-production.s3-accelerate.amazonaws.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `loom.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `loom.com` (SAN covers name: True); HTTPS record offers `h3` (QUIC path) |
| `loom-media-production.s3-accelerate.amazonaws.com` | **L** resolves; TLSv1.3, ALPN `None`, cert `*.s3-accelerate.amazonaws.com` (SAN covers name: True) |

## 10. Observed web-client hosts (dependency mapping)

- `https://www.loom.com/login`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

## 11. Attributes (App-ID model) and re-verify date

- `loom`: collaboration / voip-video, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `loom.com`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
