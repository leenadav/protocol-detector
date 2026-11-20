# Bitwarden

- Content-pack id today: `bitwarden` (`bitwarden.com`)
- Status: **READY**, NAME, batch E (`research/patches/batch-e-name-based.patch`)
- Sources accessed: 2026-11-19

## 1. What it is

Password manager (cloud, with self-hosting available).

## 2. Transport and ports

HTTPS [S1].

## 3. Observable evidence

"Bitwarden Domains" [S1]: `bitwarden.com | bitwarden.net | bitwarden.eu`, `btwrdn.co | btwrdn.com`. Endpoints include
`vault.bitwarden.com` / `vault.bitwarden.eu`, `api.bitwarden.com` / `api.bitwarden.eu`,
`events.bitwarden.com` / `events.bitwarden.eu`, `func.bitwarden.com`, `cdn.bitwarden.com`, `cdn.bitwarden.net`,
`artifacts.bitwarden.com`, `selfhost.bitwarden.com`, `charts.bitwarden.com`.

## 4. Encrypted-traffic caveats

Self-hosted Bitwarden servers use the customer's own domain and are invisible to the catalog by design.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `bitwarden.com`, `bitwarden.net`, `bitwarden.eu`, `btwrdn.com`, `btwrdn.co` | **N3** | Includes marketing and help pages |

## 6. Synthetic test vectors

Checked in scratch (`bc65e50` plus C, D and E): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `vault.bitwarden.eu`, `icons.bitwarden.net`, `x.btwrdn.co`, `btwrdn.com` | `bitwarden` (today unmapped except `bitwarden.com`) |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L and J)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xbitwarden.com` | not bitwarden (label boundary) | no application | PASS |
| L- | `bitwarden.com.example.invalid` | not bitwarden (suffix look-alike) | no application | PASS |
| L- | `xbitwarden.net` | not bitwarden (label boundary) | no application | PASS |
| L- | `bitwarden.net.example.invalid` | not bitwarden (suffix look-alike) | no application | PASS |
| L- | `xbitwarden.eu` | not bitwarden (label boundary) | no application | PASS |
| L- | `bitwarden.eu.example.invalid` | not bitwarden (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Bitwarden Help, "Bitwarden Domains, Endpoints, & URLs", `https://bitwarden.com/help/bitwarden-addresses/`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

```python
("bitwarden", ..., ("bitwarden.com", "bitwarden.net", "bitwarden.eu", "btwrdn.com", "btwrdn.co")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `bitwarden.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `bitwarden.com` (SAN covers name: True) |
| `bitwarden.net` | apex has no address (normal for a suffix entry); documented probe `cdn.bitwarden.net` queued for round 2 |
| `bitwarden.eu` | **L** resolves; TLSv1.3, ALPN `h2`, cert `bitwarden.eu` (SAN covers name: True); HTTPS record carries `ech`: SNI may be an ECH outer name; HTTPS record offers `h3` (QUIC path) |
| `btwrdn.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `btwrdn.com` (SAN covers name: True) |
| `btwrdn.co` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |

## 10. Observed web-client hosts (dependency mapping)

- `https://vault.bitwarden.com/`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

## 11. Attributes (App-ID model) and re-verify date

- `bitwarden`: business-systems / auth-service, client-server; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): **ECH-capable** names (HTTPS record `ech`, 2026-11-20): `bitwarden.eu`, so `supports-ech` applies and SNI evidence may vanish; other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `bitwarden.eu`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
