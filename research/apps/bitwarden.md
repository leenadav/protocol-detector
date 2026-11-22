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

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N and O as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `vault.bitwarden.com` | one of `bitwarden` | `bitwarden` | PASS |
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

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 6 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `bitwarden.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `bitwarden.com`, no subject organisation (domain-validated) (issuer Let's Encrypt) |
| `bitwarden.net` | apex has no address (normal for a suffix entry); suffix **verified** through documented `cdn.bitwarden.net` (round 2, ech,h3) |
| `bitwarden.eu` | **L** resolves; TLSv1.3, ALPN `h2`, cert `bitwarden.eu`, no subject organisation (domain-validated) (issuer Google Trust Services); HTTPS record carries `ech`: SNI may be an ECH outer name; HTTPS record offers `h3` (QUIC path) |
| `btwrdn.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `btwrdn.com`, no subject organisation (domain-validated) (issuer Let's Encrypt) |
| `btwrdn.co` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |

## 10. Observed web-client hosts (dependency mapping)

- `https://vault.bitwarden.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `vault.bitwarden.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `vault.bitwarden.com` | seen | app-owned | `bitwarden` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `bitwarden`: business-systems / auth-service, client-server; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): **ECH-capable** names (HTTPS record `ech`, 2026-11-20): `bitwarden.net`, `bitwarden.eu`, so `supports-ech` applies and SNI evidence may vanish; other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `bitwarden.net`, `bitwarden.eu`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
