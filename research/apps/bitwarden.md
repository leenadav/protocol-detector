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

## 7. Sources

- [S1] Bitwarden Help, "Bitwarden Domains, Endpoints, & URLs", `https://bitwarden.com/help/bitwarden-addresses/`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

```python
("bitwarden", ..., ("bitwarden.com", "bitwarden.net", "bitwarden.eu", "btwrdn.com", "btwrdn.co")),
```
