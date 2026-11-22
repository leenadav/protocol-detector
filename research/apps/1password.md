# 1Password

- Content-pack id today: `1password` (`1password.com`, `1password.eu`)
- Status: **READY**, NAME, batch D
- Sources accessed: 2026-11-19

## 1. What it is

Password manager.

## 2. Transport and ports

"add port 443 and the following domains to your allowlist" [S1].

## 3. Observable evidence

Per region [S1]: `*.1password.com` / `.eu` / `.ca` ("core 1Password service"), `*.1passwordservices.com` ("supporting services ... like Duo integration, telemetry, and subscription management"), `*.1passwordusercontent.com` / `.ca` / `.eu` ("user content ... like saved files"), app updates `app-updates.agilebits.com`, `app-updates.us.svc.1infra.net`, `*.1infra.net` ("infrastructure identification within 1Password's network"), `cache.agilebits.com` (item icons). Third-party integrations (Brex, Fastmail, LastPass, Privacy, Pwned Passwords) are not 1Password evidence.

## 4. Encrypted-traffic caveats

`agilebits.com` is 1Password's company domain, but only two exact hosts are listed, so only those are proposed.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under the 1Password domains listed | **N3** |  |
| `app-updates.agilebits.com`, `cache.agilebits.com` | **N3** (exact) |  |
| other `agilebits.com` | not mapped |  |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `my.1password.ca`, `x.1passwordservices.com`, `x.1passwordusercontent.eu`, `x.1infra.net`, `app-updates.agilebits.com` | `1password` |
| N1 | SNI `agilebits.com` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O and P as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `1password.com` | one of `1password` | `1password` | PASS |
| O+ | `accounts.1password.ca` | one of `1password` | `1password` | PASS |
| O+ | `accounts.1password.com` | one of `1password` | `1password` | PASS |
| O+ | `accounts.1password.eu` | one of `1password` | `1password` | PASS |
| O+ | `accounts.ent.1password.com` | one of `1password` | `1password` | PASS |
| O+ | `app.1password.com` | one of `1password` | `1password` | PASS |
| O+ | `my.1password.com` | one of `1password` | `1password` | PASS |
| D- | `images.ctfassets.net` | not 1password (third party) | no application | PASS |
| L- | `x1password.com` | not 1password (label boundary) | no application | PASS |
| L- | `1password.com.example.invalid` | not 1password (suffix look-alike) | no application | PASS |
| L- | `x1password.eu` | not 1password (label boundary) | no application | PASS |
| L- | `1password.eu.example.invalid` | not 1password (suffix look-alike) | no application | PASS |
| L- | `x1password.ca` | not 1password (label boundary) | no application | PASS |
| L- | `1password.ca.example.invalid` | not 1password (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] 1Password Support, "Ports and domains", `https://support.1password.com/ports-domains/`, "Published: August 18, 2026", accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("1password", ..., ("1password.com", "1password.eu", "1password.ca", "1passwordservices.com", "1passwordusercontent.com",
                      "1passwordusercontent.eu", "1passwordusercontent.ca", "1infra.net", "app-updates.agilebits.com", "cache.agilebits.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 6 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `1password.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `1password.com`, no subject organisation (domain-validated) (issuer Let's Encrypt) |
| `1password.eu` | **L** resolves; TLSv1.3, ALPN `h2`, cert `1password.eu`, no subject organisation (domain-validated) (issuer Amazon) |
| `1password.ca` | **L** resolves; TLSv1.3, ALPN `h2`, cert `1password.ca`, no subject organisation (domain-validated) (issuer Amazon) |
| `1passwordservices.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `1passwordusercontent.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `1passwordusercontent.eu` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `1passwordusercontent.ca` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `1infra.net` | apex has no address (normal for a suffix entry); suffix **verified** through documented `app-updates.us.svc.1infra.net` (round 2) |
| `app-updates.agilebits.com` | **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `app-updates-legacy.us.svc.1infra.net`, no subject organisation (domain-validated) (issuer Let's Encrypt) |
| `cache.agilebits.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `c.1password.com`, no subject organisation (domain-validated) (issuer Amazon) |

## 10. Observed web-client hosts (dependency mapping)

- `https://my.1password.com/signin`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `my.1password.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `1password.com` | seen | app-owned | `1password` |  |  |
| `accounts.1password.ca` | seen | app-owned | `1password` | not checked |  |
| `accounts.1password.com` | seen | app-owned | `1password` | not checked |  |
| `accounts.1password.eu` | seen | app-owned | `1password` | not checked |  |
| `accounts.ent.1password.com` | seen | app-owned | `1password` | not checked |  |
| `app.1password.com` | seen | app-owned | `1password` | not checked |  |
| `images.ctfassets.net` | seen | third party | no application | not checked | Contentful CMS assets |
| `my.1password.com` | seen | app-owned | `1password` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `1password`: business-systems / auth-service, client-server; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `images.ctfassets.net`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
