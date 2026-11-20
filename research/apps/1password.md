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

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L and J)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
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

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `1password.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `1password.com` (SAN covers name: True) |
| `1password.eu` | **L** resolves; TLSv1.3, ALPN `h2`, cert `1password.eu` (SAN covers name: True) |
| `1password.ca` | **L** resolves; TLSv1.3, ALPN `h2`, cert `1password.ca` (SAN covers name: True) |
| `1passwordservices.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `1passwordusercontent.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `1passwordusercontent.eu` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `1passwordusercontent.ca` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `1infra.net` | apex has no address (normal for a suffix entry); documented probe `app-updates.us.svc.1infra.net` queued for round 2 |
| `app-updates.agilebits.com` | **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `app-updates-legacy.us.svc.1infra.net` (SAN covers name: True) |
| `cache.agilebits.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `c.1password.com` (SAN covers name: True) |

## 10. Observed web-client hosts (dependency mapping)

- `https://my.1password.com/signin`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

## 11. Attributes (App-ID model) and re-verify date

- `1password`: business-systems / auth-service, client-server; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
