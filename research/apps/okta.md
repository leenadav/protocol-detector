# Okta

- Content-pack id today: `okta` (`okta.com`, `oktacdn.com`, `oktapreview.com`)
- Status: **READY**, NAME, batch D
- Sources accessed: 2026-11-19

## 1. What it is

Identity provider (workforce SSO).

## 2. Transport and ports

HTTPS [S1].

## 3. Observable evidence

"Add these domains to your DNS allowlist" [S1]: `*.okta.com`, `*.mtls.okta.com`, `*.oktapreview.com`, `*.mtls.oktapreview.com`, `*.oktacdn.com`, `*.okta-emea.com`, `*.mtls.okta-emea.com`, `*.kerberos.okta.com`, `*.kerberos.okta-emea.com`, `*.kerberos.oktapreview.com`, `*.okta-gov.com`, `*.mtls.okta-gov.com`, `*.okta.mil`, `*.mtls.okta.mil`, `*.awsglobalaccelerator.com`.

## 4. Encrypted-traffic caveats

`<org>.okta.com` carries the customer's org name, which is never logged. `awsglobalaccelerator.com` is AWS (shared) and is not mapped.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under the Okta domains | **N3** | Sign-in, not an application's use |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `acme.okta-emea.com`, `x.okta.mil` | `okta`; the org label is not in the output |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M and N as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `login.okta.com` | one of `okta` | `okta` | PASS |
| L- | `xokta.com` | not okta (label boundary) | no application | PASS |
| L- | `okta.com.example.invalid` | not okta (suffix look-alike) | no application | PASS |
| L- | `xoktacdn.com` | not okta (label boundary) | no application | PASS |
| L- | `oktacdn.com.example.invalid` | not okta (suffix look-alike) | no application | PASS |
| L- | `xoktapreview.com` | not okta (label boundary) | no application | PASS |
| L- | `oktapreview.com.example.invalid` | not okta (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Okta Help, "Allow access to Okta IP addresses", `https://help.okta.com/en-us/content/topics/security/ip-address-allow-listing.htm`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("okta", ..., ("okta.com", "oktacdn.com", "oktapreview.com", "okta-emea.com", "okta-gov.com", "okta.mil")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 and 4 of 2026-11-21 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `research/live-results-2026-11-21-r4.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `okta.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `okta.com`, no subject organisation (domain-validated) (issuer Amazon) |
| `oktacdn.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `oktapreview.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `okta-emea.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `okta.com`, no subject organisation (domain-validated) (issuer Amazon) |
| `okta-gov.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `okta.mil` | **L** resolves; TLSv1.2, ALPN `h2`, cert `*.okta.mil`, subject organisation **Okta, Inc.** (issuer DigiCert Inc) |

## 10. Observed web-client hosts (dependency mapping)

- `https://login.okta.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `login.okta.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `login.okta.com` | seen | app-owned | `okta` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `okta`: business-systems / auth-service, browser-based; characteristics `widely-used`; **risk 1**: widely used by enterprises.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
