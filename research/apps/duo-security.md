# Cisco Duo

- Content-pack id today: `duo-security` (`duosecurity.com`)
- Status: **READY**, NAME, batch G (`research/patches/batch-g-name-based.patch`): web front only
- Sources: read by Hermes, relayed, 2026-11-19; the page shows no article date

## 1. What it is

Multi-factor authentication and SSO (Cisco Duo).

## 2. Transport and ports

"HTTPS on TCP/443 or LDAPS on TCP/636" as examples of ports "required by your Duo application" [S1].

## 3. Observable evidence

"We strongly recommend adding *.duosecurity.com wildcard domain, which should encompass all the various components and URLs that Duo's service uses" [S1]. Named subtrees: `*.sso.duosecurity.com`, `*.login.duosecurity.com`, `*.pwl.duosecurity.com`, `*.devicemanagement.duosecurity.com` (regional hosts such as `ue1.devicemanagement.duosecurity.com`), `*.azureauth.duosecurity.com` (regional). Each account has its own API hostname (shown in the Admin Panel). Custom SSO domains are the customer's own. "www.duo.com" is named among Duo's dynamic-IP services [S1].

## 4. Encrypted-traffic caveats

Per-account API hostnames are opaque identifiers; the catalog names the application only and must never emit the hostname as identity. Custom SSO domains are invisible to the catalog by design. Only the exact web front `www.duo.com` is proposed: the page names no other `duo.com` host, so the apex is not mapped.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `duosecurity.com` | **N3** | Already mapped |
| SNI `www.duo.com` | **N2** (web front) | Marketing site: provider affiliation only |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D, E, F and G): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `api-1234abcd.duosecurity.com` | `duo-security` |
| P2 | SNI `www.duo.com` | `duo-security` web front (today unmapped) |
| N1 | SNI `duo.com` | unmapped |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K and M as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `admin.duosecurity.com` | one of `duo-security` | `duo-security` | PASS |
| L- | `xduosecurity.com` | not duo-security (label boundary) | no application | PASS |
| L- | `duosecurity.com.example.invalid` | not duo-security (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Duo Help, "What are Duo's IP ranges, hostnames, and data residency areas by deployment?", `https://help.duo.com/s/article/1337?language=en_US`, read by Hermes, relayed, 2026-11-19.

## 8. Catalog delta and recommendation

```python
("duo-security", ..., (), ("duosecurity.com",), ("www.duo.com",)),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 and 4 of 2026-11-21 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `research/live-results-2026-11-21-r4.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `duosecurity.com` | **L** resolves; TLSv1.3, ALPN `None`, cert `www.duosecurity.com`, no subject organisation (domain-validated) (issuer Amazon) |

## 10. Observed web-client hosts (dependency mapping)

- `https://admin.duosecurity.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `admin.duosecurity.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `admin.duosecurity.com` | seen | app-owned | `duo-security` |  |  |

## 11. Attributes (App-ID model) and re-verify date

- `duo-security`: business-systems / auth-service, client-server; characteristics none; **risk 1**: no risk-raising characteristic recorded; rating from its category.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
