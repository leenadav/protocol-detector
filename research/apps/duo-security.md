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

## 7. Sources

- [S1] Duo Help, "What are Duo's IP ranges, hostnames, and data residency areas by deployment?", `https://help.duo.com/s/article/1337?language=en_US`, read by Hermes, relayed, 2026-11-19.

## 8. Catalog delta and recommendation

```python
("duo-security", ..., (), ("duosecurity.com",), ("www.duo.com",)),
```
