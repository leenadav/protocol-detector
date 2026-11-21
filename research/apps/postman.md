# Postman

- Content-pack id today: `postman` (`postman.com`, `getpostman.com`)
- Status: **READY**, NAME, batch H (`research/patches/batch-h-name-based.patch`)
- Sources: accessed 2026-11-19; page modified 2026-11-10 (page metadata)

## 1. What it is

API development platform (desktop app, web app, CLI, VS Code extension).

## 2. Transport and ports

"By default, WebSocket connections use the same ports as HTTP (80) and HTTPS (443)" [S1].

## 3. Observable evidence

"Allowlist the following domains for all versions of Postman to make WebSocket connections: *.getpostman.com, *.postman.co, *.pstmn.io, *.postman.com" [S1]. Postman v10 and later also list `bifrost-*` gateway hosts under `gw.postman.com`, `gw.postman.co` and `getpostman.com`; the EU instance uses `.eu` subdomains of the same four domains and `bifrost.gw.eu.postman.co` / `.com`. Sign-in also needs `challenges.cloudflare.com`; the coding-agent plugin needs `github.com` and `registry.npmjs.org` [S1].

## 4. Encrypted-traffic caveats

Requests a user sends from Postman go to whatever API they target; only Postman's own service names identify Postman. `challenges.cloudflare.com`, `github.com` and `registry.npmjs.org` are shared and not proposed. "There is no fixed IP range to allowlist for Postman" (AWS) [S1].

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `postman.com`, `getpostman.com` | **N3** | Already mapped |
| SNI under `postman.co`, `pstmn.io` | **N3** |  |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D, E, F, G and H): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `bifrost-web-v4.gw.postman.co`, `x.pstmn.io` | `postman` (today unmapped) |
| P2 | SNI `bifrost-v10.getpostman.com`, `bifrost.gw.eu.postman.com` | `postman` |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J and K as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `identity.getpostman.com` | one of `postman` | `postman` | PASS |
| D- | `challenges.cloudflare.com` | not postman (third party) | no application | PASS |
| D- | `hagen.challenges.cloudflare.com` | not postman (third party (unclassified)) | no application | PASS |
| L- | `xpostman.com` | not postman (label boundary) | no application | PASS |
| L- | `postman.com.example.invalid` | not postman (suffix look-alike) | no application | PASS |
| L- | `xgetpostman.com` | not postman (label boundary) | no application | PASS |
| L- | `getpostman.com.example.invalid` | not postman (suffix look-alike) | no application | PASS |
| L- | `xpostman.co` | not postman (label boundary) | no application | PASS |
| L- | `postman.co.example.invalid` | not postman (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Postman Docs, "Firewall configuration", `https://learning.postman.com/docs/getting-started/installation/firewall`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

```python
("postman", ..., ("postman.com", "getpostman.com", "postman.co", "pstmn.io")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `postman.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `postman.com`, no subject organisation (domain-validated) (issuer Let's Encrypt) |
| `getpostman.com` | resolves; TLS handshake failed (ConnectionResetError) in both rounds where checked: not a removal reason |
| `postman.co` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.postman.co`, no subject organisation (domain-validated) (issuer Amazon) |
| `pstmn.io` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |

## 10. Observed web-client hosts (dependency mapping)

- `https://identity.getpostman.com/login`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP None (page.goto: Timeout 45000ms exceeded.), final host `identity.getpostman.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `challenges.cloudflare.com` | seen | third party | no application | not checked | Cloudflare Turnstile bot check |
| `hagen.challenges.cloudflare.com` | seen | third party (unclassified) | no application | not checked |  |
| `identity.getpostman.com` | seen | app-owned | `postman` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `postman`: business-systems / software-development, client-server; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `challenges.cloudflare.com`, `hagen.challenges.cloudflare.com`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
