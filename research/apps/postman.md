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

## 7. Sources

- [S1] Postman Docs, "Firewall configuration", `https://learning.postman.com/docs/getting-started/installation/firewall`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

```python
("postman", ..., ("postman.com", "getpostman.com", "postman.co", "pstmn.io")),
```
