# Splashtop

- Content-pack id today: `splashtop` (`splashtop.com`; web fronts apex and `www`)
- Status: **READY**, NAME, batch G (`research/patches/batch-g-name-based.patch`)
- Sources: read by Hermes, relayed, 2026-11-19; the page shows "Today, 11:24 AM" (2026-11-19)

## 1. What it is

Remote access and remote support ("all Splashtop Cloud-based solutions").

## 2. Transport and ports

Required: "Port 443 (TCP) Primary control channel & data relay". Optional: TCP 6783 for same-network direct connections; TCP 9527-9528 local loopback only; "Port 3479 (UDP) & All UDP ports. Splashtop uses QUIC for optimized end-to-end connections". Port 80 (HTTP) for downloads and update checks from CloudFront. "All Splashtop Cloud traffic is outbound only." [S1]

## 3. Observable evidence

Domains [S1]: all regions `*.api.splashtop.com` (API and session services), `*.relay.splashtop.com` (data relay), `update.splashtop.com` and `update-g3.splashtop.com` (auto-updates); EU `*.api.splashtop.eu`; OC `*.api.splashtop.nr`; for China, also `*.api.splashtop.cn` and `*.relay.splashtop.cn`. Installers and updates are hosted on Amazon CloudFront. "Splashtop remote connections use TLS over port 443" and "Splashtop supports RSA-based certificates only".

## 4. Encrypted-traffic caveats

Only the listed subtrees are proposed for the `.eu`, `.nr` and `.cn` domains (`api.splashtop.eu`, `api.splashtop.nr`, `api.splashtop.cn`, `relay.splashtop.cn`), not their apexes, which the page does not list. CloudFront download hosts are not named on the page and stay unattributed. The end-to-end QUIC path on UDP 3479 is not on UDP 443; whether its Initial carries a Splashtop server name is `UNVERIFIED`.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `splashtop.com` | **N3** | Already mapped |
| SNI under `api.splashtop.eu`, `api.splashtop.nr`, `api.splashtop.cn`, `relay.splashtop.cn` | **N3** |  |
| UDP 3479 QUIC | **U** | Not verified |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D, E, F and G): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `st-1.api.splashtop.eu`, `a.api.splashtop.nr`, `a.relay.splashtop.cn` | `splashtop` (today unmapped) |
| P2 | SNI `update-g3.splashtop.com` | `splashtop` |
| N1 | SNI `www.splashtop.eu` | unmapped (apex not listed) |

## 7. Sources

- [S1] Splashtop Business Support, "What Are the Firewall Exceptions and IP addresses of Splashtop Servers/Services?", `https://support-splashtopbusiness.splashtop.com/hc/en-us/articles/115001811966-What-Are-the-Firewall-Exceptions-and-IP-addresses-of-Splashtop-Servers-Services`, read by Hermes, relayed, 2026-11-19.

## 8. Catalog delta and recommendation

```python
("splashtop", ..., ("splashtop.com", "api.splashtop.eu", "api.splashtop.nr", "api.splashtop.cn", "relay.splashtop.cn"), ("splashtop.com", "www.splashtop.com")),
```
