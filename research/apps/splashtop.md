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

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R and L)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xsplashtop.com` | not splashtop (label boundary) | no application | PASS |
| L- | `splashtop.com.example.invalid` | not splashtop (suffix look-alike) | no application | PASS |
| L- | `xsplashtop.eu` | not splashtop (label boundary) | no application | PASS |
| L- | `api.splashtop.eu.example.invalid` | not splashtop (suffix look-alike) | no application | PASS |
| L- | `xsplashtop.nr` | not splashtop (label boundary) | no application | PASS |
| L- | `api.splashtop.nr.example.invalid` | not splashtop (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Splashtop Business Support, "What Are the Firewall Exceptions and IP addresses of Splashtop Servers/Services?", `https://support-splashtopbusiness.splashtop.com/hc/en-us/articles/115001811966-What-Are-the-Firewall-Exceptions-and-IP-addresses-of-Splashtop-Servers-Services`, read by Hermes, relayed, 2026-11-19.

## 8. Catalog delta and recommendation

```python
("splashtop", ..., ("splashtop.com", "api.splashtop.eu", "api.splashtop.nr", "api.splashtop.cn", "relay.splashtop.cn"), ("splashtop.com", "www.splashtop.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `splashtop.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.splashtop.com` (SAN covers name: True) |
| `api.splashtop.eu` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `api.splashtop.nr` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `api.splashtop.cn` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `relay.splashtop.cn` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |

## 10. Observed web-client hosts (dependency mapping)

- `https://my.splashtop.com/login`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

## 11. Attributes (App-ID model) and re-verify date

- `splashtop`: networking / remote-access, client-server; characteristics `tunnels-other-applications`, `prone-to-misuse`; **risk 4**: carries other traffic or remote control; commonly misused (unsanctioned remote access, data exfiltration).
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
