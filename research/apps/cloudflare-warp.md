# Cloudflare One Client (formerly WARP)

- Content-pack id today: `cloudflare-warp` (`cloudflareclient.com`)
- Status: **READY**, NAME, batch C (`research/patches/batch-c-name-based.patch`)
- Sources accessed: 2026-11-18

## 1. What it is

Cloudflare's device client for its Zero Trust service and consumer VPN. The page calls it "the Cloudflare
One Client (formerly WARP)" [S1]. Operators see it as an encrypted tunnel that bypasses the gateway.

## 2. Transport and ports

From [S1]:

| Use | Destination (as published) | Ports |
|---|---|---|
| Client orchestration API, outside the tunnel | SNIs `api.devices.cloudflare.com` (2026.6.0 and later); `zero-trust-client.cloudflareclient.com`, `notifications.cloudflareclient.com` (earlier versions); FedRAMP High: `api.devices.fed.cloudflare.com`, `notifications.devices.fed.cloudflare.com` | HTTPS |
| WireGuard tunnel | `162.159.193.0/24`, `2606:4700:100::/48` | UDP 2408; fallback UDP 500, 1701, 4500 |
| MASQUE tunnel | `162.159.197.0/24`, `2606:4700:102::/48` | UDP 443; fallback UDP 500, 1701, 4500, 4443, 8443, 8095, TCP 443 |
| Connectivity check outside the tunnel | `engage.cloudflareclient.com` | |
| Captive portal check | `cloudflareportal.com`, `cloudflareok.com`, `cloudflarecp.com`, plus Microsoft, Apple and Google check hosts | |

The client "overrides the resolved IPs" with the listed addresses for the API and DoH hosts [S1].

## 3. Observable evidence

- **SNI** of the orchestration API, on the CONNECT path when the client uses a proxy.
  `UNVERIFIED`: whether the API calls honour a system proxy. For the outside-tunnel check, the page says
  requests "will not use a proxy server, even if one is configured for the system" [S1].
- The tunnels themselves are UDP (WireGuard, MASQUE), except a TCP 443 MASQUE fallback [S1]. WireGuard is
  an engine family, but UDP is off the visibility-phase path.

## 4. Encrypted-traffic caveats

- `api.devices.cloudflare.com` sits under `cloudflare.com`, which the catalog treats as shared Cloudflare
  infrastructure. Only the exact vendor-named hosts are proposed. `cloudflare.com` itself stays unmapped.
- The captive-portal domains are listed without an ownership statement, alongside third-party check
  hosts. Not mapped.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `cloudflareclient.com` | **N3** | Unchanged |
| SNI `api.devices.cloudflare.com` and the two FedRAMP hosts | **N3** (exact hosts) | Client versions 2026.6.0 and later |
| `cloudflare.com` and other subdomains | do not map | Shared |
| UDP to the published ranges | later phase | |

## 6. Synthetic test vectors

Checked in scratch (batch C on `47b2743`): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `api.devices.cloudflare.com` | `cloudflare-warp` (today unmapped) |
| P2 | SNI `zero-trust-client.cloudflareclient.com`, `engage.cloudflareclient.com` | `cloudflare-warp` |
| N1 | SNI `www.cloudflare.com`, `devices.cloudflare.com` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O, P and Q as rebuilt 2026-11-24)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xcloudflareclient.com` | not cloudflare-warp (label boundary) | no application | PASS |
| L- | `cloudflareclient.com.example.invalid` | not cloudflare-warp (suffix look-alike) | no application | PASS |
| L- | `xcloudflare.com` | not cloudflare-warp (label boundary) | no application | PASS |
| L- | `api.devices.cloudflare.com.example.invalid` | not cloudflare-warp (suffix look-alike) | no application | PASS |
| L- | `api.devices.fed.cloudflare.com.example.invalid` | not cloudflare-warp (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Cloudflare docs, "Cloudflare One Client with firewall",
  `https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/index.md`, accessed 2026-11-18.

## 8. Catalog delta and recommendation

```python
("cloudflare-warp", "networking", "encrypted-tunnel", "client-server", 3, "Cloudflare WARP client endpoints",
 ("tunnels-other-applications", "evasive"),
 ("cloudflareclient.com", "api.devices.cloudflare.com", "api.devices.fed.cloudflare.com",
  "notifications.devices.fed.cloudflare.com")),
```

Optional, not in the patch: the description could follow the vendor's rename ("Cloudflare One Client (WARP)").

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `cloudflareclient.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `cloudflareclient.com`, no subject organisation (domain-validated) (issuer Let's Encrypt) |
| `api.devices.cloudflare.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `devices.cloudflare.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `api.devices.fed.cloudflare.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `devices.fed.cloudflare.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `notifications.devices.fed.cloudflare.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `devices.fed.cloudflare.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `cloudflare-warp`: networking / encrypted-tunnel, client-server; characteristics `tunnels-other-applications`, `evasive`; **risk 3**: carries other traffic or remote control; designed to avoid inspection (relays, proxies or circumvention modes).
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
