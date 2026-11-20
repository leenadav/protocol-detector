# Cisco Umbrella (roaming client, Secure Client module, SWG)

- Content-pack id today: `opendns` (`opendns.com`; description "Cisco OpenDNS resolver and dashboard")
- Status: **READY**, NAME, batch J (`research/patches/batch-j-relayed-rows-12-18.patch`): `umbrella.com` added to `opendns`; description updated
- Sources: read by Research Lab from the Hermes server, relayed by Hermes, 2026-11-20 (PRO-29); no page dates shown

## 1. What it is

Cisco's DNS-layer security and secure web gateway: the roaming client and the Secure Client Umbrella module send DNS to Umbrella resolvers and reach its API; the SWG proxies web traffic.

## 2. Transport and ports

Roaming client DNS to `208.67.222.222`, `208.67.220.220`, `2620:119:53::53`, `2620:119:35::35` on 53/UDP and 53/TCP, and "optional encryption of DNS queries" on 443/UDP and 443/TCP ("auto when 443/UDP open") [U1]. API on 443/TCP [U1]. SWG/SIG ranges on 80 and 443/TCP [U2, U3].

## 3. Observable evidence

[U1]: `disthost.umbrella.com`, `api.opendns.com`, `disthost.opendns.com` ("must resolve via local DNS"; registration, version check, status, internal domains); `debug.opendns.com` ("must get a TXT response (NXDOMAIN ok)"); `sync.hydra.opendns.com` (API, Anycast). Bypass lists [U2, U3]: `*.cisco.com`, `*.opendns.com`, `*.umbrella.com`, `isrg.trustid.ocsp.identrust.com`; Secure Client also `www.msftconnecttest.com`, `connecttest.cisco.io` [U3]. Identity-provider examples to keep direct (third parties): `*.okta.com`, `*.oktacdn.com`, `*.pingidentity.com`, `secure.aadcdn.microsoftonline-p.com`.

## 4. Encrypted-traffic caveats

The resolver traffic is addressed **by IP**: plain DNS to the anycast resolvers carries no Umbrella server name, and the catalog uses no IPs. The DNS-over-443 path is named only where it uses TLS with an Umbrella SNI (not stated, `UNVERIFIED`). `cisco.com` is Cisco-wide and is not mapped to Umbrella. `connecttest.cisco.io` (a Secure Client connectivity test) and Microsoft's `www.msftconnecttest.com` are not Umbrella names. SWG traffic is proxied web traffic for other applications, so its server names are those applications'.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `opendns.com` | **N3** | Already mapped |
| SNI under `umbrella.com` | **N3** | Roaming client API, dashboards |
| DNS to the resolver IPs | **U** for names | Address only; never used |
| `cisco.com`, `cisco.io` | not mapped | Vendor-wide |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L and J): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `disthost.umbrella.com`, `dashboard.umbrella.com` | `opendns` (today unmapped) |
| P2 | SNI `api.opendns.com`, `sync.hydra.opendns.com` | `opendns` |
| N1 | SNI `connecttest.cisco.io`, `www.msftconnecttest.com`, `xumbrella.com` | not `opendns` |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L and J)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xopendns.com` | not opendns (label boundary) | no application | PASS |
| L- | `opendns.com.example.invalid` | not opendns (suffix look-alike) | no application | PASS |
| L- | `xumbrella.com` | not opendns (label boundary) | no application | PASS |
| L- | `umbrella.com.example.invalid` | not opendns (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [U1] Cisco Umbrella, "Network Access" (roaming client), `https://securitydocs.cisco.com/docs/umbrella-sig/olh/152386.dita`, read by Research Lab from the Hermes server, relayed by Hermes, 2026-11-20 (PRO-29).
- [U2] Cisco Umbrella, "Network Requirements" (SWG), `https://securitydocs.cisco.com/docs/umbrella-sig/olh/152709.dita`, read by Research Lab from the Hermes server, relayed by Hermes, 2026-11-20 (PRO-29).
- [U3] Cisco Umbrella, "Roaming Client Prerequisites" (Secure Client Umbrella module), `https://securitydocs.cisco.com/docs/umbrella-sig/olh/152715.dita`, read by Research Lab from the Hermes server, relayed by Hermes, 2026-11-20 (PRO-29).

## 8. Catalog delta and recommendation

```python
("opendns", ..., "Cisco Umbrella and OpenDNS resolver, roaming client and dashboard", ("evasive",), ("opendns.com", "umbrella.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `opendns.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `umbrella.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |

## 10. Observed web-client hosts (dependency mapping)

- `https://dashboard.umbrella.com/`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

## 11. Attributes (App-ID model) and re-verify date

- `opendns`: networking / infrastructure, client-server; characteristics `evasive`; **risk 3**: designed to avoid inspection (relays, proxies or circumvention modes).
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
