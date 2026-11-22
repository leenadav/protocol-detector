# BeyondTrust Remote Support (Cloud)

- Content-pack id today: `beyondtrust` (`beyondtrust.com`, `beyondtrustcloud.com`, `bomgar.com`)
- Status: **DONE**, verified, no catalog change
- Sources: [B] read in the research cloud (egress proxy), 2026-11-22; page updated 2026-07-16 (`dateModified`)

## 1. What it is

Attended and unattended remote support (formerly Bomgar). The cloud service runs each customer's B Series Appliance as a BeyondTrust-hosted site.

## 2. Transport and ports

Internal network to the cloud instance: "TCP Port 80 (optional)" (portal page, redirected to 443) and "TCP Port 443 (required) Used for all session traffic". Cloud instance to the internal network: TCP 25, 465 or 587 (optional, admin mail alerts) and TCP 443 (optional, outbound events to web services) [B].

## 3. Observable evidence

[B]: "Each SRA Cloud site comes with a subdomain of the BeyondTrust cloud DNS address, such as `yoursite.beyondtrustcloud.com`"; customers may point their own name at it with a CNAME. Atlas traffic nodes "use `(customerID)-region.beyondtrustcloud.com` for routing".

## 4. Encrypted-traffic caveats

Every session runs over 443 to a name under `beyondtrustcloud.com`, which is already mapped, so the page confirms the catalog and adds nothing. Site names carry the customer's name: the catalog names the application only. A customer's own CNAME (`access.example.com` with the customer's certificate) has no BeyondTrust name and is not identifiable by name. `beyondtrust.com` also serves the vendor's marketing site (existing behaviour; no web front change proposed).

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `beyondtrustcloud.com` | **N3** | Already mapped; sites and Atlas nodes |
| Customer CNAME to the site | **U** for names | Customer's name and certificate |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K, M, N, O and P): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `acme.beyondtrustcloud.com`, `acme-us.beyondtrustcloud.com` | `beyondtrust` |
| N1 | SNI `xbeyondtrustcloud.com`, `beyondtrustcloud.com.example.invalid` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O and P as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xbeyondtrust.com` | not beyondtrust (label boundary) | no application | PASS |
| L- | `beyondtrust.com.example.invalid` | not beyondtrust (suffix look-alike) | no application | PASS |
| L- | `xbeyondtrustcloud.com` | not beyondtrust (label boundary) | no application | PASS |
| L- | `beyondtrustcloud.com.example.invalid` | not beyondtrust (suffix look-alike) | no application | PASS |
| L- | `xbomgar.com` | not beyondtrust (label boundary) | no application | PASS |
| L- | `bomgar.com.example.invalid` | not beyondtrust (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [B] BeyondTrust Docs, "Cloud network infrastructure | RS Cloud", `https://docs.beyondtrust.com/rs/docs/cloud-network`, read in the research cloud (egress proxy), 2026-11-22.

## 8. Catalog delta and recommendation

None. `beyondtrustcloud.com` covers every listed name.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 6 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `beyondtrust.com` | not yet verified (added after round 2; in `live-hosts-r7.txt` for the next run) |
| `beyondtrustcloud.com` | not yet verified (added after round 2; in `live-hosts-r7.txt` for the next run) |
| `bomgar.com` | not yet verified (added after round 2; in `live-hosts-r7.txt` for the next run) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `beyondtrust`: networking / remote-access, client-server; characteristics `tunnels-other-applications`, `prone-to-misuse`; **risk 4**: carries other traffic or remote control; commonly misused (unsanctioned remote access, data exfiltration).
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
