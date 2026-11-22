# Sophos Central (endpoint, EDR, XDR and MDR)

- Content-pack id today: `sophos` (`sophos.com`)
- Status: **READY**, NAME, batch N (`research/patches/batch-n-name-based.patch`): `sophosxl.com`, `sophosxl.net`, `sophosupd.com`, `sophosupd.net` and `hitmanpro.com` added
- Sources: read by Research Lab from the Hermes server, relayed by Hermes (PRO-108, PRO-121), 2026-11-21; page date Oct 22, 2026. Only the Endpoint/EDR/XDR/MDR section was read, and the MCS and live-terminal lists not in full

## 1. What it is

Sophos's cloud-managed endpoint protection (the page title now reads "Sophos Fusion Admin"; that this is the new name for Central is Research Lab's inference, `UNVERIFIED`), with EDR, XDR and MDR.

## 2. Transport and ports

443 (HTTPS) and 53 (DNS) [SC].

## 3. Observable evidence

[SC] core: `fusion.sophos.com`, `cloud-assets.sophos.com`, `sophos.com`, `downloads.sophos.com`, `login.sophos.com`. Wildcards: `*.sophos.com`, `*.sophosxl.com`, `*.sophosxl.net`, `*.sophosupd.com`, `*.sophosupd.net`, `*.hitmanpro.com`. Exact names include `t1.sophosupd.com`, `sus.sophosupd.com`, `sdds3.sophosupd.com`, `sdds3.sophosupd.net`, `sophosxl.net`, `4.sophosxl.net`, `samples.sophosxl.net`, `cloud.sophos.com`, `id.sophos.com`, `ssp.sophos.com`, `alert.hitmanpro.com`. Management Communication System (MCS): `mcs[2]-cloudstation-<region>.prod.hydra.sophos.com` (eu-west-1, eu-central-1, us-east-2, us-west-2), `mcs[2].stn100<code>.ctr.sophos.com` (syd, yul, hnd, gru, bom), `mcs-push-server-*`. Intelix `{us,apac,au,eu,}.analysis.sophos.com`; live terminal `live-terminal-<region>.prod.hydra.sophos.com`, `live-terminal.stn100*.ctr.sophos.com`. Non-Sophos: `az416426.vo.msecnd.net`, `dc.services.visualstudio.com`; CA sites `*.globalsign.com`, `*.globalsign.net`, `*.digicert.com`.

## 4. Encrypted-traffic caveats

All MCS, Intelix and live-terminal names fall under `sophos.com`, which is already mapped. The added domains are Sophos's update (`sophosupd`) and lookup (`sophosxl`) services. `hitmanpro.com` is a Sophos product domain that also serves the consumer HitmanPro scanner, so it is **N2** for Sophos Central. `sophosxl` lookups may also travel as DNS queries (port 53 is listed); the engine attributes by TLS SNI only, so those are not covered (`UNVERIFIED` how much of the lookup traffic is DNS). The two Microsoft names are Application Insights telemetry (see batch N: `dc.services.visualstudio.com` moves to `ms-telemetry`); the CA sites are shared. Live round 5 (2026-11-21): the `sdds3.sophosupd.com` certificate names SOPHOS LIMITED (Akamai front end); `samples.sophosxl.net` (CloudFront), `sdds3.sophosupd.net` (Amazon) and `cloud.sophos.com` (Amazon) have domain-validated certificates; `alert.hitmanpro.com` CNAMEs into Azure App Service (`alertcloud.azurewebsites.net`) with a domain-validated certificate, so `hitmanpro.com` stays **N2** and only the name is used, never the Azure targets or IPs. HitmanPro maps to the same `sophos` id, so it is not counted twice. `sophosxl.com` has no address and the page names no host under it: unverified.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `sophos.com` | **N3** | Already mapped; MCS and live terminal included |
| SNI under `sophosxl.com`, `sophosxl.net`, `sophosupd.com`, `sophosupd.net` | **N3** | Lookups and updates |
| SNI under `hitmanpro.com` | **N2** | Also a consumer product |
| Microsoft telemetry, CA sites | other ids or none | Shared |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K, M and N): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `mcs2-cloudstation-eu-west-1.prod.hydra.sophos.com`, `id.sophos.com` | `sophos` |
| P2 | SNI `sdds3.sophosupd.com`, `4.sophosxl.net`, `alert.hitmanpro.com` | `sophos` (today unmapped) |
| N1 | SNI `az416426.vo.msecnd.net`, `www.globalsign.com`, `xsophosxl.net` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N and O as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xsophos.com` | not sophos (label boundary) | no application | PASS |
| L- | `sophos.com.example.invalid` | not sophos (suffix look-alike) | no application | PASS |
| L- | `xsophosxl.com` | not sophos (label boundary) | no application | PASS |
| L- | `sophosxl.com.example.invalid` | not sophos (suffix look-alike) | no application | PASS |
| L- | `xsophosxl.net` | not sophos (label boundary) | no application | PASS |
| L- | `sophosxl.net.example.invalid` | not sophos (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [SC] Sophos, "Domains and ports to allow", `https://doc.sophos.com/central/customer/help/en-us/PeopleAndDevices/ProtectDevices/DomainsPorts/`, read by Research Lab from the Hermes server, relayed by Hermes (PRO-108, PRO-121), 2026-11-21.

## 8. Catalog delta and recommendation

```python
("sophos", ..., ("sophos.com", "sophosxl.com", "sophosxl.net", "sophosupd.com", "sophosupd.net", "hitmanpro.com")),
("ms-telemetry", ..., ("events.data.microsoft.com", "vortex.data.microsoft.com", "dc.services.visualstudio.com")),
```

`dc.services.visualstudio.com` is listed as non-Sophos here and as "Service telemetry" on the Power BI page, so it moves from `visual-studio` (by the `visualstudio.com` suffix) to `ms-telemetry` (**N2**).

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 6 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `sophos.com` | round 5 (2026-11-21); **L** resolves; TLSv1.2, TLS via documented probe `cloud.sophos.com`, probe cert `central.sophos.com`, no subject organisation (domain-validated) (issuer Amazon) |
| `sophosxl.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `sophosxl.net` | apex has no address (normal for a suffix entry); suffix **verified** through documented `samples.sophosxl.net` (round 5, cdn) |
| `sophosupd.com` | apex has no address (normal for a suffix entry); suffix **verified** through documented `sdds3.sophosupd.com` (round 5, cdn); probe certificate subject organisation **SOPHOS LIMITED** |
| `sophosupd.net` | apex has no address (normal for a suffix entry); suffix **verified** through documented `sdds3.sophosupd.net` (round 5) |
| `hitmanpro.com` | round 5 (2026-11-21); **L** resolves; TLSv1.3, TLS via documented probe `alert.hitmanpro.com`, probe cert `alert.hitmanpro.com`, no subject organisation (domain-validated) (issuer DigiCert Inc) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `sophos`: business-systems / management, client-server; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
