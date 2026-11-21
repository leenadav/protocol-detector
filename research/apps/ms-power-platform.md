# Microsoft Power Platform and Dynamics 365

- Content-pack id today: none
- Status: **READY**, NAME, batch M: new id `ms-power-platform`
- Sources: [P1] read in the research cloud (egress proxy), 2026-11-21, ms.date 2026-08-03; [P2] ms.date 2026-01-12; [P3] ms.date 2026-05-13

## 1. What it is

Microsoft's low-code platform (Power Apps, Power Automate, Copilot Studio environments) and the Dynamics 365 business apps (Sales, Customer Service, Field Service, Marketing) that run on it.

## 2. Transport and ports

HTTPS on 443 [P2]. The pages give the service tags `PowerPlatformPlex` and `PowerPlatformInfra` and IPv6 support since April 2024 [P1, P3]; the catalog uses no IPs.

## 3. Observable evidence

[P2]: `api.bap.microsoft.com`, `*.api.bap.microsoft.com`, `*.powerapps.com` (`create`, `content`, `apps`, `make`, `*.gateway.prod.island.powerapps.com`, `*.harvest.powerapps.com`), `*.flow.microsoft.com`, `*.powerautomate.com`, `*.crm#.dynamics.com` (# = region number), `api.powerplatform.com`, `*.powerplatform.com`, `*.powerplatformusercontent.com`. [P1]: Dynamics 365 `https://*.crm#.dynamics.com`, `https://dynamics.microsoft.com`, `*.api.powerplatform.com`, `*.powerplatformusercontent.com`, `https://api.admin.powerplatform.microsoft.com`. [P3]: `*.flow.microsoft.com`, `*.powerautomate.com`, `*.powerapps.com`, `*.dynamics.com`, `*.api.bap.microsoft.com`; government `.us` names.

## 4. Encrypted-traffic caveats

Dynamics 365 org names (`<org>.crm4.dynamics.com`) and Power Pages sites carry the customer's name: the catalog names the application only and never emits it. `dynamics.com` is **N2**: it is Dynamics-wide (including marketing-site hosts), and Dynamics 365 is reported under the platform id rather than split per app. `dynamics.microsoft.com` (marketing) stays `ms-base`. Connector traffic goes through shared Azure API Management names (`azure-apim.net`, `azure-apihub.net`) and shared CDN, sign-in and Graph names, which are not proposed. Government (`.us`) and 21Vianet names are not proposed in this batch.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `powerapps.com`, `powerautomate.com`, `flow.microsoft.com` | **N3** | Makers, players, flows |
| SNI under `powerplatform.com`, `powerplatformusercontent.com`, exact BAP and admin API names | **N3** | Platform APIs |
| SNI under `dynamics.com` | **N2** | Dynamics-wide |
| `azure-apim.net`, `azure-apihub.net`, sign-in, Graph | not mapped | Shared |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K and M): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `make.powerapps.com`, `x.flow.microsoft.com`, `make.powerautomate.com` | `ms-power-platform` (today `ms-base` or unmapped) |
| P2 | SNI `acme.crm4.dynamics.com`, `api.bap.microsoft.com`, `x.api.powerplatform.com` | `ms-power-platform` (today unmapped) |
| N1 | SNI `bap.microsoft.com`, `dynamics.microsoft.com`, `x.azure-apim.net`, `xpowerapps.com` | not `ms-power-platform` |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K and M as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xpowerapps.com` | not ms-power-platform (label boundary) | no application | PASS |
| L- | `powerapps.com.example.invalid` | not ms-power-platform (suffix look-alike) | no application | PASS |
| L- | `xpowerautomate.com` | not ms-power-platform (label boundary) | no application | PASS |
| L- | `powerautomate.com.example.invalid` | not ms-power-platform (suffix look-alike) | no application | PASS |
| L- | `xmicrosoft.com` | not ms-power-platform (label boundary) | no application | PASS |
| L- | `flow.microsoft.com.example.invalid` | not ms-power-platform (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [P1] Microsoft Learn, "Power Platform URLs and IP address ranges", `https://learn.microsoft.com/en-us/power-platform/admin/online-requirements`, read in the research cloud (egress proxy), 2026-11-21.
- [P2] Microsoft Learn, "Power Apps system requirements and limits", `https://learn.microsoft.com/en-us/power-apps/limits-and-config`, read in the research cloud (egress proxy), 2026-11-21.
- [P3] Microsoft Learn, "IP address configuration" (Power Automate), `https://learn.microsoft.com/en-us/power-automate/ip-address-configuration`, read in the research cloud (egress proxy), 2026-11-21.

## 8. Catalog delta and recommendation

```python
("ms-power-platform", "business-systems", "office-programs", "browser-based", 2,
 "Microsoft Power Platform (Power Apps, Power Automate) and Dynamics 365", ("transfers-files",),
 ("powerapps.com", "powerautomate.com", "flow.microsoft.com", "powerplatform.com", "powerplatformusercontent.com",
  "api.bap.microsoft.com", "api.admin.powerplatform.microsoft.com", "dynamics.com")),
```

Same category, risk and characteristics as `power-bi`.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and round 4 of 2026-11-21 where it has the name (`research/live-results-2026-11-21-r4.tsv`, partial relay; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `powerapps.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `powerautomate.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `flow.microsoft.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `powerplatform.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `powerplatformusercontent.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `api.bap.microsoft.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `api.admin.powerplatform.microsoft.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `dynamics.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `ms-power-platform`: business-systems / office-programs, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
