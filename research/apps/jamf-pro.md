# Jamf Pro

- Content-pack id today: none
- Status: **READY**, NAME, batch J: new id `jamf-pro`
- Sources: read by Research Lab from the Hermes server, relayed by Hermes, 2026-11-20 (PRO-29) (Fluid Topics content API); no page date shown

## 1. What it is

Apple device management (MDM) for macOS, iOS and iPadOS.

## 2. Transport and ports

443/TCP (Jamf Cloud) or 8443 (on-premises) for the web app and devices; 443 for Jamf services; APNs to Apple `17.0.0.0/8` on 5223 and 443 (clients) and 443/2197 (server) [J]. "All ports are TCP unless stated."

## 3. Observable evidence

[J]: `<instance>.jamfcloud.com` (Jamf Pro web app); `*.jamfcloud.com` and `*.jamf.com` for server-to-Jamf services, including `jamf-patch.jamfcloud.com` (patch database), `hw-model-names.services.jamfcloud.com`, APNs CSR and Push Proxy; `csa.services.jamfcloud.com`, `ics.services.jamfcloud.com` (Cloud Services connection, Icon Service); `registration.cloudconnector.services.jamfcloud.com` and `.gov.` (device compliance); `*.jra.services.jamfcloud.com` (Jamf Remote Assist); `appinstallers-packages.services.jamfcloud.com` (App Installers); `sentry.pub.jamf.build` ("crash logs/usage stats"); S3 names `icon-staging-production-use1-ics-application.s3.amazonaws.com`, `prod-custom-setting-schemas.s3.amazonaws.com`; Intune integration names (`login.microsoftonline.com`, `graph.microsoft.com`, `*.manage.microsoft.com`).

## 4. Encrypted-traffic caveats

Instance names (`<instance>.jamfcloud.com`) carry the customer's name: the catalog names the application only and never emits it. APNs is Apple's (`apple-push`), and the Intune names stay Microsoft's. The two S3 names are not vendor-named, so they are not proposed. `jamf.com` also serves marketing, so its apex and `www` are web fronts, as for the other device-management and remote-access vendors. Jamf Remote Assist (`jra`) is a remote-control function inside the same id. It is not separated, because only one subtree names it.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `jamfcloud.com` | **N3** | Web app, services, Remote Assist |
| SNI under `jamf.com` | **N2** | Services and marketing |
| Exact `sentry.pub.jamf.build` | **N3** (exact) | Telemetry |
| APNs, Intune names | other ids | Dependencies |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L and J): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `acme.jamfcloud.com`, `jamf-patch.jamfcloud.com`, `x.jra.services.jamfcloud.com` | `jamf-pro` |
| P2 | SNI `sentry.pub.jamf.build`, `www.jamf.com` | `jamf-pro` (`www` as a web front) |
| N1 | SNI `x.jamf.build`, `prod-custom-setting-schemas.s3.amazonaws.com`, `xjamfcloud.com` | not `jamf-pro` |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J and K)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xjamfcloud.com` | not jamf-pro (label boundary) | no application | PASS |
| L- | `jamfcloud.com.example.invalid` | not jamf-pro (suffix look-alike) | no application | PASS |
| L- | `xjamf.com` | not jamf-pro (label boundary) | no application | PASS |
| L- | `jamf.com.example.invalid` | not jamf-pro (suffix look-alike) | no application | PASS |
| L- | `xjamf.build` | not jamf-pro (label boundary) | no application | PASS |
| L- | `sentry.pub.jamf.build.example.invalid` | not jamf-pro (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [J] Jamf, "Network Ports Used by Jamf Pro", `https://learn.jamf.com/r/en-US/technical-articles/Network_Ports_Used_by_Jamf_Pro`, read by Research Lab from the Hermes server, relayed by Hermes, 2026-11-20 (PRO-29).

## 8. Catalog delta and recommendation

```python
("jamf-pro", "business-systems", "management", "client-server", 1, "Jamf Pro Apple device management",
 ("widely-used",), ("jamfcloud.com", "jamf.com", "sentry.pub.jamf.build"), ("jamf.com", "www.jamf.com")),
```

Risk 1 and category `management`, the same as `ms-intune`.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `jamfcloud.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `jamf.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `sentry.pub.jamf.build` | not in round 1 (added later; in `live-hosts-r2.txt`) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `jamf-pro`: business-systems / management, client-server; characteristics `widely-used`; **risk 1**: widely used by enterprises.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
