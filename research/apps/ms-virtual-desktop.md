# Azure Virtual Desktop and Windows 365

- Content-pack id today: none (`*.wvd.microsoft.com` falls to `ms-base`; `*.windows.cloud.microsoft` to `ms-office365` through `cloud.microsoft`)
- Status: **READY**, NAME, batch I: new id `ms-virtual-desktop`
- Sources: accessed 2026-11-19; [S1] dated 2026-09-02, [S2] dated 2026-09-18 (page metadata)

## 1. What it is

Microsoft's hosted desktops: Azure Virtual Desktop (AVD), Windows 365 Cloud PCs, and the Windows App / Remote Desktop clients that connect to them.

## 2. Transport and ports

End-user devices [S1]: TCP 443 to the names below; UDP 3478 to `51.5.0.0/16` for "Relayed DS connectivity" (an address range, not a name). Session hosts also use TCP 1688 to `azkms.core.windows.net` (Windows activation) [S1].

## 3. Observable evidence

End-user devices [S1]: `*.service.windows.cloud.microsoft`, `*.windows.cloud.microsoft`, `*.windows.static.microsoft` ("Service Traffic"), `*.wvd.microsoft.com` ("Service traffic"), `login.microsoftonline.com`, `*.servicebus.windows.net` ("Troubleshooting data"), `go.microsoft.com`, `aka.ms`, `learn.microsoft.com`, `privacy.microsoft.com`, `*.cdn.office.net`. Session hosts [S1]: `*.wvd.microsoft.com` ("Service traffic including TCP based DS connectivity"), `wvdportalstorageblob.blob.core.windows.net` ("Azure portal support"), plus shared Azure monitoring, storage, certificate and update names. US Government: `*.wvd.azure.us`. Windows 365 [S2]: `*.infra.windows365.microsoft.com` ("provisioning of Cloud PCs and the Azure Network Connection (ANC) health checks"), `*.infra.windows365.microsoft.us` (Government), and `rdweb.` / `rdbroker.wvd.microsoft.com` and `.wvd.azure.us`.

## 4. Encrypted-traffic caveats

Desktop streaming over RDP Shortpath (UDP) and the relayed path (UDP 3478 to an address range) carries no AVD server name. `windows.cloud.microsoft` is the Windows App service domain; giving it its own id takes it away from `ms-office365`, which it matches today only through the generic `cloud.microsoft` suffix. Whether other Windows cloud features use `windows.cloud.microsoft` is `UNVERIFIED` (N2). Only the exact Microsoft-named blob host is proposed, never `blob.core.windows.net`. Shared Microsoft names (`login.microsoftonline.com`, `go.microsoft.com`, `aka.ms`, `*.servicebus.windows.net`, monitoring and KMS) are not proposed. The Azure IoT hosts that Windows 365 health checks use are shared `azure-devices.net` names and are not proposed.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `wvd.microsoft.com`, `wvd.azure.us` | **N3** | Broker, web feed and gateway |
| SNI under `infra.windows365.microsoft.com`, `infra.windows365.microsoft.us` | **N3** | Cloud PC provisioning and health checks |
| SNI under `windows.cloud.microsoft`, `windows.static.microsoft` | **N2** | Windows App; other uses unverified |
| SNI `wvdportalstorageblob.blob.core.windows.net` | **N3** (exact) | Portal support |
| UDP 3478 / RDP Shortpath | **U** | No name |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `rdweb.wvd.microsoft.com`, `rdbroker.wvd.azure.us` | `ms-virtual-desktop` (today `ms-base` / unmapped) |
| P2 | SNI `x.service.windows.cloud.microsoft`, `windows.cloud.microsoft` | `ms-virtual-desktop` (today `ms-office365`) |
| P3 | SNI `x.windows.static.microsoft`, `x.infra.windows365.microsoft.com`, `wvdportalstorageblob.blob.core.windows.net` | `ms-virtual-desktop` |
| N1 | SNI `teams.cloud.microsoft`, `x.cloud.microsoft` | `ms-teams`, `ms-office365` (unchanged) |
| N2 | SNI `x.blob.core.windows.net` | unmapped |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R and L)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xmicrosoft.com` | not ms-virtual-desktop (label boundary) | no application | PASS |
| L- | `wvd.microsoft.com.example.invalid` | not ms-virtual-desktop (suffix look-alike) | no application | PASS |
| L- | `xazure.us` | not ms-virtual-desktop (label boundary) | no application | PASS |
| L- | `wvd.azure.us.example.invalid` | not ms-virtual-desktop (suffix look-alike) | no application | PASS |
| L- | `xcloud.microsoft` | not ms-virtual-desktop (label boundary) | no application | PASS |
| L- | `windows.cloud.microsoft.example.invalid` | not ms-virtual-desktop (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Microsoft Learn, "Required FQDNs and endpoints for Azure Virtual Desktop", `https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint`, accessed 2026-11-19.
- [S2] Microsoft Learn, "Network requirements" (Windows 365), `https://learn.microsoft.com/en-us/windows-365/enterprise/requirements-network`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

```python
("ms-virtual-desktop", "networking", "remote-access", "client-server", 3, "Azure Virtual Desktop, Windows 365 and Windows App",
 ("tunnels-other-applications",),
 ("wvd.microsoft.com", "wvd.azure.us", "windows.cloud.microsoft", "windows.static.microsoft",
  "infra.windows365.microsoft.com", "infra.windows365.microsoft.us", "wvdportalstorageblob.blob.core.windows.net")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `wvd.microsoft.com` | apex has no address (normal for a suffix entry); documented probe `rdbroker.wvd.microsoft.com` queued for round 2 |
| `wvd.azure.us` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `windows.cloud.microsoft` | **L** resolves; TLSv1.3, ALPN `h2`, cert `windows.cloud.microsoft` (SAN covers name: True); CNAME into shared front end `mr-z01.tm-azurefd.net`: name usable, IPs never |
| `windows.static.microsoft` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `infra.windows365.microsoft.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `infra.windows365.microsoft.us` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `wvdportalstorageblob.blob.core.windows.net` | **L** resolves; TLSv1.3, ALPN `None`, cert `*.blob.core.windows.net` (SAN covers name: True) |

## 10. Observed web-client hosts (dependency mapping)

- `https://windows.cloud.microsoft/`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

## 11. Attributes (App-ID model) and re-verify date

- `ms-virtual-desktop`: networking / remote-access, client-server; characteristics `tunnels-other-applications`; **risk 3**: carries other traffic or remote control.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
