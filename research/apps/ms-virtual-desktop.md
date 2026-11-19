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
