# Windows Update and Delivery Optimization

- Content-pack id today: `ms-update` (`windowsupdate.com`, `update.microsoft.com`, `delivery.mp.microsoft.com`)
- Status: **READY**, NAME, batch H (`research/patches/batch-h-name-based.patch`)
- Sources: accessed 2026-11-19; [S1] dated 2026-02-12, [S2] dated 2026-04-07 (page metadata)

## 1. What it is

Windows Update and Delivery Optimization (DO), Windows' download and peer-caching service for updates and other Microsoft content.

## 2. Transport and ports

For Windows Update [S1]: `*.prod.do.dsp.mp.microsoft.com` TLS 1.2; `emdl.ws.microsoft.com` HTTP; `*.dl.delivery.mp.microsoft.com` HTTP; `*.windowsupdate.com` HTTP; `*.delivery.mp.microsoft.com` HTTPS; `*.update.microsoft.com` TLS 1.2; `tsfe.trafficshaping.dsp.mp.microsoft.com` TLS 1.2. "Be sure not to use HTTPS for those endpoints that specify HTTP, and vice versa." DO service: `*.do.dsp.mp.microsoft.com` "HTTPs / 443" [S2].

## 3. Observable evidence

[S1] lists the endpoints above "for Windows 10, version 2004" and notes that "The specific endpoints can vary between Windows client versions". [S2] (Connected Cache) lists `*.do.dsp.mp.microsoft.com` as the "Delivery Optimization Service", with "Note: TLS inspection will break this connection due to certificate pinning", and content on `*.dl.delivery.mp.microsoft.com` and `*.windowsupdate.com` (HTTP/80) for "Windows Update, Windows Defender, Windows Drivers, Windows Store".

## 4. Encrypted-traffic caveats

Payloads on HTTP/80 are named by the HTTP `Host` header, not SNI. The DO service (`do.dsp.mp.microsoft.com`) also coordinates downloads of Store, Edge and Microsoft 365 content, so the name means "Microsoft software delivery" (as the entry's description says), not Windows Update alone. DO peer-to-peer transfers (TCP 7680, from [S3]) carry no server name and are not proposed. `*.dsp.mp.microsoft.com` is not proposed as a whole: only the two sourced subtrees are.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI or Host under `windowsupdate.com`, `update.microsoft.com`, `delivery.mp.microsoft.com` | **N3** | Already mapped |
| SNI under `do.dsp.mp.microsoft.com`; SNI `tsfe.trafficshaping.dsp.mp.microsoft.com`; Host `emdl.ws.microsoft.com` | **N3** | Software delivery in general, not Windows Update alone |
| TCP 7680 peer traffic | **U** | No name |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D, E, F, G and H): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `kv601.prod.do.dsp.mp.microsoft.com`, `tsfe.trafficshaping.dsp.mp.microsoft.com` | `ms-update` (today `ms-base`) |
| P2 | Host `emdl.ws.microsoft.com` | `ms-update` (today `ms-base`) |
| P3 | Host `x.dl.delivery.mp.microsoft.com`, `ctldl.windowsupdate.com` | `ms-update` (already mapped) |

## 7. Sources

- [S1] Microsoft Learn, "Windows Update issues troubleshooting" (section "Device can't access update files"), `https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/windows-update-issues-troubleshooting`, accessed 2026-11-19.
- [S2] Microsoft Learn, "Microsoft Connected Cache content and services endpoints", `https://learn.microsoft.com/en-us/windows/deployment/do/delivery-optimization-endpoints`, accessed 2026-11-19.
- [S3] Microsoft Learn, "Delivery Optimization frequently asked questions" (port 7680), `https://learn.microsoft.com/en-us/windows/deployment/do/waas-delivery-optimization-faq`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

```python
("ms-update", ..., ("windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com", "do.dsp.mp.microsoft.com", "tsfe.trafficshaping.dsp.mp.microsoft.com", "emdl.ws.microsoft.com")),
```
