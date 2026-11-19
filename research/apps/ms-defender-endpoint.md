# Microsoft Defender for Endpoint

- Content-pack id today: none (no catalog entry; `*.microsoft.com` falls to `ms-base`)
- Status: **READY**, NAME, batch D (`research/patches/batch-d-name-based.patch`): new id `ms-defender-endpoint`
- Sources accessed: 2026-11-19

## 1. What it is

Microsoft's endpoint detection and response sensor. Its presence on a device is a security-posture fact operators want, and its traffic should not be mistaken for generic Microsoft traffic.

## 2. Transport and ports

TCP 443 for the core services; certificate validation over TCP 80 [S1].

## 3. Observable evidence

"Core Defender for Endpoint services" on 443: `*.endpoint.security.microsoft.com`; "It is important to ensure connectivity to *.endpoint.security.microsoft.com is and remains possible" (streamlined connectivity). `reflector.defender.microsoft.com` is "Used by Microsoft Defender to probe IPv6 connectivity" [S1]. SmartScreen (`*.smartscreen.microsoft.com` and others), Windows Update, CRL and blob-storage hosts are listed too. They are shared with other Windows features or Azure storage, so they are not Defender evidence.

## 4. Encrypted-traffic caveats

Windows 10 versions 1607 to 1803 "require a longer list of URLs", many of them on `*.blob.core.windows.net` (shared Azure storage), so those devices are only partly visible [S1].

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `endpoint.security.microsoft.com` | **N3** sensor | Streamlined connectivity only |
| `reflector.defender.microsoft.com` | **N3** (exact) | IPv6 probe |
| SmartScreen, Windows Update, blob storage | do not map | Shared |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `x.endpoint.security.microsoft.com` | `ms-defender-endpoint` |
| P2 | SNI `reflector.defender.microsoft.com` | `ms-defender-endpoint` |
| N1 | SNI `security.microsoft.com`, `www.microsoft.com` | `ms-base` (unchanged) |

## 7. Sources

- [S1] Microsoft Learn, "Streamlined device connectivity URLs (commercial)", `https://learn.microsoft.com/en-us/defender-endpoint/streamlined-device-connectivity-urls-commercial`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("ms-defender-endpoint", "business-systems", "management", "client-server", 1, "Microsoft Defender for Endpoint",
 ("widely-used",), ("endpoint.security.microsoft.com", "reflector.defender.microsoft.com")),
```

Category `business-systems/management`, matching the existing `crowdstrike` and `sentinelone` entries. Metadata is this lane's proposal.
