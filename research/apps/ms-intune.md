# Microsoft Intune

- Content-pack id today: none (`manage.microsoft.com` falls to `ms-base`)
- Status: **READY**, NAME, batch D: new id `ms-intune`
- Sources accessed: 2026-11-19

## 1. What it is

Microsoft's device-management (MDM/MAM) service.

## 2. Transport and ports

TCP 80 and 443 [S1].

## 3. Observable evidence

"If the firewall that you're using allows you to create firewall rules using a domain name, then use the *.manage.microsoft.com and manage.microsoft.com domain"; the required core row lists `*.manage.microsoft.com`, `manage.microsoft.com`, `*.dm.microsoft.com`, `EnterpriseEnrollment.manage.microsoft.com` [S1]. Delivery Optimization (`*.do.dsp.mp.microsoft.com`), `graph.microsoft.com`, notification and Office hosts are shared with other Microsoft services.

## 4. Encrypted-traffic caveats

"SSL traffic inspection isn't supported for '*.manage.microsoft.com', '*.dm.microsoft.com'" [S1]. Not relevant in the visibility phase, but important for later.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `manage.microsoft.com`, `dm.microsoft.com` | **N3** Intune |  |
| Delivery Optimization, Graph | do not map | Shared |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `enterpriseenrollment.manage.microsoft.com`, `x.dm.microsoft.com` | `ms-intune` |
| N1 | SNI `www.microsoft.com` | `ms-base` |

## 7. Sources

- [S1] Microsoft Learn, "Network endpoints for Microsoft Intune", `https://learn.microsoft.com/en-us/intune/fundamentals/endpoints`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("ms-intune", "business-systems", "management", "client-server", 1, "Microsoft Intune device management",
 ("widely-used",), ("manage.microsoft.com", "dm.microsoft.com")),
```

Metadata is this lane's proposal.
