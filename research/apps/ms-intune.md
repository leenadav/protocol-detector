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

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-19 against `c08773f` plus batches D to I and retrofit R)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xmicrosoft.com` | not ms-intune (label boundary) | no application | PASS |
| L- | `manage.microsoft.com.example.invalid` | not ms-intune (suffix look-alike) | no application | PASS |
| L- | `dm.microsoft.com.example.invalid` | not ms-intune (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Microsoft Learn, "Network endpoints for Microsoft Intune", `https://learn.microsoft.com/en-us/intune/fundamentals/endpoints`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("ms-intune", "business-systems", "management", "client-server", 1, "Microsoft Intune device management",
 ("widely-used",), ("manage.microsoft.com", "dm.microsoft.com")),
```

Metadata is this lane's proposal.

<!-- method-v2:start -->

## 9. Live verification (L)

**BLOCKED in the research environment** (2026-11-19): its egress proxy re-terminates TLS, so a handshake would show the proxy, and direct DNS is not permitted. The tool is `research/tools/live_verify.py`; it runs from an unproxied vantage point or, DNS only, through an approved DoH resolver. No host below carries an `L` result yet.

Names to verify (catalog domains of `ms-intune`): `manage.microsoft.com`, `dm.microsoft.com`.

## 10. Observed web-client hosts (dependency mapping)

- `https://intune.microsoft.com/`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

## 11. Attributes (App-ID model) and re-verify date

- `ms-intune`: business-systems / management, client-server; characteristics `widely-used`; **risk 1**: widely used by enterprises.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): ECH support unknown until a live HTTPS-record check (section 9); other modes as stated in sections 2 to 4.
- Re-verify by: **2027-02-17** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
