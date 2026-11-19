# 1Password

- Content-pack id today: `1password` (`1password.com`, `1password.eu`)
- Status: **READY**, NAME, batch D
- Sources accessed: 2026-11-19

## 1. What it is

Password manager.

## 2. Transport and ports

"add port 443 and the following domains to your allowlist" [S1].

## 3. Observable evidence

Per region [S1]: `*.1password.com` / `.eu` / `.ca` ("core 1Password service"), `*.1passwordservices.com` ("supporting services ... like Duo integration, telemetry, and subscription management"), `*.1passwordusercontent.com` / `.ca` / `.eu` ("user content ... like saved files"), app updates `app-updates.agilebits.com`, `app-updates.us.svc.1infra.net`, `*.1infra.net` ("infrastructure identification within 1Password's network"), `cache.agilebits.com` (item icons). Third-party integrations (Brex, Fastmail, LastPass, Privacy, Pwned Passwords) are not 1Password evidence.

## 4. Encrypted-traffic caveats

`agilebits.com` is 1Password's company domain, but only two exact hosts are listed, so only those are proposed.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under the 1Password domains listed | **N3** |  |
| `app-updates.agilebits.com`, `cache.agilebits.com` | **N3** (exact) |  |
| other `agilebits.com` | not mapped |  |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `my.1password.ca`, `x.1passwordservices.com`, `x.1passwordusercontent.eu`, `x.1infra.net`, `app-updates.agilebits.com` | `1password` |
| N1 | SNI `agilebits.com` | no application |

## 7. Sources

- [S1] 1Password Support, "Ports and domains", `https://support.1password.com/ports-domains/`, "Published: August 18, 2026", accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("1password", ..., ("1password.com", "1password.eu", "1password.ca", "1passwordservices.com", "1passwordusercontent.com",
                      "1passwordusercontent.eu", "1passwordusercontent.ca", "1infra.net", "app-updates.agilebits.com", "cache.agilebits.com")),
```
