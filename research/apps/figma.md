# Figma

- Content-pack id today: `figma` (`figma.com`)
- Status: **READY**, NAME, batch D (Figma for Government only); other listed domains are PARTIAL
- Sources accessed: 2026-11-19

## 1. What it is

Design and collaboration tool.

## 2. Transport and ports

HTTPS [S1].

## 3. Observable evidence

Allowlist [S1]: `*.figma.com`, `*.figma.site`, `*.makeproxy-c.figma.site`, `*.makeproxy-m.figma.site`, `*.awswaf.com`, `*.esm.sh`, `*.jsdelivr.net`, `*.figma.app`, `*.arkoselabs.com`, `*.weavy.ai`, `*.figmaweave.com`, `*.prodregistryv2.org`; "For those on the Figma for Government solution": `*.figma-gov.com`, `*.figma-gov.site`, `*.makeproxy-c.figma-gov.site`.

## 4. Encrypted-traffic caveats

The page gives no purpose per domain. `figma.site` and `figma-gov.site` may host customers' published sites (tenant hosting), and `figma.app`, `weavy.ai` and `figmaweave.com` are unexplained, so none is proposed. Third parties: AWS WAF, esm.sh, jsDelivr, Arkose Labs.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `figma.com` | **N3** | Already mapped |
| `figma-gov.com` | **N3** | Named for Figma for Government |
| `figma.site`, `figma.app`, `figmaweave.com`, `weavy.ai` | **U** for purpose | Not mapped |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `www.figma-gov.com` | `figma` |
| N1 | SNI `x.figma.site` | no application |

## 7. Sources

- [S1] Figma Learn, "Adjust your network settings", `https://help.figma.com/hc/en-us/articles/19424714305943-Adjust-your-network-settings`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("figma", ..., ("figma.com", "figma-gov.com")),
```
