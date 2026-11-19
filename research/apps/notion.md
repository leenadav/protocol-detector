# Notion

- Content-pack id today: `notion` (`notion.so`, `notion.site`)
- Status: **READY**, NAME, batch D
- Sources accessed: 2026-11-19

## 1. What it is

Workspace and documents app.

## 2. Transport and ports

HTTPS; fixed outgoing IP blocks are published [S1].

## 3. Observable evidence

"Notion IP addresses and domains" [S1]: `notion.com`, `notion.site`, `notion-custom.com`, `app.notion.com`, `api.notion.com`, `img.notionusercontent.com`, `notionusercontent.com`, `secure.notion-static.com`, `audioprocessor.app.notion.com`.

## 4. Encrypted-traffic caveats

`notion-custom.com` is not proposed: its name suggests customers' custom domains (tenant hosting), and the page does not say what it serves (`UNVERIFIED`). Only the exact `secure.notion-static.com` is proposed, not the whole `notion-static.com` domain.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `notion.com`, `notion.so`, `notionusercontent.com`; exact `secure.notion-static.com` | **N3** |  |
| `notion-custom.com` | **U** | Not mapped |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `www.notion.com`, `img.notionusercontent.com`, `secure.notion-static.com` | `notion` |
| N1 | SNI `x.notion-static.com`, `x.notion-custom.com` | no application |

## 7. Sources

- [S1] Notion Help, "Notion IP addresses & domains to allowlist", `https://www.notion.com/help/allowlist-ip`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("notion", ..., ("notion.so", "notion.site", "notion.com", "notionusercontent.com", "secure.notion-static.com")),
```
