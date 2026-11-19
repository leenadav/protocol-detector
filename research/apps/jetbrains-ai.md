# JetBrains AI (AI Assistant, AI Enterprise)

- Content-pack id today: none for AI; `jetbrains` (`jetbrains.com`)
- Status: **READY**, NAME, batch F: new id `jetbrains-ai`
- Sources accessed: 2026-11-19

## 1. What it is

JetBrains' AI features in its IDEs. Generative-AI use by developers is a visibility question separate from the IDE vendor's
other traffic (licensing, plugins, downloads), in the same way that `github-copilot` is separate from `github`.

## 2. Transport and ports

HTTPS [S1].

## 3. Observable evidence

"api.jetbrains.ai and dynamic URLs – required for AI Enterprise functioning" [S1]. The same page lists IDE and Toolbox
hosts: `resources.`, `download.`, `plugins.`, `downloads.marketplace.`, `data.services.` and `account.jetbrains.com`.

## 4. Encrypted-traffic caveats

"Dynamic URLs" are not named [S1], so AI traffic to other hosts is not visible by name.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI `api.jetbrains.ai` | **N3** JetBrains AI | Only the named host |
| `jetbrains.com` names | `jetbrains` | IDE, licensing, plugins |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `api.jetbrains.ai` | `jetbrains-ai` |
| N1 | SNI `jetbrains.ai` | no application (only the exact host is sourced) |
| N2 | SNI `account.jetbrains.com` | `jetbrains` |

Checked in scratch (`c08773f` plus D, E and F).

## 7. Sources

- [S1] JetBrains, IDE Services Cloud Documentation, "Network access requirements",
  `https://www.jetbrains.com/help/ide-services-cloud/network-access-requirements.html`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

```python
("jetbrains-ai", "business-systems", "generative-ai", "client-server", 3, "JetBrains AI",
 ("transfers-files",), ("api.jetbrains.ai",)),
```
