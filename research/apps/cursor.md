# Cursor (AI code editor)

- Content-pack id today: `cursor` (`cursor.com`, `cursor.sh`)
- Status: **READY**, NAME, batch D
- Sources accessed: 2026-11-19

## 1. What it is

An AI-assisted code editor with hosted models and cloud agents.

## 2. Transport and ports

HTTPS. "Cursor uses HTTP/2 bidirectional streaming by default" and falls back to "HTTP/1.1 Server-Sent Events (SSE)" [S1].

## 3. Observable evidence

Allowlist [S1]: `*.cursor.sh`, `*.cursor-cdn.com`, `*.cursorapi.com`, `*.cursorvm.com`, `*.*.cursorvm.com`; SSL-inspection exclusions add `marketplace.cursorapi.com`, `authenticate.cursor.sh`, `authenticator.cursor.sh`, `cursor.com` and `*.cursor.com`. "Sign-in also uses `accounts.spacex.ai`, `accounts.x.ai`, and related auth hosts" [S1].

## 4. Encrypted-traffic caveats

**Attribution risk:** `accounts.x.ai` is under `x.ai`, which the pack maps to `xai-grok`, so a Cursor sign-in is logged as xAI Grok. It is recorded here with no change proposed (the host also serves xAI's own users). `accounts.spacex.ai` is not in the pack.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `cursor.sh`, `cursorapi.com`, `cursor-cdn.com`, `cursorvm.com` | **N3** Cursor |  |
| `accounts.x.ai` | **N2** | Shared with xAI |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `api2.cursor.sh`, `marketplace.cursorapi.com`, `x.cursor-cdn.com`, `a.b.cursorvm.com` | `cursor` |
| R1 | SNI `accounts.x.ai` | `xai-grok` (the recorded risk) |

## 7. Sources

- [S1] Cursor docs, "Network configuration", `https://cursor.com/docs/enterprise/network-configuration.md`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("cursor", ..., ("cursor.com", "cursor.sh", "cursorapi.com", "cursor-cdn.com", "cursorvm.com")),
```
