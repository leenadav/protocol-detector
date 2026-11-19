# Canva

- Content-pack id today: `canva` (`canva.com`)
- Status: **READY**, NAME, batch G (`research/patches/batch-g-name-based.patch`)
- Sources: read by Hermes, relayed, 2026-11-19; the page shows no date

## 1. What it is

Online design platform.

## 2. Transport and ports

HTTPS; "Make sure WebSockets are enabled for: www.canva.com:443" [S1].

## 3. Observable evidence

"Make sure your firewall allows these Canva domains" [S1]: `*.canva.com` (all subdomains), `*.canvacode.com` ("Required for some Canva AI features"), `*.canva-apps.com` ("Required to use Canva Apps"), `challenges.cloudflare.com` ("Required for Cloudflare security check"), `*.canva.link` ("design share links"), `*.canva.ai` ("Canva AI features"). "Some Canva Apps use additional third-party domains."

## 4. Encrypted-traffic caveats

`challenges.cloudflare.com` is Cloudflare's shared challenge service and is not proposed. `canva-apps.com` hosts apps on Canva's platform, some of them by third parties; it is still Canva's own domain.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `canva.com` | **N3** | Already mapped |
| SNI under `canvacode.com`, `canva-apps.com`, `canva.link`, `canva.ai` | **N3** | Share links also match when opened by a browser |
| `challenges.cloudflare.com` | not Canva | Shared |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D, E, F and G): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `www.canva.com` | `canva` |
| P2 | SNI `x.canvacode.com`, `x.canva-apps.com`, `canva.link`, `canva.ai` | `canva` (today unmapped) |
| N1 | SNI `challenges.cloudflare.com` | unmapped |

## 7. Sources

- [S1] Canva Help Center, "Allow Canva through your firewall", `https://www.canva.com/help/allow-canva-through-firewall/`, read by Hermes, relayed, 2026-11-19.

## 8. Catalog delta and recommendation

```python
("canva", ..., ("canva.com", "canvacode.com", "canva-apps.com", "canva.link", "canva.ai")),
```
