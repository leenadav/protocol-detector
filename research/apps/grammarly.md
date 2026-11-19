# Grammarly

- Content-pack id today: `grammarly` (`grammarly.com`, `grammarly.io`)
- Status: **BLOCKED** (no endpoint list in the source), NAME, low priority
- Sources: read by Hermes, relayed, 2026-11-19; the page shows no date

## 1. What it is

Writing assistant (browser extension, desktop and web).

## 2. Transport and ports

The page says only that a network administrator "can enable a specific web socket port" [S1]; no port is named.

## 3. Observable evidence

The relayed article body has no domain or endpoint list. It links a "WebSockets Support Q&A for System Administrators" article, which was not relayed [S1].

## 4. Encrypted-traffic caveats

Not assessed beyond the README's shared facts.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| Current pack names | **U** | Not verified by this lane |

## 6. Synthetic test vectors

None (no catalog change).


## 7. Sources

- [S1] Grammarly Support, "Network configuration blocks Grammarly services", `https://support.grammarly.com/hc/en-us/articles/115000090271-Network-configuration-blocks-Grammarly-services`, read by Hermes, relayed, 2026-11-19.

## 8. Catalog delta and recommendation

None. Next: the linked "WebSockets Support Q&A for System Administrators" article (URL unknown to this lane).
