# WeTransfer

- Content-pack id today: `wetransfer` (`wetransfer.com`, `wetransfer.net`)
- Status: **BLOCKED**, NAME. The help article moved to `wetransfer.com/help-center`, which is not an allowed host in this session
- Sources accessed: 2026-11-18

## 1. What it is

Browser-based large-file transfer, a common exfiltration and shadow-IT concern.

## 2. Transport and ports

`UNVERIFIED`.

## 3. Observable evidence

`UNVERIFIED`. `https://help.wetransfer.com/hc/en-us/articles/205458203` answered HTTP 301 to
`https://wetransfer.com/help-center` on 2026-11-18, which this session cannot reach.

## 4. Encrypted-traffic caveats

Not assessed. If WeTransfer stores transfers in shared cloud storage, those hosts would name no
application under the v0.65 rule. This is a rule consequence, not a claim about WeTransfer.

## 5. Confidence and false-positive risks

| Observable | Level |
|---|---|
| Current pack names | **U** |

## 6. Synthetic test vectors

Pending sources.

## 7. Sources

- [BLOCKED] `https://help.wetransfer.com/hc/en-us/articles/205458203` → `https://wetransfer.com/help-center`, 2026-11-18.

## 8. Catalog delta and recommendation

None yet. Next step for this lane: allow `wetransfer.com` in the research environment and read its
help centre's firewall article. That is a routine host addition, done at the start of batch C.
