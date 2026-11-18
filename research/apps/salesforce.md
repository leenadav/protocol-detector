# Salesforce

- Content-pack id today: `salesforce` (`salesforce.com`, `force.com`)
- Status: **BLOCKED**, NAME. Low priority; research continues when the source is reachable
- Sources accessed: 2026-11-18

## 1. What it is

Salesforce. See the catalog entry for its category.

## 2. Transport and ports

`UNVERIFIED`: the primary source could not be read.

## 3. Observable evidence

Help article 000003652 (allowlisting IPs and domains) redirects to `https://help.salesforce.com/s/articleView?language=en_US&id=000384438&type=1`; the headless render returned an empty page on 2026-11-18 (client-side app). Not read; nothing paraphrased.

## 4. Encrypted-traffic caveats

Not assessed beyond the README's shared facts.

## 5. Confidence and false-positive risks

| Observable | Level |
|---|---|
| Current pack names | **U** (not verified by this lane) |

## 6. Synthetic test vectors

Pending a readable source.

## 7. Sources

- `https://help.salesforce.com/HTViewSolution?id=000003652` → `.../s/articleView?...id=000384438...`: empty render, 2026-11-18

## 8. Catalog delta and recommendation

None. Next: Retry with a different render wait, or a text copy from Lee.
