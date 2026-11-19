# Salesforce

- Content-pack id today: `salesforce` (`salesforce.com`, `force.com`)
- Status: **DONE** (no change), NAME. The separate "Required Domains" help page is still unread (PARTIAL for that list)
- Sources: read by Hermes, relayed, 2026-11-19; "Publish Date: Sep 15, 2026"

## 1. What it is

Salesforce CRM and platform (first-party data centres and Hyperforce).

## 2. Transport and ports

Not stated as ports; the article is about IP allowlisting, which Salesforce discourages in favour of mTLS [S1].

## 3. Observable evidence

The article points to a separate "Salesforce Help Required Domains" list (not relayed). Names it gives itself [S1]: Force.com sites at `[MyDomainName].secure.force.com`; the Lightning CDN on CloudFront at `static.lightning.force.com`, `a.static.lightning.force.com`, `b.static.lightning.force.com`, `*.static.lightning.force.com`; "Salesforce URLs not in our infrastructure": `Developer.Salesforce.com`, `Trailhead.Salesforce.com`. IP ranges are listed per registry and in `https://ip-ranges.salesforce.com/ip-ranges.json`.

## 4. Encrypted-traffic caveats

Every name on the page is already under `salesforce.com` or `force.com`. My Domain names (`*.my.salesforce.com`, `*.secure.force.com`) carry the customer's org name; the catalog names the application only and never emits the org name. The catalog uses names only, so the IP lists are not used.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `salesforce.com`, `force.com` | **N3** | Already mapped; includes developer and Trailhead pages |

## 6. Synthetic test vectors

None (no catalog change).


## 7. Sources

- [S1] Salesforce Help, article 000384438 (IP addresses and domains to allow), `https://help.salesforce.com/s/articleView?id=000384438&type=1`, read by Hermes, relayed, 2026-11-19.

## 8. Catalog delta and recommendation

None. Next: the "Required Domains" help page it links to (URL not relayed), for any Salesforce-operated domain outside `salesforce.com` and `force.com`.
