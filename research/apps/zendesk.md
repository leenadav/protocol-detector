# Zendesk

- Content-pack id today: `zendesk` (`zendesk.com`, `zdassets.com`)
- Status: **DONE** (no change), NAME
- Sources: accessed 2026-11-19; article updated 2026-11-17

## 1. What it is

Customer service platform.

## 2. Transport and ports

Not stated as ports. "Zendesk supports FQDN-based allowlists on a very limited basis" [S1].

## 3. Observable evidence

"assets.zendesk.com and static.zdassets.com must be reachable because Zendesk's web apps and related features load core static resources from those domains" [S1]. Customer instances are `{your-subdomain}.zendesk.com`. Some features use AWS S3 names (`uploaded-assets-*.s3.*.amazonaws.com`, `*-data-importer*.s3.*.amazonaws.com`).

## 4. Encrypted-traffic caveats

Subdomains of `zendesk.com` carry the customer's name; the catalog names the application only. The S3 names are wildcard patterns on shared S3, not vendor-named hosts, and are not proposed.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `zendesk.com`, `zdassets.com` | **N3** | Already mapped |

## 6. Synthetic test vectors

None (no catalog change).


## 7. Sources

- [S1] Zendesk help, "Configuring your firewall for use with Zendesk", `https://support.zendesk.com/hc/en-us/articles/4408842860186-Configuring-your-firewall-for-use-with-Zendesk` (read through the Help Center articles API), accessed 2026-11-19.

## 8. Catalog delta and recommendation

None: the current entry matches the source.
