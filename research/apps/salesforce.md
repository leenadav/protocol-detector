# Salesforce

- Content-pack id today: `salesforce` (`salesforce.com`, `force.com`)
- Status: **READY**, NAME, batch J (`research/patches/batch-j-relayed-rows-12-18.patch`): 22 Salesforce-operated domains added
- Sources: [S1] read by Hermes, relayed, 2026-11-19 ("Publish Date: Sep 15, 2026"); [S2] read by Research Lab from the Hermes server, relayed by Hermes, 2026-11-20 (PRO-29) (headless Chrome with a shadow-DOM walk); ports not stated

## 1. What it is

Salesforce CRM and platform (Sales, Service and Experience Cloud, Trailhead).

## 2. Transport and ports

Not stated as ports [S2]. [S1] is about IP allowlisting, which Salesforce discourages in favour of mTLS.

## 3. Observable evidence

"Allow the Required Domains" [S2], linked from article 000384438 [S1]: `app.salesforceiq.com` / `app-frankfurt.salesforceiq.com` (Inbox), `*.forceusercontent.com` (maps and location), `*.force-user-content.com` (user content), `*.my.salesforce.app` (web apps), `*.salesforceliveagent.com` (Chat, Omni-Channel, SOS), `*.salesforce-experience.com` (Experience Builder), `*.salesforce-hub.com` (Customer 360 Data Manager), `*.salesforce-scrt.com` (next-generation Omni-Channel), `*.salesforce-setup.com` (Setup), `*.salesforce-sites.com` (Sites), `*.sfdcopens.com` (email tracking, "reserved for future use"), `*.site.com` (Experience Cloud sites), `*.svc.sfdcfc.net` (Inbox email integration), `.trailblazer.me` (sign-up, login, profile), `*.trailhead.com` (myTrailhead); legacy (orgs without enhanced domains): `*.documentforce.com`, `*.lightning.com`, `*.salesforce-communities.com`, `*.sfdc.sh`, `*.visualforce.com`; login screen: `*.sfdcstatic.com`, `*.lightningdesignsystem.com`, `trailblazer-identity.my.site.com`. Third parties named for the mobile app and the login screen: Localytics, Bugsnag, Eloqua, Google, DoubleClick, Facebook, Google Analytics, Okta, OneTrust, Google Tag Manager. From [S1]: `[MyDomainName].secure.force.com`, Lightning CDN `*.static.lightning.force.com`, `Developer.Salesforce.com`, `Trailhead.Salesforce.com`.

## 4. Encrypted-traffic caveats

My Domain, Sites and Experience Cloud names (`*.my.salesforce.com`, `*.my.site.com`, `*.my.salesforce.app`) carry the customer's org or site name; the catalog names the application only. `site.com` hosts customer-branded Experience Cloud sites, so a match means Salesforce-hosted content, not that the user works in a Salesforce org (N2). `svc.sfdcfc.net` and `my.salesforce.app` are proposed as the exact subtrees listed, not their parents. The third parties are dependencies and are not proposed. The legacy domains stay, since orgs without enhanced domains still use them.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `salesforce.com`, `force.com` | **N3** | Already mapped |
| SNI under the 19 dedicated Salesforce domains | **N3** |  |
| SNI under `site.com`, `trailhead.com`, `trailblazer.me` | **N2** | Customer sites and learning or identity |
| Third-party login and mobile names | not mapped | Dependencies |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L and J): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `app.salesforceiq.com`, `x.my.salesforce.app`, `x.salesforce-scrt.com`, `x.svc.sfdcfc.net`, `x.visualforce.com` | `salesforce` (today unmapped) |
| P2 | SNI `acme.my.site.com`, `trailblazer-identity.my.site.com`, `trailblazer.me` | `salesforce` |
| N1 | SNI `x.salesforce.app`, `x.sfdcfc.net`, `analytics.localytics.com`, `secure.eloqua.com` | not `salesforce` |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J and K)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `c.salesforce.com` | one of `salesforce` | `salesforce` | PASS |
| O+ | `isr6.sfdc-qn0go2.salesforce.com` | one of `salesforce` | `salesforce` | PASS |
| O+ | `login.salesforce.com` | one of `salesforce` | `salesforce` | PASS |
| L- | `xsalesforce.com` | not salesforce (label boundary) | no application | PASS |
| L- | `salesforce.com.example.invalid` | not salesforce (suffix look-alike) | no application | PASS |
| L- | `xforce.com` | not salesforce (label boundary) | no application | PASS |
| L- | `force.com.example.invalid` | not salesforce (suffix look-alike) | no application | PASS |
| L- | `xsalesforceiq.com` | not salesforce (label boundary) | no application | PASS |
| L- | `salesforceiq.com.example.invalid` | not salesforce (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Salesforce Help, article 000384438 (IP addresses and domains to allow), `https://help.salesforce.com/s/articleView?id=000384438&type=1`, read by Hermes, relayed, 2026-11-19.
- [S2] Salesforce Help, "Allow the Required Domains", `https://help.salesforce.com/s/articleView?id=xcloud.setup_domains.htm&type=5`, read by Research Lab from the Hermes server, relayed by Hermes, 2026-11-20 (PRO-29).

## 8. Catalog delta and recommendation

```python
("salesforce", ..., ("salesforce.com", "force.com", "salesforceiq.com", "forceusercontent.com", "force-user-content.com",
 "my.salesforce.app", "salesforceliveagent.com", "salesforce-experience.com", "salesforce-hub.com", "salesforce-scrt.com",
 "salesforce-setup.com", "salesforce-sites.com", "sfdcopens.com", "site.com", "svc.sfdcfc.net", "trailblazer.me", "trailhead.com",
 "documentforce.com", "lightning.com", "salesforce-communities.com", "sfdc.sh", "visualforce.com", "sfdcstatic.com",
 "lightningdesignsystem.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `salesforce.com` | **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `salesforce.com` (SAN covers name: True) |
| `force.com` | **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `salesforce.com` (SAN covers name: True) |
| `salesforceiq.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `forceusercontent.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `force-user-content.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `my.salesforce.app` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `salesforceliveagent.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `salesforce-experience.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `salesforce-hub.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `salesforce-scrt.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `salesforce-setup.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `salesforce-sites.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `sfdcopens.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `site.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `svc.sfdcfc.net` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `trailblazer.me` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `trailhead.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `documentforce.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `lightning.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `salesforce-communities.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `sfdc.sh` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `visualforce.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `sfdcstatic.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |
| `lightningdesignsystem.com` | not in round 1 (added later; in `live-hosts-r2.txt`) |

## 10. Observed web-client hosts (dependency mapping)

- `https://login.salesforce.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `login.salesforce.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `c.salesforce.com` | seen | app-owned | `salesforce` | not checked |  |
| `isr6.sfdc-qn0go2.salesforce.com` | seen | app-owned | `salesforce` | not checked |  |
| `login.salesforce.com` | seen | app-owned | `salesforce` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `salesforce`: business-systems / general-business, browser-based; characteristics `widely-used`, `transfers-files`; **risk 2**: widely used by enterprises; moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
