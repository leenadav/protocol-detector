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


<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R and L)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xsalesforce.com` | not salesforce (label boundary) | no application | PASS |
| L- | `salesforce.com.example.invalid` | not salesforce (suffix look-alike) | no application | PASS |
| L- | `xforce.com` | not salesforce (label boundary) | no application | PASS |
| L- | `force.com.example.invalid` | not salesforce (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Salesforce Help, article 000384438 (IP addresses and domains to allow), `https://help.salesforce.com/s/articleView?id=000384438&type=1`, read by Hermes, relayed, 2026-11-19.

## 8. Catalog delta and recommendation

None. Next: the "Required Domains" help page it links to (URL not relayed), for any Salesforce-operated domain outside `salesforce.com` and `force.com`.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `salesforce.com` | **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `salesforce.com` (SAN covers name: True) |
| `force.com` | **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `salesforce.com` (SAN covers name: True) |

## 10. Observed web-client hosts (dependency mapping)

- `https://login.salesforce.com/`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

## 11. Attributes (App-ID model) and re-verify date

- `salesforce`: business-systems / general-business, browser-based; characteristics `widely-used`, `transfers-files`; **risk 2**: widely used by enterprises; moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
