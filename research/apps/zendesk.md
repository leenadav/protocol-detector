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


<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R and L)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xzendesk.com` | not zendesk (label boundary) | no application | PASS |
| L- | `zendesk.com.example.invalid` | not zendesk (suffix look-alike) | no application | PASS |
| L- | `xzdassets.com` | not zendesk (label boundary) | no application | PASS |
| L- | `zdassets.com.example.invalid` | not zendesk (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Zendesk help, "Configuring your firewall for use with Zendesk", `https://support.zendesk.com/hc/en-us/articles/4408842860186-Configuring-your-firewall-for-use-with-Zendesk` (read through the Help Center articles API), accessed 2026-11-19.

## 8. Catalog delta and recommendation

None: the current entry matches the source.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `zendesk.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `zendesk.com` (SAN covers name: True) |
| `zdassets.com` | apex has no address (normal for a suffix entry); documented probe `static.zdassets.com` queued for round 2 |

## 10. Observed web-client hosts (dependency mapping)

- `https://www.zendesk.com/login/`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

## 11. Attributes (App-ID model) and re-verify date

- `zendesk`: business-systems / general-business, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
