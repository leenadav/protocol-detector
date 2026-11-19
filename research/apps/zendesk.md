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

### Method v2 vectors (checked 2026-11-19 against `c08773f` plus batches D to I and retrofit R)

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

**BLOCKED in the research environment** (2026-11-19): its egress proxy re-terminates TLS, so a handshake would show the proxy, and direct DNS is not permitted. The tool is `research/tools/live_verify.py`; it runs from an unproxied vantage point or, DNS only, through an approved DoH resolver. No host below carries an `L` result yet.

Names to verify (catalog domains of `zendesk`): `zendesk.com`, `zdassets.com`.

## 10. Observed web-client hosts (dependency mapping)

- `https://www.zendesk.com/login/`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

## 11. Attributes (App-ID model) and re-verify date

- `zendesk`: business-systems / general-business, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): ECH support unknown until a live HTTPS-record check (section 9); other modes as stated in sections 2 to 4.
- Re-verify by: **2027-02-17** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
