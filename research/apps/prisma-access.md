# Palo Alto Networks Prisma Access (Prisma Agent)

- Content-pack id today: none
- Status: **READY**, NAME, batch F (`research/patches/batch-f-name-based.patch`): new id `prisma-access`
- Sources accessed: 2026-11-19

## 1. What it is

Palo Alto Networks' SASE service and its endpoint agent (Prisma Agent; GlobalProtect deployments). For a gateway it
is a competing security tunnel worth naming.

## 2. Transport and ports

"443 HTTPS — Endpoint Manager, gateways, SSL tunnel"; "80 HTTP — captive portal detection"; "4501 MFA listening port";
local proxy from 9999; gateways also use "the dynamic ESP port specified in your gateway configuration" [S1].

## 3. Observable evidence

- Endpoint Manager ("manages enrollment, authentication, and communication for Prisma Agent endpoints"):
  `<tenant>.epm.gpcloudservice.com` on 443 [S1].
- Static URLs: `docs.paloaltonetworks.com` (support documentation), `www.paloaltonetworks.com` (privacy policy),
  `filter.paloaltonetworks.com` ("Network extension server address") [S1].
- Portals and gateways are the customer's own FQDNs (`<portal-fqdn>/global-protect/...`) [S1].

## 4. Encrypted-traffic caveats

The tenant label in `<tenant>.epm.gpcloudservice.com` is an identifier and is never logged. Customer portal and gateway
names are not catalog material. The tunnel itself is SSL on 443 or ESP [S1]. The agent sends `storage.googleapis.com`
outside the tunnel by default (a bypass host) [S1]; that is Google's, not Palo Alto evidence.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `epm.gpcloudservice.com` | **N3** agent enrollment and management | |
| SNI `filter.paloaltonetworks.com` | **N3** (exact) | |
| Other `gpcloudservice.com` names | **U** | Not mapped (portal and gateway naming not read) |
| `www.paloaltonetworks.com`, `docs.` | not mapped | Website |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `c08773f` plus D, E and F).

| # | Input | Expected |
|---|---|---|
| P1 | SNI `acme.epm.gpcloudservice.com` | `prisma-access`; the tenant label is not in the output |
| P2 | SNI `filter.paloaltonetworks.com` | `prisma-access` |
| N1 | SNI `x.gpcloudservice.com`, `www.paloaltonetworks.com` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J and K)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xgpcloudservice.com` | not prisma-access (label boundary) | no application | PASS |
| L- | `epm.gpcloudservice.com.example.invalid` | not prisma-access (suffix look-alike) | no application | PASS |
| L- | `xpaloaltonetworks.com` | not prisma-access (label boundary) | no application | PASS |
| L- | `filter.paloaltonetworks.com.example.invalid` | not prisma-access (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Palo Alto Networks TechDocs, "Prisma Agent FQDNs and Ports",
  `https://docs.paloaltonetworks.com/prisma-agent/administration/prerequisites/prisma-agent-fqdns-and-ports`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

```python
("prisma-access", "networking", "proxy", "client-server", 2, "Palo Alto Networks Prisma Access agent",
 ("tunnels-other-applications",), ("epm.gpcloudservice.com", "filter.paloaltonetworks.com")),
```

Metadata mirrors the existing `zscaler` and `netskope` entries (`networking/proxy`); it is this lane's proposal.

**Live result (2026-11-20): both names are NXDOMAIN.** Per RFC 8020, no name exists at or below either of
them, so neither can carry Prisma Access traffic as documented. Recommendation to the Engine lane: **drop the
`prisma-access` entry from patch F before applying it** (F is not yet implemented). The catalog cannot hold an
entry with no names (the parity case generator needs one), and rollback cannot restore a deleted entry, so a later
patch cannot remove it cleanly. Re-research when the documentation names live hosts. Round 2 (`live-hosts-r2.txt`)
re-checks both names first.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `epm.gpcloudservice.com` | **NXDOMAIN**: nothing at or below this name exists (RFC 8020); recommend removal after round 2 confirms |
| `filter.paloaltonetworks.com` | **NXDOMAIN**: nothing at or below this name exists (RFC 8020); recommend removal after round 2 confirms |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `prisma-access`: networking / proxy, client-server; characteristics `tunnels-other-applications`; **risk 2**: carries other traffic or remote control.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
