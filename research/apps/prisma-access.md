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

## 7. Sources

- [S1] Palo Alto Networks TechDocs, "Prisma Agent FQDNs and Ports",
  `https://docs.paloaltonetworks.com/prisma-agent/administration/prerequisites/prisma-agent-fqdns-and-ports`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

```python
("prisma-access", "networking", "proxy", "client-server", 2, "Palo Alto Networks Prisma Access agent",
 ("tunnels-other-applications",), ("epm.gpcloudservice.com", "filter.paloaltonetworks.com")),
```

Metadata mirrors the existing `zscaler` and `netskope` entries (`networking/proxy`); it is this lane's proposal.
