# Netskope Client

- Content-pack id today: `netskope` (`netskope.com`, `goskope.com`)
- Status: **DONE** for `goskope.com` (verified; no change). `epdlp-prod.netskope.io` is **READY**, NAME, batch D (`research/patches/batch-d-name-based.patch`)
- Sources accessed: 2026-11-18

## 1. What it is

Netskope's endpoint client for its SSE service (Internet Security, Private Access, Endpoint DLP). On a
gateway it shows up as a competing security tunnel.

## 2. Transport and ports

TCP/443 to the client hosts. "TLS connectivity" and "DTLS connectivity to Netskope NewEdge data plane"
(UDP/443) go to Netskope data-centre subnets. DNS on UDP/53; ICMP and UDP 33434-33498 are used for path
telemetry [S1].

## 3. Observable evidence

"Netskope Client Firewall Allowlist Requirements" [S1]:

| Host (as published) | Purpose (as published) |
|---|---|
| `addon-<tenant>[.region].goskope.com` | "Downloading configuration files and dynamically detecting proxies" |
| `download-<tenant>[.region].goskope.com` | "Downloading client package updates" |
| `nsauth-<tenant>[.region].goskope.com` | "IdP-based Client Enrollment and Periodic Re-authentication for Private Apps" |
| `achecker-<tenant>[.region].goskope.com` | "Client enforcement" |
| `gateway.npa.goskope.com`, `*.npa.goskope.com` | Private Access data plane and enrollment |
| `gateway.gslb.goskope.com` | "GSLB latency-based Gateway Selection" |
| `epdlp.gslb.goskope.com`, `*.epdlp.goskope.com`, `epdlp-prod.netskope.io` | "Endpoint DLP connectivity and policy updates" |
| `enrollment.goskope.com`, `enrollment.*.goskope.com`, `enrollment.*.govskope.ca`, `enrollment.*.govskope.us` | "Secure Enrollment connectivity" |
| `*.googleapis.com`, `dns.google` | Google (third party) |

The page also notes: "We negotiate HTTP/2 for all domains if the origin server supports it" [S1].

## 4. Encrypted-traffic caveats

- **Tenant names appear in host names** (`addon-<tenant>...`). The application id may be logged; the tenant
  label is an identifier and must not be (AGENTS.md).
- The data plane is TLS or DTLS to NewEdge subnets, published as IP space, not names [S1].

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `goskope.com` | **N3** Netskope client | Already mapped |
| SNI `epdlp-prod.netskope.io` | **N3** (exact host) | Not mapped today |
| `govskope.ca`, `govskope.us` | **N2** | Government enrollment; only `enrollment.*` subdomains are listed, so the exact domains are not proposed |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `addon-acme.goskope.com` (synthetic tenant) | `netskope`; the tenant label is not in the output |
| P2 | SNI `epdlp-prod.netskope.io` | `netskope` (after the proposed entry) |
| N1 | SNI `x.netskope.io` | no application |

## 7. Sources

- [S1] Netskope Technical Documentation, "Netskope Client Network Configuration",
  `https://docs.netskope.com/en/netskope-client-network-configuration`, accessed 2026-11-18.

## 8. Catalog delta and recommendation

Batch D:

```python
("netskope", ..., ("netskope.com", "goskope.com", "epdlp-prod.netskope.io")),
```

`...` stands for the unchanged fields. No change to `goskope.com`.
