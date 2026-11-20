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

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J and K)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xnetskope.com` | not netskope (label boundary) | no application | PASS |
| L- | `netskope.com.example.invalid` | not netskope (suffix look-alike) | no application | PASS |
| L- | `xgoskope.com` | not netskope (label boundary) | no application | PASS |
| L- | `goskope.com.example.invalid` | not netskope (suffix look-alike) | no application | PASS |
| L- | `xnetskope.io` | not netskope (label boundary) | no application | PASS |
| L- | `epdlp-prod.netskope.io.example.invalid` | not netskope (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Netskope Technical Documentation, "Netskope Client Network Configuration",
  `https://docs.netskope.com/en/netskope-client-network-configuration`, accessed 2026-11-18.

## 8. Catalog delta and recommendation

Batch D:

```python
("netskope", ..., ("netskope.com", "goskope.com", "epdlp-prod.netskope.io")),
```

`...` stands for the unchanged fields. No change to `goskope.com`.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `netskope.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `netskope.com` (SAN covers name: True) |
| `goskope.com` | apex has no address (normal for a suffix entry); documented probe `enrollment.goskope.com` queued for round 2 |
| `epdlp-prod.netskope.io` | **L** resolves; TLSv1.3, ALPN `h2`, cert `epdlp-prod.netskope.io` (SAN covers name: True) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `netskope`: networking / proxy, client-server; characteristics `tunnels-other-applications`; **risk 2**: carries other traffic or remote control.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
