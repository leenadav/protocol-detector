# Amazon WorkSpaces

- Content-pack id today: none
- Status: **READY**, NAME, batch I: new id `amazon-workspaces` (regional API hosts: DECISION, see section 8)
- Sources: accessed 2026-11-19

## 1. What it is

AWS-hosted virtual desktops (PCoIP and DCV), with desktop clients and Web Access.

## 2. Transport and ports

[S1]: PCoIP streaming TCP and UDP 4172 ("do not support the use of a proxy server nor TLS decryption and inspection for port 4172 traffic in UDP"); PCoIP client UDP 50002 and 55002; DCV streaming TCP and UDP 4195 ("TLS decryption and inspection are not supported"); "The WorkSpaces client application first attempts to stream using UDP (QUIC)"; "The WorkSpaces web client will connect over TCP port 4195 or 443"; Web Access port 80 for the first connection to `https://clients.amazonworkspaces.com`, then 443.

## 3. Observable evidence

"Domains and IP addresses to add to your allow list" [S1]: `connectivity.amazonworkspaces.com` (connectivity check), `clients.amazonworkspaces.com`, per-region `skylight-client-ds.<region>.amazonaws.com` and `skylight-client-ds.<region>.api.aws` (IPv6), the Dynamic Messaging Service `ws-client-service.<region>.amazonaws.com`, regional `<region>.signin.aws.amazon.com`, S3 names (`opfcaptcha-prod.s3.amazonaws.com`, `s3.amazonaws.com/workspaces-client-properties/...`, `workspace-client-assets-pdt.s3-us-gov-*.amazonaws.com`) and CloudFront distributions (`d2td7dqidlhjx7.cloudfront.net` for client auto-update, and per-region login-page distributions). "DCV gateway domain names": `*.prod.<region>.highlander.aws.a2z.com` (and FIPS `*.wsp-fips.prod.<region>.highlander.aws.a2z.com`) for each Region.

## 4. Encrypted-traffic caveats

CloudFront distribution names (`dXXXX.cloudfront.net`) are random names on a shared CDN, not vendor-named, and are not proposed. Sign-in (`signin.aws.amazon.com`) is shared AWS sign-in. `highlander.aws.a2z.com` is listed by the page only as the DCV WorkSpace gateway domain; whether other AWS services use `highlander` names is `UNVERIFIED` (N2). The DCV stream on UDP 4195 uses QUIC; whether its Initial carries the gateway name is `UNVERIFIED` on traffic.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `amazonworkspaces.com` | **N3** | Client and Web Access |
| SNI under `highlander.aws.a2z.com` | **N2** | DCV gateways per the page |
| Exact `skylight-client-ds.<region>.amazonaws.com` / `.api.aws`, `ws-client-service.<region>.amazonaws.com` | **N3** (exact) | Not in the patch; see section 8 |
| UDP 4172, 4195, 50002, 55002 | **U** | Port only |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `clients.amazonworkspaces.com`, `connectivity.amazonworkspaces.com` | `amazon-workspaces` |
| P2 | SNI `x.prod.us-east-1.highlander.aws.a2z.com` | `amazon-workspaces` |
| N1 | SNI `skylight-client-ds.us-east-1.amazonaws.com` | unmapped (regional hosts not in the patch) |
| N2 | SNI `d2td7dqidlhjx7.cloudfront.net`, `x.aws.a2z.com` | unmapped |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J and K)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `clients.amazonworkspaces.com` | one of `amazon-workspaces` | `amazon-workspaces` | PASS |
| L- | `xamazonworkspaces.com` | not amazon-workspaces (label boundary) | no application | PASS |
| L- | `amazonworkspaces.com.example.invalid` | not amazon-workspaces (suffix look-alike) | no application | PASS |
| L- | `xa2z.com` | not amazon-workspaces (label boundary) | no application | PASS |
| L- | `highlander.aws.a2z.com.example.invalid` | not amazon-workspaces (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] AWS documentation, Amazon WorkSpaces Administration Guide, "IP address and port requirements for WorkSpaces", `https://docs.aws.amazon.com/workspaces/latest/adminguide/workspaces-port-requirements.html`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

```python
("amazon-workspaces", "networking", "remote-access", "client-server", 3, "Amazon WorkSpaces",
 ("tunnels-other-applications",),
 ("amazonworkspaces.com", "highlander.aws.a2z.com")),
```

DECISION for Hermes: the page also lists 48 exact regional hosts on shared AWS domains (16 Regions × `skylight-client-ds.<region>.amazonaws.com`, `skylight-client-ds.<region>.api.aws`, `ws-client-service.<region>.amazonaws.com`). They are WorkSpaces-specific (N3) but many; this lane left them out of the patch and can add them if wanted. Without them, a desktop client's directory lookups are unnamed and only its streaming gateways and Web Access are named.

**Decision applied (2026-11-20):** the 48 exact regional API hosts stay **out** of the catalog. Reason: they
are exact names on shared AWS domains, one per Region and per IP family, and the list grows with each new Region.
Leaving one out silently loses a Region, while the two suffixes (`amazonworkspaces.com`, `highlander.aws.a2z.com`)
already name the client, Web Access and every streaming gateway. Live check: `clients.amazonworkspaces.com`
resolves (12 addresses, TLS 1.3, own certificate). The suffix `highlander.aws.a2z.com` has no address at its apex
and no documented concrete gateway name, so it stays N2 until a gateway name is observed.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `amazonworkspaces.com` | apex has no address (normal for a suffix entry); suffix **verified** through documented `clients.amazonworkspaces.com` (TLS TLSv1.3, cert `clients.amazonworkspaces.com`) |
| `highlander.aws.a2z.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |

## 10. Observed web-client hosts (dependency mapping)

- `https://clients.amazonworkspaces.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `clients.amazonworkspaces.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `clients.amazonworkspaces.com` | seen | app-owned | `amazon-workspaces` |  |  |

## 11. Attributes (App-ID model) and re-verify date

- `amazon-workspaces`: networking / remote-access, client-server; characteristics `tunnels-other-applications`; **risk 3**: carries other traffic or remote control.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
