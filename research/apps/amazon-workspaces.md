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

## 7. Sources

- [S1] AWS documentation, Amazon WorkSpaces Administration Guide, "IP address and port requirements for WorkSpaces", `https://docs.aws.amazon.com/workspaces/latest/adminguide/workspaces-port-requirements.html`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

```python
("amazon-workspaces", "networking", "remote-access", "client-server", 3, "Amazon WorkSpaces",
 ("tunnels-other-applications",),
 ("amazonworkspaces.com", "highlander.aws.a2z.com")),
```

DECISION for Hermes: the page also lists 48 exact regional hosts on shared AWS domains (16 Regions × `skylight-client-ds.<region>.amazonaws.com`, `skylight-client-ds.<region>.api.aws`, `ws-client-service.<region>.amazonaws.com`). They are WorkSpaces-specific (N3) but many; this lane left them out of the patch and can add them if wanted. Without them, a desktop client's directory lookups are unnamed and only its streaming gateways and Web Access are named.
