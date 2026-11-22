# Asana

- Content-pack id today: `asana` (`asana.com`)
- Status: **READY**, NAME, batch J (`research/patches/batch-j-relayed-rows-12-18.patch`): Asana-owned domains and exact S3 bucket hosts added
- Sources: read by Research Lab from the Hermes server, relayed by Hermes, 2026-11-20 (PRO-29) (headless Chrome); no page date shown

## 1. What it is

Work management (tasks, projects).

## 2. Transport and ports

HTTPS. "Asana gives no static IP list" [A].

## 3. Observable evidence

Non-FedRAMP [A]: `asana.com`, `*.asana.com`, `*.asana.plus`, `asanausercontent.com`, `d3ki9tyy5l5ruj.cloudfront.net` (web app, APIs, uploads and downloads, avatars, CDN); per-data-region buckets `asana-user-private-us-east-1.s3.amazonaws.com`, `asana-user-private-me-central-1.s3.me-central-1.amazonaws.com`, `asana-user-private-ap-northeast-1.s3.ap-northeast-1.amazonaws.com`, `asana-user-private-eu-central-1.s3.eu-central-1.amazonaws.com`, `asana-user-private-ap-southeast-2.s3.ap-southeast-2.amazonaws.com`. FedRAMP: `app.asana-gov.com`, `asana-user-private-fedramp-prod.s3.amazonaws.com`, `d1dg3ns82tdjz3.cloudfront.net`.

## 4. Encrypted-traffic caveats

The CloudFront distribution names are random names on a shared CDN, not vendor-named, so they are not proposed (as for WorkSpaces). The S3 bucket hosts are exact vendor-named names (the precedent of WeTransfer and Loom). `app.asana-gov.com` is proposed as an exact name: the page names no other `asana-gov.com` host.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `asana.com` | **N3** | Already mapped |
| SNI under `asana.plus`, `asanausercontent.com` | **N3** |  |
| Exact `app.asana-gov.com` and the six bucket hosts | **N3** (exact) | Uploads and downloads |
| CloudFront `d…cloudfront.net` | not mapped | Shared CDN |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L and J): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `x.asana.plus`, `asanausercontent.com`, `app.asana-gov.com` | `asana` (today unmapped) |
| P2 | SNI `asana-user-private-eu-central-1.s3.eu-central-1.amazonaws.com` | `asana` |
| N1 | SNI `d3ki9tyy5l5ruj.cloudfront.net`, `other.s3.amazonaws.com`, `x.asana-gov.com` | not `asana` |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N and O as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xasana.com` | not asana (label boundary) | no application | PASS |
| L- | `asana.com.example.invalid` | not asana (suffix look-alike) | no application | PASS |
| L- | `xasana.plus` | not asana (label boundary) | no application | PASS |
| L- | `asana.plus.example.invalid` | not asana (suffix look-alike) | no application | PASS |
| L- | `xasanausercontent.com` | not asana (label boundary) | no application | PASS |
| L- | `asanausercontent.com.example.invalid` | not asana (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [A] Asana Help, "Asana IP address ranges and hostnames", `https://help.asana.com/s/article/asana-ip-address-ranges-and-hostnames`, read by Research Lab from the Hermes server, relayed by Hermes, 2026-11-20 (PRO-29).

## 8. Catalog delta and recommendation

```python
("asana", ..., ("asana.com", "asana.plus", "asanausercontent.com", "app.asana-gov.com", "asana-user-private-us-east-1.s3.amazonaws.com",
 "asana-user-private-me-central-1.s3.me-central-1.amazonaws.com", "asana-user-private-ap-northeast-1.s3.ap-northeast-1.amazonaws.com",
 "asana-user-private-eu-central-1.s3.eu-central-1.amazonaws.com", "asana-user-private-ap-southeast-2.s3.ap-southeast-2.amazonaws.com",
 "asana-user-private-fedramp-prod.s3.amazonaws.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 6 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `asana.com` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `asana.com`, no subject organisation (domain-validated) (issuer Let's Encrypt) |
| `asana.plus` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `asana.plus`, no subject organisation (domain-validated) (issuer Amazon) |
| `asanausercontent.com` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `asanausercontent.com`, no subject organisation (domain-validated) (issuer Amazon) |
| `app.asana-gov.com` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `app.asana-gov.com`, no subject organisation (domain-validated) (issuer Amazon) |
| `asana-user-private-us-east-1.s3.amazonaws.com` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `s3.amazonaws.com`, no subject organisation (domain-validated) (issuer Amazon); CNAME into shared front end `s3-w.us-east-1.amazonaws.com`: name usable, IPs never |
| `asana-user-private-me-central-1.s3.me-central-1.amazonaws.com` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `*.s3.me-central-1.amazonaws.com`, no subject organisation (domain-validated) (issuer Amazon); CNAME into shared front end `s3-r-w.me-central-1.amazonaws.com`: name usable, IPs never |
| `asana-user-private-ap-northeast-1.s3.ap-northeast-1.amazonaws.com` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `*.s3-ap-northeast-1.amazonaws.com`, no subject organisation (domain-validated) (issuer Amazon); CNAME into shared front end `s3-r-w.ap-northeast-1.amazonaws.com`: name usable, IPs never |
| `asana-user-private-eu-central-1.s3.eu-central-1.amazonaws.com` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `*.s3.eu-central-1.amazonaws.com`, no subject organisation (domain-validated) (issuer Amazon); CNAME into shared front end `s3-r-w.eu-central-1.amazonaws.com`: name usable, IPs never |
| `asana-user-private-ap-southeast-2.s3.ap-southeast-2.amazonaws.com` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `*.s3-ap-southeast-2.amazonaws.com`, no subject organisation (domain-validated) (issuer Amazon); CNAME into shared front end `s3-r-w.ap-southeast-2.amazonaws.com`: name usable, IPs never |
| `asana-user-private-fedramp-prod.s3.amazonaws.com` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `s3.amazonaws.com`, no subject organisation (domain-validated) (issuer Amazon); CNAME into shared front end `s3-w.us-east-1.amazonaws.com`: name usable, IPs never |

## 10. Observed web-client hosts (dependency mapping)

- `https://app.asana.com/`: **not yet observed** (added after pass 2; listed in `web-urls.txt` for the next server run).

## 11. Attributes (App-ID model) and re-verify date

- `asana`: business-systems / office-programs, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
