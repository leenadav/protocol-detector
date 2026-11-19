# WeTransfer

- Content-pack id today: `wetransfer` (`wetransfer.com`, `wetransfer.net`)
- Status: **READY**, NAME, batch C (`research/patches/batch-c-name-based.patch`)
- Sources accessed: 2026-11-18. Article "Updated 22 October 2026"

## 1. What it is

Browser-based large-file transfer, a common exfiltration and shadow-IT concern.

## 2. Transport and ports

"WeTransfer uses HTTPS (port 443) for secure communication and the QUIC protocol for faster, more efficient
transfers. QUIC is the transport layer for HTTP/3 and runs over UDP" [S1]. Admins should allow TCP 443 and
UDP 443 [S1].

## 3. Observable evidence

From "How do I configure a firewall for WeTransfer?" [S1]:

| Section | Hosts (as listed) |
|---|---|
| Core WeTransfer domains | `wetransfer.com`, `www.`, `analytics-v2.`, `cdn.`, `donny.`, `experiments.`, `help.`, `lebowski.`, `privacy.`, `snowplow.`, `tagging.`, `auth.`, `auth-web.`, `portals.wetransfer.com` |
| WeTransfer.net domains | `wetransfer.net`, `backgrounds.`, `bsp-proxy.`, `ekstrom.`, `helios-assets.`, `nolan.`, `spaceship.`, `storm.`, `storm-eu-west-1.`, `tempest.wetransfer.net` |
| Short links | `we.tl` |
| Amazon S3 storage | `wt-prod-euwest1-storm.s3.amazonaws.com`, `wt-prod-euwest1-storm.s3-accelerate.amazonaws.com`, `wt-prod-euwest1-storm.s3.eu-west-1.amazonaws.com`, the same three for `wt-prod-useast1-storm`, plus generic `s3.amazonaws.com`, `s3.eu-west-1.amazonaws.com`, `s3.us-east-1.amazonaws.com`, `s3-accelerate.amazonaws.com` |
| Observability, background images, analytics and advertising | Datadog, Sentry, Unsplash, Google, Bing, Facebook, Twitter, ProfitWell, jsDelivr, OneTrust hosts (third parties) |

## 4. Encrypted-traffic caveats

- **Transfers can go to S3.** The six `wt-prod-*-storm` bucket hosts are named by WeTransfer [S1], so they
  are proposed as exact hosts (precedent: the GitHub Copilot `webpubsub.azure.com` hosts). Generic S3 hosts
  and `amazonaws.com` name no application (v0.65 rule).
- **QUIC.** Transfers over HTTP/3 leave the visibility-phase TCP path [S1].
- `help.wetransfer.com` and `www.wetransfer.com` are support and marketing. They are not proposed as web
  fronts here because the page lists them as core service domains without separating them.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `wetransfer.com`, `wetransfer.net` | **N3** | Includes marketing and help |
| SNI `we.tl` | **N3** short links | Opening a link, not necessarily a transfer |
| SNI of the six named S3 bucket hosts | **N3** (exact hosts) | Upload or download storage |
| Generic S3, third-party hosts | do not map | Shared |

## 6. Synthetic test vectors

Checked in scratch (batch C on `47b2743`): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `we.tl` | `wetransfer` (today unmapped) |
| P2 | SNI `wt-prod-euwest1-storm.s3-accelerate.amazonaws.com` | `wetransfer` |
| N1 | SNI `s3.amazonaws.com`, `other-bucket.s3.amazonaws.com` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-19 against `c08773f` plus batches D to I and retrofit R)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `cdn.wetransfer.com` | one of `wetransfer` | `wetransfer` | PASS |
| O+ | `wetransfer.com` | one of `wetransfer` | `wetransfer` | PASS |
| L- | `xwetransfer.com` | not wetransfer (label boundary) | no application | PASS |
| L- | `wetransfer.com.example.invalid` | not wetransfer (suffix look-alike) | no application | PASS |
| L- | `xwetransfer.net` | not wetransfer (label boundary) | no application | PASS |
| L- | `wetransfer.net.example.invalid` | not wetransfer (suffix look-alike) | no application | PASS |
| L- | `xwe.tl` | not wetransfer (label boundary) | no application | PASS |
| L- | `we.tl.example.invalid` | not wetransfer (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] WeTransfer Help Center, "How do I configure a firewall for WeTransfer?",
  `https://wetransfer.com/help-center/troubleshooting/configure-firewall` (linked from "My firewall is blocking
  WeTransfer", `https://wetransfer.com/help-center/security-privacy/why-blocked`), "Updated 22 October 2026",
  accessed 2026-11-18.

## 8. Catalog delta and recommendation

```python
("wetransfer", "general-internet", "file-sharing", "browser-based", 3, "WeTransfer file transfer", ("transfers-files",),
 ("wetransfer.com", "wetransfer.net", "we.tl", "wt-prod-euwest1-storm.s3.amazonaws.com",
  "wt-prod-euwest1-storm.s3-accelerate.amazonaws.com", "wt-prod-euwest1-storm.s3.eu-west-1.amazonaws.com",
  "wt-prod-useast1-storm.s3.amazonaws.com", "wt-prod-useast1-storm.s3-accelerate.amazonaws.com",
  "wt-prod-useast1-storm.s3.us-east-1.amazonaws.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

**BLOCKED in the research environment** (2026-11-19): its egress proxy re-terminates TLS, so a handshake would show the proxy, and direct DNS is not permitted. The tool is `research/tools/live_verify.py`; it runs from an unproxied vantage point or, DNS only, through an approved DoH resolver. No host below carries an `L` result yet.

Names to verify (catalog domains of `wetransfer`): `wetransfer.com`, `wetransfer.net`, `we.tl`, `wt-prod-euwest1-storm.s3.amazonaws.com`, `wt-prod-euwest1-storm.s3-accelerate.amazonaws.com`, `wt-prod-euwest1-storm.s3.eu-west-1.amazonaws.com`, `wt-prod-useast1-storm.s3.amazonaws.com`, `wt-prod-useast1-storm.s3-accelerate.amazonaws.com`, `wt-prod-useast1-storm.s3.us-east-1.amazonaws.com`.

## 10. Observed web-client hosts (dependency mapping)

- `https://wetransfer.com/`, loaded 2026-11-19 without signing in: HTTP 200, final host `wetransfer.com`.

Pass 1 is a lower bound. The proxy refuses hosts not on the allowlist ("failed" below), so hosts that only scripts from a refused host would contact are missing.

| Host | Requests (refused) | Class | Attribution today | Note |
|---|---|---|---|---|
| `cdn.wetransfer.com` | 79 (79) | app-owned | `wetransfer` |  |
| `wetransfer.com` | 1 (0) | app-owned | `wetransfer` |  |

## 11. Attributes (App-ID model) and re-verify date

- `wetransfer`: general-internet / file-sharing, browser-based; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): ECH support unknown until a live HTTPS-record check (section 9); other modes as stated in sections 2 to 4.
- Re-verify by: **2027-02-17** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
