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
