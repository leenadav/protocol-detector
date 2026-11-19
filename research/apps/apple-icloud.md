# Apple iCloud and iCloud Private Relay

- Content-pack id today: `icloud` (`icloud.com`, `icloud-content.com`), `apple-push` (`push.apple.com`), `apple-base`
- Status: **READY**, NAME, batch D: iCloud domains plus a new id `icloud-private-relay`
- Sources accessed: 2026-11-19

## 1. What it is

Apple's consumer cloud (storage, sync) and iCloud Private Relay, an encrypted relay that hides browsing destinations from the network. Private Relay matters for a gateway: it is a bypass, not file sharing.

## 2. Transport and ports

Mostly TCP 443. Push notifications: `*.push.apple.com` on "443, 80, 5223, 2197" TCP [S1].

## 3. Observable evidence

iCloud, "In addition to the Apple Account hosts listed above" [S1]: `*.apple-cloudkit.com`, `*.apple-livephotoskit.com`, `*.apzones.com` (China), `*.cdn-apple.com`, `*.gc.apple.com`, `*.icloud.com`, `*.icloud.apple.com`, `*.icloud-content.com`, `*.iwork.apple.com`; `mask.icloud.com` and `mask-h2.icloud.com` are listed as "iCloud Private Relay" [S1]. Apple Account hosts: `account.apple.com`, `appleid.cdn-apple.com`, `idmsa.apple.com`, `gsa.apple.com`.

## 4. Encrypted-traffic caveats

Private Relay's data path is not described on this page. Only its host names are, and a relay connection is by design opaque about the final destination. `cdn-apple.com` and `gc.apple.com` serve more than iCloud, so they are not mapped to iCloud.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI `mask.icloud.com`, `mask-h2.icloud.com` | **N3** Private Relay | Today these fall under `icloud.com` and are logged as file sharing |
| SNI under `apple-cloudkit.com`, `apple-livephotoskit.com`, `icloud.apple.com`, `iwork.apple.com` | **N3** iCloud |  |
| `cdn-apple.com`, `gc.apple.com` | do not map to iCloud | Shared Apple |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `mask.icloud.com`, `mask-h2.icloud.com` | `icloud-private-relay` |
| P2 | SNI `x.apple-cloudkit.com`, `x.icloud.apple.com` | `icloud` |
| N1 | SNI `www.icloud.com` | `icloud` |
| N2 | SNI `www.apple.com` | `apple-base` |

## 7. Sources

- [S1] Apple Support, "Use Apple products on enterprise networks", `https://support.apple.com/en-us/101555`, "Published Date: August 07, 2026", accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("icloud", ..., ("icloud.com", "icloud-content.com", "apple-cloudkit.com", "apple-livephotoskit.com", "icloud.apple.com",
                  "iwork.apple.com")),
("icloud-private-relay", "networking", "encrypted-tunnel", "client-server", 3, "Apple iCloud Private Relay",
 ("tunnels-other-applications", "evasive"), ("mask.icloud.com", "mask-h2.icloud.com")),
```

`mask.icloud.com` is longer than `icloud.com`, so it wins.
