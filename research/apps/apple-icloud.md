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

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-19 against `c08773f` plus batches D to I and retrofit R)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xicloud.com` | not icloud/icloud-private-relay (label boundary) | no application | PASS |
| L- | `icloud.com.example.invalid` | not icloud/icloud-private-relay (suffix look-alike) | no application | PASS |
| L- | `xicloud-content.com` | not icloud/icloud-private-relay (label boundary) | no application | PASS |
| L- | `icloud-content.com.example.invalid` | not icloud/icloud-private-relay (suffix look-alike) | no application | PASS |
| L- | `xapple-cloudkit.com` | not icloud/icloud-private-relay (label boundary) | no application | PASS |
| L- | `apple-cloudkit.com.example.invalid` | not icloud/icloud-private-relay (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

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

<!-- method-v2:start -->

## 9. Live verification (L)

**BLOCKED in the research environment** (2026-11-19): its egress proxy re-terminates TLS, so a handshake would show the proxy, and direct DNS is not permitted. The tool is `research/tools/live_verify.py`; it runs from an unproxied vantage point or, DNS only, through an approved DoH resolver. No host below carries an `L` result yet.

Names to verify (catalog domains of `icloud`, `icloud-private-relay`): `icloud.com`, `icloud-content.com`, `apple-cloudkit.com`, `apple-livephotoskit.com`, `icloud.apple.com`, `iwork.apple.com`, `mask.icloud.com`, `mask-h2.icloud.com`.

## 10. Observed web-client hosts (dependency mapping)

- `https://www.icloud.com/`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

## 11. Attributes (App-ID model) and re-verify date

- `icloud`: general-internet / file-sharing, client-server; characteristics `widely-used`, `transfers-files`; **risk 2**: widely used by enterprises; moves files out of the organisation.
- `icloud-private-relay`: networking / encrypted-tunnel, client-server; characteristics `tunnels-other-applications`, `evasive`; **risk 3**: carries other traffic or remote control; designed to avoid inspection (relays, proxies or circumvention modes).
- Functions separated by name: `icloud` (Apple iCloud services), `icloud-private-relay` (Apple iCloud Private Relay).
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): ECH support unknown until a live HTTPS-record check (section 9); other modes as stated in sections 2 to 4.
- Re-verify by: **2027-02-17** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
