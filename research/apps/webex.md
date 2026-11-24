# Cisco Webex

- Content-pack id today: `webex` (`webex.com`, `wbx2.com`)
- Status: **READY**, NAME, batch B (`research/patches/batch-b-name-based.patch`)
- Implemented: content release 2026.11.4 on `claude/go-migration` (`6ab434d`); verified in the pack at `47b2743`, 2026-11-18
- Sources accessed: 2026-11-18. Article revision history, latest entry 11/17/2026

## 1. What it is

Cisco's meetings, messaging and calling suite. The article covers "Webex Meetings and Webex
Messaging" network requirements and links to separate pages for Webex Calling [S1].

## 2. Transport and ports

From "Webex Services – Port Numbers and Protocols" [S1]:

| Port | Protocol | Use (as published) |
|---|---|---|
| 443 | HTTPS | signaling to the Webex service URLs |
| 5004 and 9000 | SRTP over UDP | "Encrypted audio, video, and content sharing" |
| 5004 | SRTP over TCP | fallback "if UDP cannot be used" |
| 443 | SRTP over TLS | fallback "if UDP and TCP cannot be used" |
| 123 UDP, 53 UDP/TCP | NTP, DNS | |

"Session establishment to Webex services is based on defined URLs, rather than IP addresses" [S1]. Media goes to published IP subnets [S1].

## 3. Observable evidence

"Cisco Webex Services URLs" table [S1]:

| Domain | Description (as published) |
|---|---|
| `*.webex.com`, `*.cisco.com`, `*.wbx2.com`, `*.ciscospark.com`, `*.webexapis.com` | "Webex micro-services" (meetings, messaging, identity, OAuth, ...) |
| `*.webexcontent.com` | "Webex storage for user-generated content and logs" |
| `*.accompany.com` | "People Insights Integration" (Cisco-owned) |
| `*.clouddrive.com`, `*.ciscosparkcontent.com`, `*.rackcdn.com` | "Core Webex services being deprecated" (storage replaced by `webexcontent.com` in October 2019) |

Third-party domains listed for Webex features (`*.sparkpostmail.com`, `*.giphy.com`, `*.walkme.com`,
`*.amplitude.com`, Akamai, CloudFront, Fastly, AWS and others) are not Webex evidence.

TLS media on 443 [S1] means meeting media can appear as TLS on the CONNECT path. Whether its SNI is a
Webex name is `UNVERIFIED`.

## 4. Encrypted-traffic caveats

- "The Webex app does not support Proxy server decryption and inspection of TLS sessions for Webex
  Meetings media services" [S1]. That matters only for later, decrypting phases.
- `*.cisco.com` is listed but serves all of Cisco, so it must not name Webex.
- UDP media is off the visibility-phase path.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `webex.com`, `wbx2.com`, `ciscospark.com`, `webexapis.com`, `webexcontent.com` | **N3** Webex | |
| `ciscosparkcontent.com` | **N2** | Deprecated log upload [S1] |
| `cisco.com` | **N1**, do not map | All of Cisco |
| `clouddrive.com`, `rackcdn.com` | do not map | Deprecated storage and its CDN [S1]; the page does not say who operates them (`UNVERIFIED`), so no mapping |
| UDP 5004/9000 to published subnets | later phase | |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `idbroker.webex.com` (synthetic label) | `webex` |
| P2 | SNI `x.webexapis.com`, `x.webexcontent.com`, `ciscospark.com` | `webex` (today unmapped) |
| N1 | SNI `www.cisco.com` | no application |
| N2 | SNI `webex.com.example.invalid` | no application |
| N3 | `ech_outer()` with outer SNI `x.webex.com` | no application |

The rows other than N3 were checked with `attribution_for_host` in scratch (batch A plus B applied): all as expected.

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O, P and Q as rebuilt 2026-11-24)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `tsa-f.webex.com` | one of `webex` | `webex` | PASS |
| O+ | `u2c.svc.webex.com` | one of `webex` | `webex` | PASS |
| O+ | `wdm-k.wbx2.com` | one of `webex` | `webex` | PASS |
| O+ | `web.webex.com` | one of `webex` | `webex` | PASS |
| D- | `api.eu.amplitude.com` | not webex (third party) | `amplitude` | PASS |
| L- | `xwebex.com` | not webex (label boundary) | no application | PASS |
| L- | `webex.com.example.invalid` | not webex (suffix look-alike) | no application | PASS |
| L- | `xwbx2.com` | not webex (label boundary) | no application | PASS |
| L- | `wbx2.com.example.invalid` | not webex (suffix look-alike) | no application | PASS |
| L- | `xciscospark.com` | not webex (label boundary) | no application | PASS |
| L- | `ciscospark.com.example.invalid` | not webex (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Webex Help Center, "Network Requirements for Webex Services" (WBX000028782),
  `https://help.webex.com/en-us/article/WBX000028782/Network-Requirements-for-Webex-Services`, accessed
  2026-11-18 (latest revision entry 11/17/2026).

## 8. Catalog delta and recommendation

```python
("webex", "collaboration", "voip-video", "client-server", 2, "Cisco Webex meetings", ("widely-used",),
 ("webex.com", "wbx2.com", "ciscospark.com", "webexapis.com", "webexcontent.com", "ciscosparkcontent.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `webex.com` | **L** resolves; TLSv1.2, ALPN `None`, cert `webex.com`, subject organisation **Cisco Systems Inc.** (issuer IdenTrust) |
| `wbx2.com` | resolves; TLS handshake failed (TimeoutError) in both rounds where checked: not a removal reason |
| `ciscospark.com` | resolves; TLS handshake failed (TimeoutError) in both rounds where checked: not a removal reason |
| `webexapis.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `api-gateway-k.wbx2.com`, subject organisation **Cisco Systems Inc.** (issuer IdenTrust) |
| `webexcontent.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `ciscosparkcontent.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |

## 10. Observed web-client hosts (dependency mapping)

- `https://web.webex.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `web.webex.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `api.eu.amplitude.com` | seen | third party | `amplitude` | not checked |  |
| `tsa-f.webex.com` | seen | app-owned | `webex` | not checked |  |
| `u2c.svc.webex.com` | seen | app-owned | `webex` | not checked |  |
| `wdm-k.wbx2.com` | seen | app-owned | `webex` | not checked |  |
| `web.webex.com` | seen | app-owned | `webex` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `webex`: collaboration / voip-video, client-server; characteristics `widely-used`; **risk 2**: widely used by enterprises.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `amplitude`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
