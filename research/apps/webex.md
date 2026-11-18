# Cisco Webex

- Content-pack id today: `webex` (`webex.com`, `wbx2.com`)
- Status: **READY**, NAME, batch B (`research/patches/batch-b-name-based.patch`)
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

## 7. Sources

- [S1] Webex Help Center, "Network Requirements for Webex Services" (WBX000028782),
  `https://help.webex.com/en-us/article/WBX000028782/Network-Requirements-for-Webex-Services`, accessed
  2026-11-18 (latest revision entry 11/17/2026).

## 8. Catalog delta and recommendation

```python
("webex", "collaboration", "voip-video", "client-server", 2, "Cisco Webex meetings", ("widely-used",),
 ("webex.com", "wbx2.com", "ciscospark.com", "webexapis.com", "webexcontent.com", "ciscosparkcontent.com")),
```
