# Zscaler (Client Connector and clouds)

- Content-pack id today: `zscaler` (`zscaler.com`, `zscaler.net`, `zscloud.net`)
- Status: **READY**, NAME, batch D. Unblocked: the configuration site is readable (the help article stays under maintenance)
- Sources accessed: 2026-11-19

## 1. What it is

Zscaler's SSE services and the Client Connector endpoint agent.

## 2. Transport and ports

Client Connector [S1]: service discovery, enrollment and login on 443 (`mobile.`, `login.` and `logout6.` hosts on the cloud domain); PAC on 80/443; tunnel to enforcement nodes on "80, 443 (TCP & UDP), 8080 (if 80,443 are blocked)"; captive portal on 80 (`gateway.`, `gateway6.` hosts).

## 3. Observable evidence

Cloud names listed on Zscaler's own configuration site [S1]: ZIA `zscaler.net`, `zscalerone.net`, `zscalertwo.net`, `zscalerthree.net`, `zscloud.net`, `zscalerbeta.net`, `zscalergov.net`, `zscalerten.net`; ZPA `private.zscaler.com`, `zpagov.net`, `zpatwo.net`, `zpabeta.net`; ZDX `zdxcloud.net`, `zdxgov.net`, `zdxbeta.net`, `zdxten.net`; authentication `zslogin.net`, `zsloginbeta.net`, `zidentitygov.net`; also `goairgap.com` (Zero Trust Branch), `zsdkone.net` (ZSDK), `zsaiguard.net` (AI Protect), and `.us` government domains.

## 4. Encrypted-traffic caveats

The tunnel to enforcement nodes is published as IP ranges, not names. Samsung ELM hosts (`secb2b.com`) are third-party.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under the cloud domains | **N3** Zscaler |  |
| `goairgap.com`, `zsdkone.net`, `zsaiguard.net`, `.us` domains | **N3** | Not proposed in D (smaller products); a follow-up |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `mobile.zscaler.net`, `login.zscalertwo.net`, `x.zdxcloud.net`, `x.zslogin.net` | `zscaler` |

## 7. Sources

- [S1] Zscaler Config, `https://config.zscaler.com/zscaler.net/zscaler-app` ("Zscaler Client Connector" section and cloud list), accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("zscaler", ..., ("zscaler.com", "zscaler.net", "zscloud.net", "zscalerone.net", "zscalertwo.net", "zscalerthree.net",
                    "zscalerten.net", "zscalerbeta.net", "zscalergov.net", "zpagov.net", "zpatwo.net", "zpabeta.net", "zdxcloud.net",
                    "zdxgov.net", "zdxbeta.net", "zdxten.net", "zslogin.net", "zsloginbeta.net", "zidentitygov.net")),
```
