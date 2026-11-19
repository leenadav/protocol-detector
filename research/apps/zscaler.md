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

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-19 against `c08773f` plus batches D to I and retrofit R)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xzscaler.com` | not zscaler (label boundary) | no application | PASS |
| L- | `zscaler.com.example.invalid` | not zscaler (suffix look-alike) | no application | PASS |
| L- | `xzscaler.net` | not zscaler (label boundary) | no application | PASS |
| L- | `zscaler.net.example.invalid` | not zscaler (suffix look-alike) | no application | PASS |
| L- | `xzscloud.net` | not zscaler (label boundary) | no application | PASS |
| L- | `zscloud.net.example.invalid` | not zscaler (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Zscaler Config, `https://config.zscaler.com/zscaler.net/zscaler-app` ("Zscaler Client Connector" section and cloud list), accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("zscaler", ..., ("zscaler.com", "zscaler.net", "zscloud.net", "zscalerone.net", "zscalertwo.net", "zscalerthree.net",
                    "zscalerten.net", "zscalerbeta.net", "zscalergov.net", "zpagov.net", "zpatwo.net", "zpabeta.net", "zdxcloud.net",
                    "zdxgov.net", "zdxbeta.net", "zdxten.net", "zslogin.net", "zsloginbeta.net", "zidentitygov.net")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

**BLOCKED in the research environment** (2026-11-19): its egress proxy re-terminates TLS, so a handshake would show the proxy, and direct DNS is not permitted. The tool is `research/tools/live_verify.py`; it runs from an unproxied vantage point or, DNS only, through an approved DoH resolver. No host below carries an `L` result yet.

Names to verify (catalog domains of `zscaler`): `zscaler.com`, `zscaler.net`, `zscloud.net`, `zscalerone.net`, `zscalertwo.net`, `zscalerthree.net`, `zscalerten.net`, `zscalerbeta.net`, `zscalergov.net`, `zpagov.net`, `zpatwo.net`, `zpabeta.net`, `zdxcloud.net`, `zdxgov.net`, `zdxbeta.net`, `zdxten.net`, `zslogin.net`, `zsloginbeta.net`, `zidentitygov.net`.

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `zscaler`: networking / proxy, client-server; characteristics `tunnels-other-applications`; **risk 2**: carries other traffic or remote control.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): ECH support unknown until a live HTTPS-record check (section 9); other modes as stated in sections 2 to 4.
- Re-verify by: **2027-02-17** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
