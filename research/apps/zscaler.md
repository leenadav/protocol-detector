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

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M and N as rebuilt 2026-11-21)

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

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 5 of 2026-11-21 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `zscaler.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `www.zscaler.com`, subject organisation **Zscaler, Inc.** (issuer DigiCert Inc) |
| `zscaler.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `zscloud.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `zscalerone.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `zscalertwo.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `zscalerthree.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `zscalerten.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `zscalerbeta.net` | resolves; TLS handshake failed (SSLCertVerificationError) in both rounds where checked: not a removal reason |
| `zscalergov.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `zpagov.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `zpatwo.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `zpabeta.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `zdxcloud.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `zdxgov.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `zdxbeta.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `zdxten.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `zslogin.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `zsloginbeta.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `zidentitygov.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `zscaler`: networking / proxy, client-server; characteristics `tunnels-other-applications`; **risk 2**: carries other traffic or remote control.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
