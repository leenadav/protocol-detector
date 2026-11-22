# Twilio (Programmable Video and REST API)

- Content-pack id today: `twilio` (`twilio.com`)
- Status: **DONE**, verified, no catalog change
- Sources: [T1] read by Research Lab from the Hermes server, relayed by Hermes (PRO-108, PRO-121), 2026-11-21, dateModified 2026-03-24; [T2] dateModified 2026-10-14; the essential-domains support article returned 403 (not read)

## 1. What it is

Communications APIs (voice, messaging, video) used inside customers' applications.

## 2. Transport and ports

Video signalling over WSS on 443; STUN on UDP 3478; TURN on UDP 3478 and TLS 443; media from IP ranges on UDP 10,000 to 60,000 [T1]. REST API over HTTPS; "too dynamic to list" its IPs [T2].

## 3. Observable evidence

[T1]: `*.vss.twilio.com` (`global`, `au1`, `br1`, `de1`, `ie1`, `in1`, `jp1`, `sg1`, `us1`, `us2`), `sdkgw.us1.twilio.com`, `ecs.us1.twilio.com` (pre-2021 SDKs only), `*.stun.twilio.com`, `*.turn.twilio.com`. [T2]: allow outbound HTTPS to any `*.twilio.com` subdomain.

## 4. Encrypted-traffic caveats

Every listed name is under `twilio.com`, which is already mapped, so no change. STUN to `*.stun.twilio.com` is identified as STUN by the protocol layer; the name appears only in the client's DNS query, not the STUN packet. Media is addressed by IP and carries no name. Twilio runs inside other companies' apps, so a match means an app uses Twilio, not that the user chose Twilio.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `twilio.com` | **N3** | Signalling, TURN over TLS, REST |
| STUN 3478/UDP | protocol only | No SNI |
| Media UDP 10,000 to 60,000 | **U** for names | IP ranges only |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K, M and N): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `global.vss.twilio.com`, `sdkgw.us1.twilio.com`, `x.turn.twilio.com` | `twilio` |
| N1 | SNI `xtwilio.com`, `twilio.com.example.invalid` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O and P as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xtwilio.com` | not twilio (label boundary) | no application | PASS |
| L- | `twilio.com.example.invalid` | not twilio (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [T1] Twilio Docs, "Firewall and Network Configuration" (Programmable Video), `https://www.twilio.com/docs/video/ip-addresses`, read by Research Lab from the Hermes server, relayed by Hermes (PRO-108, PRO-121), 2026-11-21.
- [T2] Twilio Docs, REST API security page (title not relayed), `https://www.twilio.com/docs/usage/security`, read by Research Lab from the Hermes server, relayed by Hermes (PRO-108, PRO-121), 2026-11-21.

## 8. Catalog delta and recommendation

None. `twilio.com` covers every listed name.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `twilio.com` | round 5 (2026-11-21); **L** resolves; TLSv1.2, TLS via documented probe `global.vss.twilio.com`, probe cert `*.vss.twilio.com`, no subject organisation (domain-validated) (issuer Amazon) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `twilio`: collaboration / voip-video, client-server; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
