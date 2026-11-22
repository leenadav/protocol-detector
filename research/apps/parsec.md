# Parsec

- Content-pack id today: `parsec` (`parsec.app`, `parsecgaming.com`; web fronts apex and `www`)
- Status: **READY**, NAME, batch J (`research/patches/batch-j-relayed-rows-12-18.patch`): `parsecusercontent.com` added
- Sources: read by Research Lab from the Hermes server, relayed by Hermes, 2026-11-20 (PRO-29); article updated 2026-09-06 (read through the Zendesk public API: the page shows a Cloudflare challenge)

## 1. What it is

Low-latency remote desktop (Unity).

## 2. Transport and ports

443/TCP for the API, WebSocket API, downloads and CDN; STUN on 3478/UDP; "Peer-to-Peer UDP Streaming" on random UDP ports (configurable static) [P].

## 3. Observable evidence

[P]: `kessel-ws.parsec.app` ("Websocket API"), `kessel-api.parsec.app` ("API"), `builds.parsec.app` and `builds.parsecgaming.com` ("Downloads/Updates"), `public.parsec.app` ("CDN"), `parsecusercontent.com` ("Avatars/Profile images"), `stun.parsec.app` and `stun6.parsec.app` (STUN, IPv4/IPv6). "DNS must resolve parsec.app + all subdomains, AWS S3, CloudFront".

## 4. Encrypted-traffic caveats

The stream itself is peer-to-peer UDP to the peer's WAN address, with no server name. Only signalling, STUN and downloads are named. STUN on 3478 goes to `stun.parsec.app`: the STUN family identifies the protocol, and the name only appears if the client resolves it (the DNS query, not the STUN packet).

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `parsec.app`, `parsecgaming.com` | **N3** | Already mapped |
| SNI under `parsecusercontent.com` | **N3** | Profile images |
| P2P UDP stream | **U** | No name |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L and J): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `kessel-ws.parsec.app`, `builds.parsecgaming.com` | `parsec` |
| P2 | SNI `x.parsecusercontent.com` | `parsec` (today unmapped) |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N and O as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xparsec.app` | not parsec (label boundary) | no application | PASS |
| L- | `parsec.app.example.invalid` | not parsec (suffix look-alike) | no application | PASS |
| L- | `xparsecgaming.com` | not parsec (label boundary) | no application | PASS |
| L- | `parsecgaming.com.example.invalid` | not parsec (suffix look-alike) | no application | PASS |
| L- | `xparsecusercontent.com` | not parsec (label boundary) | no application | PASS |
| L- | `parsecusercontent.com.example.invalid` | not parsec (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [P] Parsec Support, "Parsec Connectivity Requirements", `https://support.parsec.app/hc/en-us/articles/32381460716180-Parsec-Connectivity-Requirements`, read by Research Lab from the Hermes server, relayed by Hermes, 2026-11-20 (PRO-29).

## 8. Catalog delta and recommendation

```python
("parsec", ..., ("parsec.app", "parsecgaming.com", "parsecusercontent.com"), ("parsec.app", "www.parsec.app")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 6 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `parsec.app` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `parsec.app`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `parsecgaming.com` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `*.parsecgaming.com`, no subject organisation (domain-validated) (issuer Amazon) |
| `parsecusercontent.com` | round 3 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `parsecusercontent.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |

## 10. Observed web-client hosts (dependency mapping)

- `https://web.parsec.app/`: **not yet observed** (added after pass 2; listed in `web-urls.txt` for the next server run).

## 11. Attributes (App-ID model) and re-verify date

- `parsec`: networking / remote-access, client-server; characteristics `tunnels-other-applications`, `prone-to-misuse`; **risk 4**: carries other traffic or remote control; commonly misused (unsanctioned remote access, data exfiltration).
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
