# RustDesk

- Content-pack id today: `rustdesk` (`rustdesk.com`, description "public servers"; web fronts apex and `www`)
- Status: **PARTIAL**, NAME. Low priority; research continues when the source is reachable
- Sources accessed: 2026-11-18

## 1. What it is

RustDesk. See the catalog entry for its category.

## 2. Transport and ports

See section 3.

## 3. Observable evidence

RustDesk's self-host docs give the server roles and ports: "hbbs - RustDesk ID (rendezvous / signaling) server, listen on TCP (21114 - for http in Pro only, 21115, 21116, 21118 for web socket) and UDP (21116)"; "hbbr - RustDesk relay server, listen on TCP (21117, 21119 for web socket)"; core ports "TCP 21114-21119, UDP 21116". The public server host names are not on that page, so the catalog's `rustdesk.com` mapping for public servers is `UNVERIFIED`. The ports could support a later PROTOCOL item, but the wire format is not specified on the page.

## 4. Encrypted-traffic caveats

Not assessed beyond the README's shared facts.

## 5. Confidence and false-positive risks

| Observable | Level |
|---|---|
| Current pack names | **U** (not verified by this lane) |

## 6. Synthetic test vectors

Pending a readable source.

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O, P and Q as rebuilt 2026-11-24)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xrustdesk.com` | not rustdesk (label boundary) | no application | PASS |
| L- | `rustdesk.com.example.invalid` | not rustdesk (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- `https://rustdesk.com/docs/en/self-host/`, accessed 2026-11-18

## 8. Catalog delta and recommendation

None. Next: No catalog change. A PROTOCOL item would need a published wire format, and none was found.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `rustdesk.com` | **L** resolves; TLSv1.2, ALPN `h2`, cert `rustdesk.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `rustdesk`: networking / remote-access, client-server; characteristics `tunnels-other-applications`, `prone-to-misuse`, `used-by-malware`; **risk 4**: carries other traffic or remote control; commonly misused (unsanctioned remote access, data exfiltration); seen in malware campaigns.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
