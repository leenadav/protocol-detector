# Kaseya VSA (SaaS and agent)

- Content-pack id today: `kaseya` (`kaseya.com`, `kaseya.net`; web fronts `kaseya.com`, `www.kaseya.com`)
- Status: **DONE**, verified, no catalog change (`blocked-urls.md` rows 30 and 31)
- Sources: [K1] and [K2] read by Research Lab from the Hermes server (direct network, no sign-in, no challenge bypass), 2026-11-22 (PRO-168); relayed verbatim in `research/relay/pro-168-rows-30-44.md` on `hermes/research-data-pro168` at `f721a8c4fb2b2056ea5bfb2141b1574059f8a933` (PRO-182)

## 1. What it is

Kaseya VSA is a remote monitoring and management (RMM) platform for managed service providers: an agent on each managed
endpoint checks in to a Kaseya server (Kaseya-hosted SaaS or on-premises) and receives scripts, patches and remote-control
sessions.

## 2. Transport and ports

- Agent to server: "TCP/IP Outbound Port 5721. Agents connect to the Kaseya Server on port 5721. This port assignment may be
  changed by the administrator" [K2]; the SaaS page says "The Kaseya Agent communicates on the following port": TCP/UDP
  outbound 5721 [K1].
- Remote control and P2P file deployment: "UDP/TCP Outbound Port 3478 to stun.kaseya.com" [K2].
- Web UI: TCP 80 and 443 [K1]. Alarm e-mail relay: port 25, sending domain `sg.cloud.kaseya.net` [K1].

## 3. Observable evidence

- [K1] lists **no host names** for agent check-in, only IP ranges per region (NA: four ranges; UK/EU: seven). The Kaseya
  server's own name is customer-specific and not published [K2].
- The only host names on the two pages are `stun.kaseya.com` (UDP/TCP 3478) [K2], `sg.cloud.kaseya.net` (mail) and the
  status page `status.kaseya.net` [K1]. All three are under catalog suffixes.
- Port 5721 carries Kaseya's own agent protocol; its bytes are not published, so there is no structural profile (**U**).

## 4. Encrypted-traffic caveats

The SaaS VSA instance name is not on the page, so a tenant reached by a customer's own name or by IP is not identifiable by
name. STUN on 3478 is a UDP family and off the observed path in the visibility phase. [K1] also lists Cloudflare's published
ranges (Cloudflare fronting): shared front-end addresses, never evidence.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `kaseya.com` / `kaseya.net` | **N2** | Also the vendor's marketing site and other Kaseya products (already a web front) |
| `stun.kaseya.com` on 3478 | **N3** for the name | UDP path not observed in this phase |
| Port 5721 alone | **U** | Administrator can change it; no published bytes |
| SaaS IP ranges | not used | IP evidence is outside the name catalog |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K, M, N, O, P and Q): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `stun.kaseya.com`, `sg.cloud.kaseya.net` | `kaseya` |
| N1 | SNI `xkaseya.com` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O, P and Q as rebuilt 2026-11-24)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xkaseya.com` | not kaseya (label boundary) | no application | PASS |
| L- | `kaseya.com.example.invalid` | not kaseya (suffix look-alike) | no application | PASS |
| L- | `xkaseya.net` | not kaseya (label boundary) | no application | PASS |
| L- | `kaseya.net.example.invalid` | not kaseya (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [K1] Kaseya Helpdesk, "Kaseya Cloud SaaS IP Addresses and Ports",
  `https://helpdesk.kaseya.com/hc/en-gb/articles/229028268-Kaseya-Cloud-SaaS-IP-Addresses-and-Ports`, HTTP 200, no redirect;
  no page date shown.
- [K2] Kaseya VSA 9 help, "Agent Minimum Requirements", `https://help.vsa9.kaseya.com/help/Content/VSA/reqs/home.htm`,
  HTTP 200; page "Last modified" 2024-03-05.

## 8. Catalog delta and recommendation

None. Every Kaseya-owned name on both pages is under `kaseya.com` or `kaseya.net`. The IP ranges are recorded here only;
the name catalog does not carry addresses.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `kaseya.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `kaseya.net` | not yet verified (added after round 2; not yet queued for a live round) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `kaseya`: networking / remote-access, client-server; characteristics `tunnels-other-applications`, `prone-to-misuse`; **risk 4**: carries other traffic or remote control; commonly misused (unsanctioned remote access, data exfiltration).
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
