# Tailscale

- Content-pack id today: `tailscale` (`tailscale.com`, `tailscale.io`; web fronts `tailscale.com`, `www.tailscale.com`)
- Status: **DONE**, NAME: the coordination hosts are verified, so no catalog change. `tailscale.io` is unverified (kept)
- Sources accessed: 2026-11-18. Page "Last validated Feb 2, 2026"

## 1. What it is

A WireGuard-based mesh VPN with a hosted coordination service and DERP relays.

## 2. Transport and ports

From [S1]:

| Use | Transport (as published) |
|---|---|
| Coordination server and backend | HTTPS TCP 443; coordination "prefer[s] to use HTTP on port 80 with an efficient encrypted transport", falling back to 443 |
| DERP relays | HTTPS TCP 443 ("The set of DERP relays ... grows over time") |
| Direct WireGuard | UDP from source port 41641 (default) |
| STUN | UDP 3478, "only ... to DERP servers" |
| Captive-portal check | unencrypted HTTP to `/generate_204` on port 80 |

`login.tailscale.com` and `controlplane.tailscale.com` resolve to `192.200.0.0/24` / `2606:B740:49::/48`
(since July 2025); `log.tailscale.com` to `199.165.136.0/24` / `2606:B740:1::/48` [S1].

## 3. Observable evidence

- SNI `login.tailscale.com`, `controlplane.tailscale.com`, `log.tailscale.com` [S1], all under `tailscale.com`.
- Coordination over port 80 is not plain HTTP but "an efficient encrypted transport" [S1]. Its wire
  format is not on this page (`UNVERIFIED`), so the HTTP/1 family may see only an initial request or nothing.
- DERP relay host names are not listed on this page. The DERP map is a separate document, not read here.

## 4. Encrypted-traffic caveats

The data plane is WireGuard over UDP (an engine family, off the visibility-phase path). Relayed traffic
over DERP on TCP 443 is visible only as TLS to DERP hosts, whose names are not verified here.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `tailscale.com` (not apex or `www`) | **N3** coordination and logging | |
| `tailscale.io` (pack) | **U** | Not on the page |
| DERP hosts | **U** | Not read |

## 6. Synthetic test vectors

`login.tailscale.com`, `controlplane.tailscale.com`, `log.tailscale.com` → `tailscale` (checked in scratch). `www.tailscale.com` → web front.

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J and K as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `login.tailscale.com` | one of `tailscale` | `tailscale` | PASS |
| L- | `xtailscale.com` | not tailscale (label boundary) | no application | PASS |
| L- | `tailscale.com.example.invalid` | not tailscale (suffix look-alike) | no application | PASS |
| L- | `xtailscale.io` | not tailscale (label boundary) | no application | PASS |
| L- | `tailscale.io.example.invalid` | not tailscale (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Tailscale docs, "What firewall ports should I open to use Tailscale?", `https://tailscale.com/docs/reference/faq/firewall-ports.md`, accessed 2026-11-18.

## 8. Catalog delta and recommendation

No change. DERP relay names: the DERP-servers page (`https://tailscale.com/docs/reference/derp-servers.md`, "Last validated Jan 21, 2026") says clients receive a DERP map from the coordination server, retrievable at `https://controlplane.tailscale.com/derpmap/default`. That host is not allowed in this session, so the relay names are **BLOCKED**, low value: if they are under `tailscale.com` they are already mapped. `tailscale.io` remains unverified.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `tailscale.com` | **L** resolves; TLSv1.2, ALPN `h2`, cert `tailscale.com`, no subject organisation (domain-validated) (issuer Amazon) |
| `tailscale.io` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |

## 10. Observed web-client hosts (dependency mapping)

- `https://login.tailscale.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `login.tailscale.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `login.tailscale.com` | seen | app-owned | `tailscale` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `tailscale`: networking / encrypted-tunnel, client-server; characteristics `tunnels-other-applications`; **risk 3**: carries other traffic or remote control.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
