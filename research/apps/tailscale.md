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

## 7. Sources

- [S1] Tailscale docs, "What firewall ports should I open to use Tailscale?", `https://tailscale.com/docs/reference/faq/firewall-ports.md`, accessed 2026-11-18.

## 8. Catalog delta and recommendation

No change. DERP relay names: the DERP-servers page (`https://tailscale.com/docs/reference/derp-servers.md`, "Last validated Jan 21, 2026") says clients receive a DERP map from the coordination server, retrievable at `https://controlplane.tailscale.com/derpmap/default`. That host is not allowed in this session, so the relay names are **BLOCKED**, low value: if they are under `tailscale.com` they are already mapped. `tailscale.io` remains unverified.
