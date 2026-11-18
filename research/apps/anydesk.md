# AnyDesk

- Content-pack id today: `anydesk` (`anydesk.com`, `net.anydesk.com`; web fronts `anydesk.com`, `www.anydesk.com`)
- Status: **READY** for the host name and ports. The wire format beyond "TLS" is unpublished.
- Sources accessed: 2026-11-18. Page "Updated on Jan 21, 2026"

## 1. What it is

A commercial remote-desktop and remote-support tool. Unsanctioned remote-access tools are a standing
concern for gateway operators (shadow IT, abuse in support scams). The pack already marks it
`prone-to-misuse` and `used-by-malware`, risk 4.

## 2. Transport and ports

As published [S1]:

- "TCP ports: 80, 443, and 6568". "At least one of these ports must be open to create a remote connection."
- "UDP ports: 50001–50003", "Used by AnyDesk's Discovery feature to identify devices on the local
  network", sent to "239.255.102.18 (multicast)". This is local multicast and never reaches the proxy.

## 3. Observable evidence

- **Host name**: "we recommend whitelisting the following domain ... `*.net.anydesk.com`. This ensures
  that the AnyDesk client can reach our servers and initiate or maintain remote sessions" [S1].
- **TLS**: AnyDesk asks to be excluded from "HTTPS scanning" and "Deep packet inspection (DPI)" because
  "these scans can disrupt AnyDesk's TLS encryption" [S1]. So the client-to-server session is TLS.
  `UNVERIFIED`: whether the ClientHello carries an SNI, what it contains, and which ALPN (if any) is
  offered. The page says nothing about them.
- **Port 6568**: a vendor-specific port [S1]. Detection never uses ports (v0.65 contract), but a TLS
  ClientHello to TCP 6568 through CONNECT is a useful corroborating fact for the log.

## 4. Encrypted-traffic caveats

- If AnyDesk's ClientHello omits SNI, only the proxy's CONNECT target names the destination. That
  target is the proxy's own fact, not the detector's.
- AnyDesk explicitly expects to break under TLS interception [S1]. In the visibility phase nothing is
  intercepted, so the remark matters only for later phases.
- Direct (peer-to-peer) connections are implied by the Windows firewall prompt for "direct
  connections" [S1]. They bypass the proxy and are invisible to it.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `net.anydesk.com` | **N3** remote session | If SNI is sent at all (`UNVERIFIED`) |
| SNI `anydesk.com`, `www.anydesk.com` | web front only | Download and marketing site; already a web front in the pack |
| CONNECT to TCP 6568 with a TLS ClientHello | supporting fact | Port alone never names an app |
| Custom clients | not separable | AnyDesk offers "Custom Client" builds [S1]; no published name difference |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `relay-01.net.anydesk.com` (synthetic label), TCP 443 | `anydesk` |
| P2 | Same ClientHello through CONNECT to port 6568 | `anydesk`; port recorded, not used for identity |
| P3 | ClientHello with **no** SNI to port 6568 | `ssl`, no application (the name must come from SNI, never from the port) |
| N1 | SNI `www.anydesk.com` | web front, no remote session asserted |
| N2 | SNI `net.anydesk.com.example.invalid` | no application |
| N3 | `ech_outer()` with outer SNI under `net.anydesk.com` | no application |

## 7. Sources

- [S1] AnyDesk Help Center, "Configure firewalls for AnyDesk", `https://support.anydesk.com/firewall`
  (redirected from `/knowledge/firewall`), "Updated on Jan 21, 2026", accessed 2026-11-18.

## 8. Catalog delta and recommendation

No change to names: `net.anydesk.com` is verified. The pack's extra entry `anydesk.com` as a
non-front domain overlaps the web fronts. The Engine lane should confirm that only `www.` and the apex are
fronts and other `anydesk.com` subdomains name the application, which is what the current
pack appears to do. Next research step: AnyDesk's documentation of its connection protocol, if it
exists, to verify the SNI question.
