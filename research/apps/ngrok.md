# ngrok

- Content-pack id today: `ngrok` (`ngrok.com`; web fronts `ngrok.com`, `www.ngrok.com`)
- Status: **READY**, NAME, batch C (`research/patches/batch-c-name-based.patch`)
- Sources accessed: 2026-11-18

## 1. What it is

A tunnelling service. The ngrok agent, run inside a network, publishes a local service to the internet.
For a gateway operator, an agent connecting out is the shadow-IT event worth seeing.

## 2. Transport and ports

Outbound only: "Firewalls usually allow outbound connections, which is what an ngrok agent makes to
establish a session with the ngrok service" [S1]. Certificate revocation checks use port 80 by default, or
HTTPS on 443 when `crl_url` is set to `https://crl.ngrok-agent.com/ngrok.crl` [S1].

## 3. Observable evidence

Agent hosts, as published:

| Host | Purpose (as published) |
|---|---|
| `connect.ngrok-agent.com` | "Connect URLs (the default is connect.ngrok-agent.com, but there is one for each region)" [S1] |
| `connect.us.`, `.eu.`, `.ap.`, `.au.`, `.sa.`, `.jp.`, `.in.ngrok-agent.com` | regional connect hosts, listed as "the DNS lookups to block" to stop non-corporate accounts [S2] |
| `tunnel.ngrok.com` and `tunnel.{us,eu,ap,au,sa,jp,in}.ngrok.com` | same list [S2] |
| `update.ngrok-agent.com` | "The update URL ... so that the ngrok agent can quickly update itself" [S1] |
| `update.equinox.io` | update URL for agents before 3.36.0. "Equinox is fully owned by ngrok and used exclusively for building and distributing ngrok binaries" [S1] |
| `crl.ngrok-agent.com` (3.10.0 and later), `crl.ngrok.com` (3.9.0 and before) | certificate revocation list [S1] |

Custom Connect URLs exist: an organization can brand its own connect host and block the defaults [S1, S2].

## 4. Encrypted-traffic caveats

- SNI only. A custom Connect URL is the customer's own domain, so it is invisible to this catalog by design.
- Public endpoints served by ngrok for its users' tunnels are tenant hosting. Under the v0.65 rule they
  name no application, and no source here lists them.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `ngrok-agent.com` | **N3** agent session or update | Connect vs update vs CRL is visible only by first label |
| SNI `tunnel*.ngrok.com` | **N3** | Already `ngrok` via `ngrok.com` |
| SNI `update.equinox.io` | **N3** (exact host) | The domain `equinox.io` is not mapped; only the named host |
| `ngrok.com`, `www.ngrok.com` | web front | Unchanged |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `47b2743` plus batch C): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `connect.ngrok-agent.com`, `connect.eu.ngrok-agent.com` | `ngrok` (today unmapped) |
| P2 | SNI `update.ngrok-agent.com`, `crl.ngrok-agent.com`, `update.equinox.io` | `ngrok` |
| P3 | SNI `tunnel.us.ngrok.com` | `ngrok` |
| N1 | SNI `equinox.io` | no application |
| N2 | SNI `x.ngrok-free.app` (synthetic tenant name) | no application |
| N3 | `ech_outer()` with outer SNI `connect.ngrok-agent.com` | no application (engine rule; not a name lookup) |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O, P and Q as rebuilt 2026-11-24)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `assets.ngrok.com` | one of `ngrok` | `ngrok` | PASS |
| O+ | `dashboard.ngrok.com` | one of `ngrok` | `ngrok` | PASS |
| O+ | `login.ngrok.com` | one of `ngrok` | `ngrok` | PASS |
| L- | `xngrok.com` | not ngrok (label boundary) | no application | PASS |
| L- | `ngrok.com.example.invalid` | not ngrok (suffix look-alike) | no application | PASS |
| L- | `xngrok-agent.com` | not ngrok (label boundary) | no application | PASS |
| L- | `ngrok-agent.com.example.invalid` | not ngrok (suffix look-alike) | no application | PASS |
| L- | `xequinox.io` | not ngrok (label boundary) | no application | PASS |
| L- | `update.equinox.io.example.invalid` | not ngrok (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] ngrok docs, "Running ngrok Behind a Corporate Firewall", `https://ngrok.com/docs/guides/running-behind-firewalls.md`, accessed 2026-11-18.
- [S2] ngrok docs, "Securing your tunnels" ("Blocking non-corporate accounts"), `https://ngrok.com/docs/gateway/security-dev-productivity/securing-your-tunnels.md`, accessed 2026-11-18.

## 8. Catalog delta and recommendation

```python
("ngrok", "networking", "remote-access", "client-server", 4, "ngrok tunnel service control plane",
 ("tunnels-other-applications", "prone-to-misuse", "used-by-malware"), ("ngrok.com", "ngrok-agent.com", "update.equinox.io"),
 ("ngrok.com", "www.ngrok.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `ngrok.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `ngrok.com`, no subject organisation (domain-validated) (issuer Let's Encrypt) |
| `ngrok-agent.com` | apex has no address (normal for a suffix entry); suffix **verified** through documented `crl.ngrok-agent.com` (round 2) |
| `update.equinox.io` | **L** resolves; TLSv1.3, ALPN `h2`, cert `update.equinox.io`, no subject organisation (domain-validated) (issuer Let's Encrypt); CNAME into shared front end `update.equinox.io.herokudns.com`: name usable, IPs never |

## 10. Observed web-client hosts (dependency mapping)

- `https://dashboard.ngrok.com/login`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `login.ngrok.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `assets.ngrok.com` | seen | app-owned | `ngrok` | not checked |  |
| `dashboard.ngrok.com` | seen | app-owned | `ngrok` |  |  |
| `login.ngrok.com` | seen | app-owned | `ngrok` |  |  |

## 11. Attributes (App-ID model) and re-verify date

- `ngrok`: networking / remote-access, client-server; characteristics `tunnels-other-applications`, `prone-to-misuse`, `used-by-malware`; **risk 4**: carries other traffic or remote control; commonly misused (unsanctioned remote access, data exfiltration); seen in malware campaigns.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
