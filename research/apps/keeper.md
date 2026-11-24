# Keeper (password manager and KeeperPAM)

- Content-pack id today: `keeper` (`keepersecurity.com`)
- Proposed: `keeper` extended with the five regional domains and `keeper.io`, batch Q
- Status: **READY** (`blocked-urls.md` row 36)
- Sources: [KP] read by Research Lab from the Hermes server (direct network, no sign-in, no challenge bypass), 2026-11-22 (PRO-168); relayed verbatim in `research/relay/pro-168-rows-30-44.md` on `hermes/research-data-pro168` at `f721a8c4fb2b2056ea5bfb2141b1574059f8a933` (PRO-182)

## 1. What it is

Keeper is a password manager and secrets vault; KeeperPAM adds privileged-access connections and tunnels. Each tenant is
hosted in one region (US, US GovCloud, EU, AU, CA, JP).

## 2. Transport and ports

"For all application access, outbound TCP port 443 should be open to your users for the endpoints listed below, depending on
your tenant location. For KeeperPAM connections and tunnels, TCP and UDP 3478 also needs to be open to the region's krelay
endpoint" [KP]. "We recommend using FQDN since some of Keeper's services use dynamic IPs" [KP].

## 3. Observable evidence

| Region | Names [KP] |
|---|---|
| Global, all customers | `keepersecurity.com`, `keeper.io`, `gitbook.io` (documentation portal) |
| US | `keepersecurity.com`, `push.services`, `files.services`, `connect`, `krelay` `.keepersecurity.com` |
| US GovCloud | `govcloud.keepersecurity.us`, `push.services`, `files.services`, `connect`, `krelay` `.keepersecurity.us` |
| EU, AU, CA, JP | the same five names under `keepersecurity.eu`, `keepersecurity.com.au`, `keepersecurity.ca`, `keepersecurity.jp` |

E-mail is sent through Amazon SES from dedicated IPs; inbound SIEM and Automator source IPs per region are on the page and
were not copied (inbound, not used by a detector).

## 4. Encrypted-traffic caveats

`krelay.*` on 3478 is a relay for PAM tunnels (TCP and UDP): it tunnels other protocols, so a `krelay` session is Keeper
by name but its payload is the tunnelled application. The UDP leg is off the observed path in this phase. `gitbook.io` is a
third-party documentation host used by many other projects and names no application.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `keepersecurity.<region>` | **N3** | Apex names also serve Keeper's web site |
| SNI under `keeper.io` | **N2** | Also the documentation site (`docs.keeper.io`) |
| `gitbook.io` | not attributed | Third party |
| Port 3478 alone | **U** | Shared with every STUN/TURN service |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K, M, N, O, P and Q): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `krelay.keepersecurity.eu`, `connect.keepersecurity.com.au`, `govcloud.keepersecurity.us`, `docs.keeper.io` | `keeper` |
| N1 | SNI `xkeeper.io`, `keepersecurity.com.example.invalid` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O, P and Q as rebuilt 2026-11-24)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xkeepersecurity.com` | not keeper (label boundary) | no application | PASS |
| L- | `keepersecurity.com.example.invalid` | not keeper (suffix look-alike) | no application | PASS |
| L- | `xkeepersecurity.us` | not keeper (label boundary) | no application | PASS |
| L- | `keepersecurity.us.example.invalid` | not keeper (suffix look-alike) | no application | PASS |
| L- | `xkeepersecurity.eu` | not keeper (label boundary) | no application | PASS |
| L- | `keepersecurity.eu.example.invalid` | not keeper (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [KP] Keeper Documentation, "Keeper FQDNs and IP Addresses", `https://docs.keeper.io/enterprise-guide/ip-allow-keeper`
  (redirected from `/en/enterprise-guide/...`), HTTP 200; "Last updated 4 months ago" (page metadata `updatedAt`
  2026-11-18T22:37:03Z).

## 8. Catalog delta and recommendation

Extend `keeper` with `keepersecurity.us`, `keepersecurity.eu`, `keepersecurity.com.au`, `keepersecurity.ca`,
`keepersecurity.jp` and `keeper.io`. `gitbook.io` is not added. Patch: `research/patches/batch-q-relayed-rows-30-44.patch`.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `keepersecurity.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `keepersecurity.us` | not yet verified (added after round 2; not yet queued for a live round) |
| `keepersecurity.eu` | not yet verified (added after round 2; not yet queued for a live round) |
| `keepersecurity.com.au` | not yet verified (added after round 2; not yet queued for a live round) |
| `keepersecurity.ca` | not yet verified (added after round 2; not yet queued for a live round) |
| `keepersecurity.jp` | not yet verified (added after round 2; not yet queued for a live round) |
| `keeper.io` | not yet verified (added after round 2; not yet queued for a live round) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `keeper`: business-systems / auth-service, client-server; characteristics none; **risk 1**: no risk-raising characteristic recorded; rating from its category.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
