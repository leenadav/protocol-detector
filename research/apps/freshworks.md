# Freshworks (Freshdesk and Freshservice)

- Content-pack id today: `freshworks` (`freshworks.com`, `freshdesk.com`, `freshservice.com`)
- Proposed: `freshworks` extended with five Freshworks platform domains, batch Q
- Status: **READY** (`blocked-urls.md` row 40)
- Sources: [FD] and [FS] read by Research Lab from the Hermes server (direct network, no sign-in, no challenge bypass), 2026-11-22 (PRO-168); relayed verbatim in `research/relay/pro-168-rows-30-44.md` on `hermes/research-data-pro168` at `f721a8c4fb2b2056ea5bfb2141b1574059f8a933` (PRO-182)

## 1. What it is

Freshdesk (customer support) and Freshservice (IT service management) are Freshworks SaaS products; they share Freshworks'
sign-in (`myfreshworks.com`), notification and marketplace platform.

## 2. Transport and ports

Neither page states ports. The products are web applications; TCP 443 is the expected transport but is not stated
(`UNVERIFIED`).

## 3. Observable evidence

[FD]: "To ensure all functions of Freshdesk work properly, please whitelist these domains in your firewall." Freshworks-owned
rows (as written):

| Name | Description |
|---|---|
| `*.freshdesk.com` | "API calls to Freshdesk" |
| `*.myfreshworks.com` | "Unified authentication system in Freshworks" |
| `*.freshworksapi.com` | "Used for authentication and agent profiles" |
| `*.rtschannel.com` | "a platform service within Freshworks to push notifications/messages inside the product" |
| `*.fdcollab.com`, `api.fdcollab.com` | "Freshconnect integration in Freshdesk. It's a collaborator feature" |
| `*.freshdev.io` | "Used for marketplace integration" |
| `*.freshchat.com`, `*.webpush.freshchat.com`, `apicdn-wchat.freshchat.com` | "Freshchat integration with Freshdesk" |
| `*.freshmarketer.com` (support portal only) | "Freshmarketer integration" |

Third-party rows: `*.amazonaws.com`, `*.s3.amazonaws.com`, Cloudflare (`*.cloudflare.com`, `cdnjs`, `ajax`,
`cloudflareinsights.com`), `*.cloudfront.net`, Inline Manual, `bam.nr-data.net` (New Relic), Heap Analytics, and for the
support portal Google Analytics, `addevent.com` and `netdna.bootstrapcdn.com`.

[FS] has no domain table: "you can allowlist the 'freshservice.com' and 'myfreshworks.com' domains, or resolve these domains
to IPs at your end and allowlist those IPs" (the load-balancer IPs were deprecated by November 2025).

## 4. Encrypted-traffic caveats

Freshchat and Freshmarketer are separate Freshworks products (a chat service and a marketing product). Whether their scripts
load on customers' own websites is not stated on these pages (`UNVERIFIED`). If they do, adding them to `freshworks` would
name Freshworks for visits to unrelated sites (decision 4). They are left out, conservatively, and recorded here. `bam.nr-data.net` is New Relic's browser agent, see `apps/new-relic.md`.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `freshdesk.com`, `freshservice.com` | **N3** | Tenant names `<company>.freshdesk.com` |
| SNI under `myfreshworks.com`, `freshworksapi.com`, `rtschannel.com` | **N2** | Shared by every Freshworks product |
| SNI under `fdcollab.com`, `freshdev.io` | **N2** | Collaboration and marketplace platform |
| `freshchat.com`, `freshmarketer.com` | **U** for this app | Separate products; possible embedding `UNVERIFIED` |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K, M, N, O, P and Q): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `acme.freshdesk.com`, `acme.myfreshworks.com`, `x.rtschannel.com`, `api.fdcollab.com`, `x.freshdev.io`, `x.freshworksapi.com` | `freshworks` |
| N1 | SNI `x.freshchat.com`, `xfreshdesk.com` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O, P and Q as rebuilt 2026-11-24)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xfreshworks.com` | not freshworks (label boundary) | no application | PASS |
| L- | `freshworks.com.example.invalid` | not freshworks (suffix look-alike) | no application | PASS |
| L- | `xfreshdesk.com` | not freshworks (label boundary) | no application | PASS |
| L- | `freshdesk.com.example.invalid` | not freshworks (suffix look-alike) | no application | PASS |
| L- | `xfreshservice.com` | not freshworks (label boundary) | no application | PASS |
| L- | `freshservice.com.example.invalid` | not freshworks (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [FD] Freshdesk Support, "Freshdesk domains to whitelist in your firewall",
  `https://support.freshdesk.com/support/solutions/articles/234412-freshdesk-domains-to-whitelist-in-your-firewall`,
  HTTP 200; "Modified on: Wed, 12 Jun, 2024 at 8:01 PM".
- [FS] Freshservice Support, "Update to WAF (Web Application Firewall) for Freshservice load balancers",
  `https://support.freshservice.com/support/solutions/articles/50000003571-update-to-waf-web-application-firewall-for-freshservice-load-balancers`
  (redirected from `/en/support/...`), HTTP 200; "Modified on: Fri, 14 Nov, 2025 at 5:09 PM".

## 8. Catalog delta and recommendation

Extend `freshworks` with `myfreshworks.com`, `freshworksapi.com`, `rtschannel.com`, `fdcollab.com` and `freshdev.io`.
Not added: `freshchat.com`, `freshmarketer.com` (separate products, possible embedding `UNVERIFIED`; they need their own source) and every
third-party row. Patch: `research/patches/batch-q-relayed-rows-30-44.patch`.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `freshworks.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `freshdesk.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `freshservice.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `myfreshworks.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `freshworksapi.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `rtschannel.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `fdcollab.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `freshdev.io` | not yet verified (added after round 2; not yet queued for a live round) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `freshworks`: business-systems / general-business, browser-based; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
