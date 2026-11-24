# PagerDuty (incident response)

- Content-pack id today: `pagerduty` (`pagerduty.com`)
- Status: **DONE**, verified, no catalog change (`blocked-urls.md` row 44)
- Sources: [PD] read by Research Lab from the Hermes server (direct network, no sign-in, no challenge bypass), 2026-11-22 (PRO-168); relayed verbatim in `research/relay/pro-168-rows-30-44.md` on `hermes/research-data-pro168` at `f721a8c4fb2b2056ea5bfb2141b1574059f8a933` (PRO-182)

## 1. What it is

PagerDuty is an incident-response service: monitoring tools send events to it, responders use its web and mobile apps, and
it calls out to webhooks and integrations.

## 2. Transport and ports

Events API: TCP 443 (HTTPS). REST API: TCP 443, "HTTP connections are not allowed". Jira Server integration to
`app.pagerduty.com` / `app.eu.pagerduty.com`: port not stated. Webhooks are outbound from PagerDuty to customer-chosen
endpoints [PD].

## 3. Observable evidence

| Purpose | US | EU |
|---|---|---|
| Events API (trigger, acknowledge, resolve) | `events.pagerduty.com` | `events.eu.pagerduty.com` |
| REST API | `api.pagerduty.com` | `api.eu.pagerduty.com` |
| Jira Server integration | `app.pagerduty.com` | `app.eu.pagerduty.com` |

The page says IP safelisting "is no longer best practice" for webhooks and to "Safelist IPs resolving to the URLs
corresponding to your service region. Currently available regions are US and EU." Example A records are quoted for the
Events API (three US, three EU addresses); REST API addresses are in a separate list. No third-party or CDN hosts [PD].

## 4. Encrypted-traffic caveats

Webhooks leave PagerDuty towards the customer's own names, so they never carry a PagerDuty SNI. The quoted addresses are
examples and change; they are not used.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `pagerduty.com` | **N3** | Also the company site (`www`) |
| Webhook deliveries | **U** by name | Customer's own destination name |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K, M, N, O, P and Q): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `events.eu.pagerduty.com`, `api.pagerduty.com` | `pagerduty` |
| N1 | SNI `xpagerduty.com` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O, P and Q as rebuilt 2026-11-24)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xpagerduty.com` | not pagerduty (label boundary) | no application | PASS |
| L- | `pagerduty.com.example.invalid` | not pagerduty (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [PD] PagerDuty Docs, "Safelist IPs", `https://docs.pagerduty.com/account-admin/safelist-ips` (the vendor redirected the URL
  in row 44 here), HTTP 200; no page date shown.

## 8. Catalog delta and recommendation

None. All six names are under `pagerduty.com`.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `pagerduty.com` | not yet verified (added after round 2; not yet queued for a live round) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `pagerduty`: business-systems / management, client-server; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
