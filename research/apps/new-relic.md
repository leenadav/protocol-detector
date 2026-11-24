# New Relic (observability)

- Content-pack id today: `new-relic` (`newrelic.com`, `nr-data.net`)
- Proposed: new vendor-level id `new-relic-base` for the browser agent's five hosts (decision 4), batch Q; `new-relic` unchanged
- Status: **READY** (`blocked-urls.md` row 43)
- Sources: [NR] read by Research Lab from the Hermes server (direct network, no sign-in, no challenge bypass), 2026-11-22 (PRO-168); relayed verbatim in `research/relay/pro-168-rows-30-44.md` on `hermes/research-data-pro168` at `f721a8c4fb2b2056ea5bfb2141b1574059f8a933` (PRO-182); [RC] and [FD] (RingCentral and Freshdesk pages, same read) for the embedding

## 1. What it is

New Relic is an observability platform: APM, infrastructure and mobile agents, OpenTelemetry and the Event, Log, Metric and
Trace APIs send telemetry to New Relic's ingest endpoints. Its browser agent runs inside customers' web pages.

## 2. Transport and ports

"For all data ingest applications, with the exception of OpenTelemetry, use port 443 ... If you have an existing
configuration that uses port 80, we recommend updating it to use 443" [NR]. OpenTelemetry (`otlp.nr-data.net`,
`otlp.eu01.nr-data.net`, `otlp.jp.nr-data.net`): 443, 4317 (HTTP/2) and 4318 (HTTP/1.1) [NR]. The IAST validator needs
secure WebSocket. "Networks, IPs, domains, ports, and endpoints last updated March 4, 2025" [NR].

## 3. Observable evidence

[NR] lists the telemetry endpoints per region (US 20, EU 22, JP 19 names), every one under `newrelic.com` or `nr-data.net`:
`collector`, `aws-api`, `cloud-collector`, `bam`, `bam-cell`, `csec`, `insights-collector`, `log-api`, `metric-api`,
`trace-api`, `infra-api`, `identity-api`, `infrastructure-command-api`, `opamp.service`, `system-identity-oauth.service`,
`nrql-lookup.service`, `mobile-collector`, `mobile-crash`, `mobile-symbol-upload` and `otlp` (with `.eu`, `.eu01` and
`.jp` variants). Browser monitoring ingest is `bam*` [NR]. No CDN hosts are listed. Ingest IP blocks: five IPv4 ranges
(recorded, not used).

Two other vendors' pages, read in the same pass, list New Relic's browser hosts as dependencies of their own apps:
RingCentral's help panel (`js-agent.newrelic.com`, `bam.nr-data.net`) [RC] and Freshdesk ("`bam.nr-data.net`: Used for new
relic integration") [FD].

## 4. Encrypted-traffic caveats

The browser agent loads on unrelated sites: with today's catalog, a RingCentral or Freshdesk user's browser is reported as
`new-relic` for `bam.nr-data.net`. Decision 4 (tag hosts loaded on unrelated pages go to a vendor-level id, as for
`datadog-base` and `hubspot-base`) applies. The agent and API endpoints (`collector`, `otlp`, `log-api`, ...) are sent by
the customer's own servers and stay `new-relic`.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI of an agent or API endpoint under `newrelic.com` / `nr-data.net` | **N3** | Telemetry from a monitored host |
| `bam*.nr-data.net`, `js-agent.newrelic.com` | **N2** as `new-relic-base` | Loaded by other sites; names the embed, not New Relic use |
| `newrelic.com` apex and `docs` | **N2** | Also the company and documentation site |
| Port 4317/4318 alone | **U** | Generic OTLP ports used by every OpenTelemetry backend |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K, M, N, O, P and Q): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `collector.newrelic.com`, `otlp.eu01.nr-data.net`, `csec.jp.nr-data.net` | `new-relic` |
| P2 | SNI `bam.nr-data.net`, `bam.eu01.nr-data.net`, `js-agent.newrelic.com` | `new-relic-base` |
| N1 | SNI `xnr-data.net` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O, P and Q as rebuilt 2026-11-24)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xnewrelic.com` | not new-relic/new-relic-base (label boundary) | no application | PASS |
| L- | `newrelic.com.example.invalid` | not new-relic/new-relic-base (suffix look-alike) | no application | PASS |
| L- | `xnr-data.net` | not new-relic/new-relic-base (label boundary) | no application | PASS |
| L- | `nr-data.net.example.invalid` | not new-relic/new-relic-base (suffix look-alike) | no application | PASS |
| L- | `bam.nr-data.net.example.invalid` | not new-relic/new-relic-base (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [NR] New Relic Docs, networks page (title not relayed), `https://docs.newrelic.com/docs/new-relic-solutions/get-started/networks/`,
  HTTP 200, no redirect; page states "last updated March 4, 2025".
- [RC] RingCentral, "Network requirements for RingEX" (Table 3.2.1, help panel row); see `apps/ringcentral.md`.
- [FD] Freshdesk, "Freshdesk domains to whitelist in your firewall"; see `apps/freshworks.md`.

## 8. Catalog delta and recommendation

New id `new-relic-base` (general-internet / internet-utility, browser-based, risk 2, "New Relic browser agent embedded in
other websites (not New Relic use)"), placed before `new-relic`, with `bam.nr-data.net`, `bam-cell.nr-data.net`,
`bam.eu01.nr-data.net`, `bam.jp.nr-data.net` and `js-agent.newrelic.com`. `new-relic` keeps `newrelic.com` and `nr-data.net`;
longest-suffix matching sends the five exact names to the new id. The dualstack and FedRAMP endpoint lists were not copied,
so their names are not checked here. Patch:
`research/patches/batch-q-relayed-rows-30-44.patch`.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `newrelic.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `nr-data.net` | not yet verified (added after round 2; not yet queued for a live round) |
| `bam.nr-data.net` | not yet verified (added after round 2; not yet queued for a live round) |
| `bam-cell.nr-data.net` | not yet verified (added after round 2; not yet queued for a live round) |
| `bam.eu01.nr-data.net` | not yet verified (added after round 2; not yet queued for a live round) |
| `bam.jp.nr-data.net` | not yet verified (added after round 2; not yet queued for a live round) |
| `js-agent.newrelic.com` | not yet verified (added after round 2; not yet queued for a live round) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `new-relic`: business-systems / management, client-server; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- `new-relic-base`: general-internet / internet-utility, browser-based; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- Functions separated by name: `new-relic` (New Relic observability), `new-relic-base` (New Relic browser agent embedded in other websites (not New Relic use)).
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
