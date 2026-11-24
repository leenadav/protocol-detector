# Datadog (Agent, web app and browser RUM intake)

- Content-pack id today: `datadog` (`datadoghq.com`, `datadoghq.eu`)
- Status: **READY**, NAME, batch M (`research/patches/batch-m-name-based.patch`): `ddog-gov.com` added to `datadog`; new vendor-level id `datadog-base` for the browser RUM intake domains
- Sources: [D1, D2, D3] read in the research cloud (egress proxy), 2026-11-21 (markdown versions of the pages); no page dates shown

## 1. What it is

Infrastructure monitoring, APM and log management: the Agent on customer hosts sends telemetry to Datadog intake hosts; users work in the web app; the browser RUM SDK, embedded in customers' own websites, sends real-user telemetry.

## 2. Transport and ports

"Traffic is always initiated by the Agent to Datadog" [D1]. Agent data on 443/TCP; Custom Agent Autoscaling 8443/TCP; NTP 123/UDP; a remote-configuration connectivity test on 8042/TCP; deprecated TCP log collection on a site-specific port [D1]. Local-only ports (DogStatsD 8125/UDP, APM receiver 8126/TCP, GUI 5002, IPC 5001) stay on the host [D1].

## 3. Observable evidence

[D1]: install hosts `install.datadoghq.com`, `yum.datadoghq.com`, `keys.datadoghq.com`, `apt.datadoghq.com`, `windows-agent.datadoghq.com`; per-product intake names under the site, for example `trace.agent.<site>`, `<VERSION>-app.agent.<site>` ("You must add `*.agent.<site>`"), `<VERSION>-flare.agent.<site>`, `orchestrator.<site>`, `intake.profile.<site>`, `sbom-intake.<site>`, `ndm-intake.<site>`, `llmobs-intake.<site>`, `intake.synthetics.<site>`. Sites [D2]: `datadoghq.com` (US1) and `us3`, `us5`, `ap1`, `ap2`, `uk1` `.datadoghq.com`, `datadoghq.eu` (EU1), `ddog-gov.com` (US1-FED, US2-FED). Browser RUM intake origins [D3]: `browser-intake-datadoghq.com`, `browser-intake-us3-datadoghq.com`, `browser-intake-us5-datadoghq.com`, `browser-intake-datadoghq.eu`, `browser-intake-ap1-datadoghq.com`, `browser-intake-ap2-datadoghq.com`, `browser-intake-uk1-datadoghq.com`, `browser-intake-ddog-gov.com`, `browser-intake-us2-ddog-gov.com`.

## 4. Encrypted-traffic caveats

The browser intake names are separate registrable domains (`browser-intake-datadoghq.eu` is **not** under `datadoghq.eu`). They are loaded by customers' websites (dependency pass 1 saw `browser-intake-us5-datadoghq.com` on the Claude platform page and `browser-intake-datadoghq.com` on Loom), so under decision 4 they go to the vendor-level id `datadog-base`, not to `datadog`: a match there means a page embeds Datadog RUM, not that the user works in Datadog. Agent traffic is TLS to names under the site; the site itself (US1, EU1, Gov) identifies the region, which is not emitted.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `datadoghq.com`, `datadoghq.eu` | **N3** | Already mapped |
| SNI under `ddog-gov.com` | **N3** | Gov sites |
| SNI under the 9 browser intake domains | **N3** for `datadog-base` | Embedded RUM on other sites; not Datadog use |
| Local ports 8125, 8126, 5001, 5002 | not used | Host-local |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K and M): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `7-31-0-app.agent.datadoghq.com`, `trace.agent.datadoghq.eu` | `datadog` |
| P2 | SNI `app.ddog-gov.com`, `trace.agent.us2.ddog-gov.com` | `datadog` (today unmapped) |
| P3 | SNI `browser-intake-datadoghq.eu`, `browser-intake-us5-datadoghq.com` | `datadog-base` (today unmapped) |
| N1 | SNI `xddog-gov.com`, `browser-intake-datadoghq.net` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O, P and Q as rebuilt 2026-11-24)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xdatadoghq.com` | not datadog/datadog-base (label boundary) | no application | PASS |
| L- | `datadoghq.com.example.invalid` | not datadog/datadog-base (suffix look-alike) | no application | PASS |
| L- | `xdatadoghq.eu` | not datadog/datadog-base (label boundary) | no application | PASS |
| L- | `datadoghq.eu.example.invalid` | not datadog/datadog-base (suffix look-alike) | no application | PASS |
| L- | `xddog-gov.com` | not datadog/datadog-base (label boundary) | no application | PASS |
| L- | `ddog-gov.com.example.invalid` | not datadog/datadog-base (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [D1] Datadog Docs, "Network Traffic" (Agent), `https://docs.datadoghq.com/agent/configuration/network/`, read in the research cloud (egress proxy), 2026-11-21.
- [D2] Datadog Docs, "Getting Started with Datadog Sites", `https://docs.datadoghq.com/getting_started/site/`, read in the research cloud (egress proxy), 2026-11-21.
- [D3] Datadog Docs, "Proxy Your Browser RUM Data", `https://docs.datadoghq.com/real_user_monitoring/guide/proxy-rum-data/`, read in the research cloud (egress proxy), 2026-11-21.

## 8. Catalog delta and recommendation

```python
("datadog", ..., ("datadoghq.com", "datadoghq.eu", "ddog-gov.com")),
("datadog-base", "general-internet", "internet-utility", "browser-based", 2,
 "Datadog tags and shared services embedded in other websites (not Datadog use)", (),
 ("browser-intake-datadoghq.com", "browser-intake-us3-datadoghq.com", "browser-intake-us5-datadoghq.com",
  "browser-intake-ap1-datadoghq.com", "browser-intake-ap2-datadoghq.com", "browser-intake-uk1-datadoghq.com",
  "browser-intake-datadoghq.eu", "browser-intake-ddog-gov.com", "browser-intake-us2-ddog-gov.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `datadoghq.com` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `*.datadoghq.com`, subject organisation **Datadog, Inc.** (issuer DigiCert Inc) |
| `datadoghq.eu` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `*.datadoghq.eu`, subject organisation **Datadog, Inc.** (issuer DigiCert Inc) |
| `ddog-gov.com` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `*.ddog-gov.com`, subject organisation **Datadog, Inc.** (issuer DigiCert Inc) |
| `browser-intake-datadoghq.com` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `*.browser-intake-datadoghq.com`, subject organisation **Datadog, Inc.** (issuer DigiCert Inc) |
| `browser-intake-us3-datadoghq.com` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `*.browser-intake-us3-datadoghq.com`, subject organisation **Datadog, Inc.** (issuer DigiCert Inc) |
| `browser-intake-us5-datadoghq.com` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `*.browser-intake-us5-datadoghq.com`, subject organisation **Datadog, Inc.** (issuer DigiCert Inc) |
| `browser-intake-ap1-datadoghq.com` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `*.browser-intake-ap1-datadoghq.com`, subject organisation **Datadog, Inc.** (issuer DigiCert Inc) |
| `browser-intake-ap2-datadoghq.com` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `*.browser-intake-ap2-datadoghq.com`, subject organisation **Datadog, Inc.** (issuer DigiCert Inc) |
| `browser-intake-uk1-datadoghq.com` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `*.browser-intake-uk1-datadoghq.com`, subject organisation **Datadog, Inc.** (issuer DigiCert Inc) |
| `browser-intake-datadoghq.eu` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `*.browser-intake-datadoghq.eu`, subject organisation **Datadog, Inc.** (issuer DigiCert Inc) |
| `browser-intake-ddog-gov.com` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `*.browser-intake-ddog-gov.com`, subject organisation **Datadog, Inc.** (issuer DigiCert Inc) |
| `browser-intake-us2-ddog-gov.com` | round 4 (2026-11-21); **L** resolves; TLSv1.3, ALPN `h2`, cert `*.browser-intake-us2-ddog-gov.com`, subject organisation **Datadog, Inc.** (issuer DigiCert Inc) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `datadog`: business-systems / management, client-server; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- `datadog-base`: general-internet / internet-utility, browser-based; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- Functions separated by name: `datadog` (Datadog monitoring), `datadog-base` (Datadog tags and shared services embedded in other websites (not Datadog use)).
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
