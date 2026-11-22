# Atera

- Content-pack id today: `atera` (`atera.com`; web fronts apex and `www`)
- Status: **READY**, NAME, batch J (`research/patches/batch-j-relayed-rows-12-18.patch`): three exact vendor-named agent hosts added
- Sources: read by Research Lab from the Hermes server, relayed by Hermes, 2026-11-20 (PRO-29); article updated 2026-11-03 (Zendesk API). Only the Atera Agent section was relayed

## 1. What it is

Remote monitoring and management (RMM) with remote access, for managed service providers and IT teams.

## 2. Transport and ports

443/TCP, plus 8883/TCP and UDP for the agent ("agent overall") [T].

## 3. Observable evidence

[T]: `*.atera.com` (for example `app`, `agent-api`, `agent-api-v2`, `agenthb`, `appcdn`, `ps`, `pubsub`, `files-cus`, `files-weu`, `agentreportingstore`; console and agent communication); IoT channel `a32dl55qcodech-ats.iot.eu-west-1.amazonaws.com` with `*.amazontrust.com`; PubNub channel `ps.pndsn.com`, `pubsub.pubnub.com`, `atera.pubnubapi.com`; agent heartbeat `atera-agent-heartbeat-cus.servicebus.windows.net`, `atera-agent-heartbeat.servicebus.windows.net`; .NET runtime names (Microsoft); blob storage `agentspoliciesprod`, `packagesstore`, `ticketingitemsstoreeu`, `automationtasks` (`.blob.core.windows.net`); Azure observability names; `cacerts.thawte.com`.

## 4. Encrypted-traffic caveats

Proposed: only the exact names that carry Atera's name on shared services (`atera.pubnubapi.com` and the two heartbeat namespaces). Not proposed: the IoT endpoint, an account-specific random name on shared AWS IoT; the generic blob account names, which don't carry Atera's name; PubNub's shared names; Microsoft's .NET and Azure names; and the CA. Port 8883 is MQTT over TLS (IANA `secure-mqtt`): the agent's IoT channel would carry the AWS IoT SNI, not an Atera name. Third-party add-on sections of the page (Acronis, AnyDesk, Bitdefender and others) were not relayed.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `atera.com` | **N3** | Already mapped |
| Exact `atera.pubnubapi.com`, `atera-agent-heartbeat*.servicebus.windows.net` | **N3** (exact) | Agent channels |
| IoT endpoint, blob accounts, PubNub shared names | not mapped | Shared or not vendor-named |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L and J): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `agent-api.atera.com` | `atera` |
| P2 | SNI `atera.pubnubapi.com`, `atera-agent-heartbeat-cus.servicebus.windows.net` | `atera` (today unmapped) |
| N1 | SNI `ps.pndsn.com`, `pubsub.pubnub.com`, `x.servicebus.windows.net`, `agentspoliciesprod.blob.core.windows.net` | not `atera` |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J and K as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xatera.com` | not atera (label boundary) | no application | PASS |
| L- | `atera.com.example.invalid` | not atera (suffix look-alike) | no application | PASS |
| L- | `xpubnubapi.com` | not atera (label boundary) | no application | PASS |
| L- | `atera.pubnubapi.com.example.invalid` | not atera (suffix look-alike) | no application | PASS |
| L- | `xwindows.net` | not atera (label boundary) | no application | PASS |
| L- | `atera-agent-heartbeat.servicebus.windows.net.example.invalid` | not atera (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [T] Atera Support, "Firewall settings for Atera's integrations", `https://support.atera.com/hc/en-us/articles/360015461139-Firewall-settings-for-Atera-s-integrations`, read by Research Lab from the Hermes server, relayed by Hermes, 2026-11-20 (PRO-29).

## 8. Catalog delta and recommendation

```python
("atera", ..., ("atera.com", "atera.pubnubapi.com", "atera-agent-heartbeat.servicebus.windows.net",
 "atera-agent-heartbeat-cus.servicebus.windows.net"), ("atera.com", "www.atera.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `atera.com` | not yet verified (added after round 2; in `live-hosts-r2.txt` for the next run) |
| `atera.pubnubapi.com` | not yet verified (added after round 2; in `live-hosts-r2.txt` for the next run) |
| `atera-agent-heartbeat.servicebus.windows.net` | not yet verified (added after round 2; in `live-hosts-r2.txt` for the next run) |
| `atera-agent-heartbeat-cus.servicebus.windows.net` | not yet verified (added after round 2; in `live-hosts-r2.txt` for the next run) |

## 10. Observed web-client hosts (dependency mapping)

- `https://app.atera.com/`: **not yet observed** (added after pass 2; listed in `web-urls.txt` for the next server run).

## 11. Attributes (App-ID model) and re-verify date

- `atera`: networking / remote-access, client-server; characteristics `tunnels-other-applications`, `prone-to-misuse`, `used-by-malware`; **risk 4**: carries other traffic or remote control; commonly misused (unsanctioned remote access, data exfiltration); seen in malware campaigns.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
