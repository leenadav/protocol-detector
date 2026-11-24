# ManageEngine Endpoint Central (Cloud)

- Content-pack id today: none (Zoho-hosted names fall under `zoho`: `zoho.com`, `zoho.eu`)
- Proposed: new id `manageengine-endpoint-central` (54 exact names under the `manageengine.*` domains), batch Q
- Status: **READY** (`blocked-urls.md` row 32)
- Sources: [ME] read by Research Lab from the Hermes server (direct network, no sign-in, no challenge bypass), 2026-11-22 (PRO-168); relayed verbatim in `research/relay/pro-168-rows-30-44.md` on `hermes/research-data-pro168` at `f721a8c4fb2b2056ea5bfb2141b1574059f8a933` (PRO-182)

## 1. What it is

Endpoint Central (formerly Desktop Central) is ManageEngine's (Zoho Corporation) unified endpoint management product: patch
deployment, software deployment, configuration and on-demand operations on managed computers. The cloud edition runs in a
ManageEngine data centre per region; agents and distribution servers connect to it.

## 2. Transport and ports

The page gives **no ports**; it lists domains and IP ranges only [ME]. TCP 443 is not stated and is therefore not assumed
here (`UNVERIFIED`).

## 3. Observable evidence

[ME] has one tab per data centre (US, EU, AU, IN, JP, CN, CA, UK, SA, UAE, SG), each listing the domains to allow for roaming
agents, distribution servers and agents behind a distribution server, then the region's IP ranges and "Geo DNS Domains". The
agent names follow the regex `(endpointcentral-agent)(p)?[0-9]{1,2}\.manageengine\.com`, with the page's instruction to list
the names one by one where a regex is not supported. Stated purposes (US tab):

| Name | Purpose as written | Owner |
|---|---|---|
| `desktopcentral.manageengine.<tld>` | "the server's URL. The roaming agent updates the task status to the cloud server" | ManageEngine, dedicated |
| `endpointcentral-agent[p]N.manageengine.<tld>` | agent communication | ManageEngine, dedicated |
| `patchdb.manageengine.com` | "latest patch information along with the download URLs" | ManageEngine |
| `patchdatabase.manageengine.com` | "download dependent patches from the Endpoint Central Server" | ManageEngine |
| `bonitas.zohocorp.com` (and `.eu`) | "upload logs for analysis and troubleshooting" | Zoho, shared |
| `us3-dms.zoho.com`, `us4-dms.zoho.com` (regional `*-dms.zoho.*`) | "on-demand operations" | Zoho, shared |
| `download-accl.zoho.com`, `files-me-accl.zoho.com` | package and file downloads | Zoho, shared |
| `downloads.zohocdn.com` | "download new agent binaries ... during upgrade process" | Zoho CDN, shared |

Exact ManageEngine names per tab (54 in all): US `desktopcentral.manageengine.com` and 15 agent names (`agent0` to
`agent8`, `agent10`, `agentp1`, `agentp2`, `agentp3`, `agentp5`, `agentp18`), plus `patchdb` and `patchdatabase`; EU
`.eu` with 8 agent names; AU `desktopcentral.manageengine.com.au` (no agent names on the tab); IN `.in` with 11; JP `.jp`,
CA `.ca` with 1 each; CN `.cn` with 2 plus `patchdb.manageengine.cn`; UK `.uk` with 2; SA, UAE and SG list only
`endpointcentral-agent0.manageengine.sa`, `.ae` and `.sg` (the UAE domain is `.ae` although the tab says ".uae").

Research Lab notes that a few Geo-DNS lines of one tab fall into the next tab's list in the extracted text (for example
`download-accl.zoho.eu` under AU): those are Zoho names and are not proposed, so the artefact does not affect the delta.

## 4. Encrypted-traffic caveats

The Zoho-hosted names (`*-dms.zoho.*`, `download-accl`, `files-me-accl`, `downloads.zohocdn.com`, `bonitas.zohocorp.*`) are
shared Zoho infrastructure; the page does not say they serve Endpoint Central only, so they stay with `zoho` (where already
covered) or with no application (`zohocdn.com`, `zohocorp.com`). `manageengine.com` itself is also the marketing site and
the home of every other ManageEngine product, so only the exact names are proposed, never the bare suffix. Remote-control
hosts and ports are not on this page.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI `desktopcentral.manageengine.<tld>`, `endpointcentral-agent*` | **N3** | Dedicated; the regex allows names the page does not list (`agent9`, `agentp4`, ...), which stay unmapped |
| `patchdb` / `patchdatabase.manageengine.com` | **N2** | Patch database; other ManageEngine patch products may share it (not stated) |
| Zoho-hosted names | **N1** for this app | Shared Zoho services; not attributed |
| Ports | **U** | None published |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K, M, N, O, P and Q): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `desktopcentral.manageengine.com`, `acme.desktopcentral.manageengine.com`, `desktopcentral.manageengine.com.au` | `manageengine-endpoint-central` |
| P2 | SNI `endpointcentral-agentp18.manageengine.com`, `endpointcentral-agent0.manageengine.sg`, `patchdb.manageengine.cn` | `manageengine-endpoint-central` |
| N1 | SNI `www.manageengine.com`, `endpointcentral-agent99.manageengine.com` (not listed), `xdesktopcentral.manageengine.com` | no application |
| N2 | SNI `us3-dms.zoho.com` | `zoho` (unchanged) |
| N3 | SNI `downloads.zohocdn.com` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O, P and Q as rebuilt 2026-11-24)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xmanageengine.com` | not manageengine-endpoint-central (label boundary) | no application | PASS |
| L- | `desktopcentral.manageengine.com.example.invalid` | not manageengine-endpoint-central (suffix look-alike) | no application | PASS |
| L- | `endpointcentral-agent0.manageengine.com.example.invalid` | not manageengine-endpoint-central (suffix look-alike) | no application | PASS |
| L- | `endpointcentral-agent1.manageengine.com.example.invalid` | not manageengine-endpoint-central (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [ME] ManageEngine Endpoint Central Cloud help, "Domains Required for Agent Communication",
  `https://www.manageengine.com/products/desktop-central/help/cloud/server/domains-required-for-agent-communication.html`
  (the URL in `blocked-urls.md` row 32 redirects here), HTTP 200; no page date shown.

## 8. Catalog delta and recommendation

New id `manageengine-endpoint-central` (business-systems / management, client-server, risk 3, characteristic
`transfers-files`: it deploys software and runs on-demand operations on endpoints), placed before `forticlient`, with the 54
exact names of section 3. Nothing else changes; `zoho` keeps `zoho.com` and `zoho.eu`. Patch:
`research/patches/batch-q-relayed-rows-30-44.patch` (release `2026.13.2`).

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `desktopcentral.manageengine.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent0.manageengine.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent1.manageengine.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent2.manageengine.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent3.manageengine.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent4.manageengine.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agentp1.manageengine.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agentp2.manageengine.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agentp3.manageengine.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agentp5.manageengine.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent5.manageengine.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent6.manageengine.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent7.manageengine.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent8.manageengine.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent10.manageengine.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agentp18.manageengine.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `patchdb.manageengine.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `patchdatabase.manageengine.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `desktopcentral.manageengine.eu` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent0.manageengine.eu` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent1.manageengine.eu` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agentp1.manageengine.eu` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent2.manageengine.eu` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agentp3.manageengine.eu` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agentp7.manageengine.eu` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agentp13.manageengine.eu` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agentp17.manageengine.eu` | not yet verified (added after round 2; not yet queued for a live round) |
| `desktopcentral.manageengine.com.au` | not yet verified (added after round 2; not yet queued for a live round) |
| `desktopcentral.manageengine.in` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent0.manageengine.in` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent1.manageengine.in` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent2.manageengine.in` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent3.manageengine.in` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agentp2.manageengine.in` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agentp7.manageengine.in` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agentp12.manageengine.in` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agentp14.manageengine.in` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agentp15.manageengine.in` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agentp16.manageengine.in` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agentp19.manageengine.in` | not yet verified (added after round 2; not yet queued for a live round) |
| `desktopcentral.manageengine.jp` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent0.manageengine.jp` | not yet verified (added after round 2; not yet queued for a live round) |
| `desktopcentral.manageengine.cn` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent0.manageengine.cn` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agentp7.manageengine.cn` | not yet verified (added after round 2; not yet queued for a live round) |
| `patchdb.manageengine.cn` | not yet verified (added after round 2; not yet queued for a live round) |
| `desktopcentral.manageengine.ca` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent0.manageengine.ca` | not yet verified (added after round 2; not yet queued for a live round) |
| `desktopcentral.manageengine.uk` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent0.manageengine.uk` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agentp9.manageengine.uk` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent0.manageengine.sa` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent0.manageengine.ae` | not yet verified (added after round 2; not yet queued for a live round) |
| `endpointcentral-agent0.manageengine.sg` | not yet verified (added after round 2; not yet queued for a live round) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `manageengine-endpoint-central`: business-systems / management, client-server; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
