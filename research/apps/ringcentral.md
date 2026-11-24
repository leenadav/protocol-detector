# RingCentral (RingEX, RingCentral App and Video)

- Content-pack id today: `ringcentral` (`ringcentral.com`)
- Proposed: `ringcentral` extended with 17 names (regional domains, `glip.com`, exact PubNub and S3 hosts), batch Q
- Status: **READY** (`blocked-urls.md` row 33)
- Sources: [RC] read by Research Lab from the Hermes server (direct network, no sign-in, no challenge bypass), 2026-11-22 (PRO-168); relayed verbatim in `research/relay/pro-168-rows-30-44.md` on `hermes/research-data-pro168` at `f721a8c4fb2b2056ea5bfb2141b1574059f8a933` (PRO-182)

## 1. What it is

RingCentral RingEX is a cloud phone, messaging and video service; the RingCentral App (desktop, web, mobile) and RingCentral
Video are its clients. "Glip" is RingCentral's messaging back end.

## 2. Transport and ports

From [RC] (ports written `TCP\443`):

- Web portals and APIs: TCP 443 (Table 3.1.1 and the FQDN rows of 3.2.1 and 3.2.2).
- Signalling to IP supernets: TCP 8083 (desktop and web, SIP/WSS/DTLS); mobile TCP 5091 (SIP/TCP), 5097 (SIP/TLS), 443.
- Media: UDP 20000 to 64999 and UDP 19302 (app); RingCentral Video SRTP UDP 10000 to 19999, TCP 443 when UDP is blocked.
- The supernets (Table 2.1: ten IPv4 ranges) are recorded here and not used by the name catalog.

## 3. Observable evidence

RingCentral-owned names on the page:

| Names | Purpose (as written) | Supernet? |
|---|---|---|
| `www`, `status`, `support`, `accounts`, `service`, `login`, `analytics`, `v`, `media`, `api-meet`, `api`, `api-mucc`, `edr`, `downloads`, `app`, `mvp`, `dl.mvp` `.ringcentral.com` | portals, APIs, Video, updates | mixed |
| `service.ringcentral.co.uk`, `login.ringcentral.co.uk`, `analytics.ringcentral.co.uk` | UK portals | yes / no |
| `service.ringcentral.eu`, `login.ringcentral.eu`, `analytics.ringcentral.eu` | Europe portals | yes / no |
| `analytics.ringcentral.ca` | Canada analytics portal | no |
| `discovery.ringcentral.biz` | "Discovery service API" | yes |
| `*.glip.com` | "Messaging service API" | |
| `ringcentral.pubnubapi.com`, `ringcentral-0.pubnubapi.com` to `ringcentral-9.pubnubapi.com` | "Presence status, call log notifications, voicemail notifications" | |
| `glip-vault-1.s3.amazonaws.com`, `glip-vault-1.s3-accelerate.amazonaws.com` | "Application file upload and download" | |

Third-party and shared names the page also lists (not RingCentral): `*.cloudfront.net`, `mpsnare.iesnare.com` and
`ringcentral.112.2o7.net` (two-factor SDK), `www.filestackapi.com`, Giphy and `i.embed.ly`, `mtalk.google.com`,
`api.push.apple.com`, the help-panel hosts (`*.demdex.net`, `*.coveo.com`, `*.vimeo.com`, `*.akamaized.net`,
`www.youtube.com`, `js-agent.newrelic.com`, `bam.nr-data.net`, `cdn.cookielaw.org`), LaunchDarkly and testRTC.

## 4. Encrypted-traffic caveats

PubNub and S3 are shared platforms: only the exact RingCentral-named hosts are proposed (same rule as `atera.pubnubapi.com`
and the Loom and WeTransfer buckets). `*.cloudfront.net` names no application. Signalling to supernet addresses on 8083,
5091 and 5097 has no SNI the page names; media is UDP and off the observed path in this phase. `js-agent.newrelic.com` and
`bam.nr-data.net` show that New Relic's browser agent loads inside other vendors' apps; see `apps/new-relic.md`.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `ringcentral.com`, `.co.uk`, `.eu`, `.ca`, `.biz` | **N2** | `www`, `support` and `status` are the company site, not product use |
| SNI under `glip.com` | **N3** | Messaging back end |
| Exact PubNub and S3 hosts | **N3** for the name | Name only; the IPs are the shared platform's |
| Supernet IPs, ports 8083/5091/5097 | not used | Outside the name catalog; UDP not observed |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K, M, N, O, P and Q): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `discovery.ringcentral.biz`, `login.ringcentral.eu`, `analytics.ringcentral.ca`, `service.ringcentral.co.uk`, `v.ringcentral.com` | `ringcentral` |
| P2 | SNI `app.glip.com`, `ringcentral-7.pubnubapi.com`, `glip-vault-1.s3-accelerate.amazonaws.com` | `ringcentral` |
| N1 | SNI `ringcentral-10.pubnubapi.com` (not listed), `other.s3.amazonaws.com`, `ringcentral.112.2o7.net` | no application |
| N2 | SNI `atera.pubnubapi.com` | `atera` (unchanged) |
| N3 | SNI `mtalk.google.com` | `google-base` (unchanged) |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O, P and Q as rebuilt 2026-11-24)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xringcentral.com` | not ringcentral (label boundary) | no application | PASS |
| L- | `ringcentral.com.example.invalid` | not ringcentral (suffix look-alike) | no application | PASS |
| L- | `xco.uk` | not ringcentral (label boundary) | no application | PASS |
| L- | `ringcentral.co.uk.example.invalid` | not ringcentral (suffix look-alike) | no application | PASS |
| L- | `xringcentral.eu` | not ringcentral (label boundary) | no application | PASS |
| L- | `ringcentral.eu.example.invalid` | not ringcentral (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [RC] RingCentral Support, "Network requirements for RingEX",
  `https://support.ringcentral.com/gb/en/network-and-system-requirements/network-requirements/network-requirements-ringex.html`,
  HTTP 200; no page date in the extracted text. Tables 2.1, 3.1.1, 3.2.1 and 3.2.2 were copied; 3.2.3 onward (hardphones,
  Rooms, Webinar) were not, and can be asked for.

## 8. Catalog delta and recommendation

Extend `ringcentral` with `ringcentral.co.uk`, `ringcentral.eu`, `ringcentral.ca`, `ringcentral.biz`, `glip.com`,
`ringcentral.pubnubapi.com`, `ringcentral-0.pubnubapi.com` to `ringcentral-9.pubnubapi.com`, `glip-vault-1.s3.amazonaws.com`
and `glip-vault-1.s3-accelerate.amazonaws.com` (17 names). Third-party names are not added. Patch:
`research/patches/batch-q-relayed-rows-30-44.patch`.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `ringcentral.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `ringcentral.co.uk` | not yet verified (added after round 2; not yet queued for a live round) |
| `ringcentral.eu` | not yet verified (added after round 2; not yet queued for a live round) |
| `ringcentral.ca` | not yet verified (added after round 2; not yet queued for a live round) |
| `ringcentral.biz` | not yet verified (added after round 2; not yet queued for a live round) |
| `glip.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `ringcentral.pubnubapi.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `ringcentral-0.pubnubapi.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `ringcentral-1.pubnubapi.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `ringcentral-2.pubnubapi.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `ringcentral-3.pubnubapi.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `ringcentral-4.pubnubapi.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `ringcentral-5.pubnubapi.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `ringcentral-6.pubnubapi.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `ringcentral-7.pubnubapi.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `ringcentral-8.pubnubapi.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `ringcentral-9.pubnubapi.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `glip-vault-1.s3.amazonaws.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `glip-vault-1.s3-accelerate.amazonaws.com` | not yet verified (added after round 2; not yet queued for a live round) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `ringcentral`: collaboration / voip-video, client-server; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
