# Intercom (Inbox and Messenger)

- Content-pack id today: `intercom` (`intercom.io`, `intercom.com`, `intercomcdn.com`)
- Proposed: `intercom` extended with 19 Intercom-owned domains from its CSP list, batch Q
- Status: **READY** (`blocked-urls.md` row 42)
- Sources: [IC] read by Research Lab from the Hermes server (direct network, no sign-in, no challenge bypass), 2026-11-22 (PRO-168); relayed verbatim in `research/relay/pro-168-rows-30-44.md` on `hermes/research-data-pro168` at `f721a8c4fb2b2056ea5bfb2141b1574059f8a933` (PRO-182)

## 1. What it is

Intercom is a customer-messaging service: support agents use the Inbox (`app.intercom.com`), and the Messenger widget is
embedded in customers' websites and apps. A page that embeds the Messenger contacts Intercom on behalf of its visitors; the
catalog already names that traffic `intercom` (for example `widget.intercom.io` in `apps/miro.md`).

## 2. Transport and ports

No ports stated; every source is `https://` or `wss://` (TCP 443 implied by the scheme) [IC].

## 3. Observable evidence

[IC] is a Content Security Policy list, not a firewall table, and notes that the regional CDN domains apply only to the
workspace's hosting region. Its firewall section: "Many of the above domains will also need to be allowed in your firewall
settings ... To access the Intercom Inbox when a firewall is active, one of the following domains will need to be
allowlisted ...: app.intercom.com (US region), app.eu.intercom.com (EU region), app.au.intercom.com (AU region)".

Intercom-owned domains in the directives, by registrable domain:

| Domain | Hosts on the page |
|---|---|
| `intercom.io`, `intercom.com`, `intercomcdn.com` (mapped) | `app`, `widget`, `via`, `api`, `api.eu`, `api.au`, `api-iam`, `api-ping`, `nexus-*-websocket`, `messenger-apps`; `js`, `fonts`, `uploads`, `downloads`, `gifs`, `video-messages` |
| `intercomcdn.eu` | `uploads`, `downloads` |
| `intercom-messenger.com` | `*` (https and wss) |
| `intercomusercontent.com` | `uploads` |
| `intercom-sheets.com` | apex |
| `intercom-reporting.com` | `www` |
| `intercom.help` | apex (form-action) |
| `intercomassets.com`, `intercomassets.eu` | `static`, `static.au` |
| `intercom-attachments-1.com` to `intercom-attachments-9.com`, `intercom-attachments.eu`, `intercom-attachments.com` | `*`, and `*.au` for the last |

Third-party hosts on the page: `www.youtube.com`, `player.vimeo.com`, `fast.wistia.net` (video embeds).

## 4. Encrypted-traffic caveats

The Messenger is embedded: an `intercom` verdict means "Intercom traffic", not "this user opened Intercom". That is the
existing meaning of the id and is unchanged. `intercom.help` hosts customers' help centres; a help centre on a customer's own
domain is not identifiable by name. The `wss://` Messenger connections are inside TLS; only their SNI is visible.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under the 22 Intercom domains | **N3** | Registrable domains are Intercom-branded; the page lists hosts, the catalog uses their registrable domains |
| Embedded Messenger on another site | **N2** | Names Intercom, not the site |
| Video embeds | not attributed | Third party |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K, M, N, O, P and Q): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `api-iam.eu.intercom.io`, `x.intercom-messenger.com`, `uploads.intercomusercontent.com`, `acme.intercom.help` | `intercom` |
| P2 | SNI `x.au.intercom-attachments.com`, `x.intercom-attachments-9.com`, `static.au.intercomassets.com` | `intercom` |
| N1 | SNI `x.intercom-attachments-10.com` (not listed), `fast.wistia.net` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O, P and Q as rebuilt 2026-11-24)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xintercom.io` | not intercom (label boundary) | no application | PASS |
| L- | `intercom.io.example.invalid` | not intercom (suffix look-alike) | no application | PASS |
| L- | `xintercom.com` | not intercom (label boundary) | no application | PASS |
| L- | `intercom.com.example.invalid` | not intercom (suffix look-alike) | no application | PASS |
| L- | `xintercomcdn.com` | not intercom (label boundary) | no application | PASS |
| L- | `intercomcdn.com.example.invalid` | not intercom (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [IC] Intercom Help, "Using Intercom with Content Security Policy",
  `https://www.intercom.com/help/en/articles/3894-using-intercom-with-content-security-policy` (article 3894 moved here from
  the URL in row 42), HTTP 200; `dateModified` 2026-05-13T09:00:36Z.

## 8. Catalog delta and recommendation

Extend `intercom` with `intercomcdn.eu`, `intercom-messenger.com`, `intercomusercontent.com`, `intercom-sheets.com`,
`intercom-reporting.com`, `intercom.help`, `intercomassets.com`, `intercomassets.eu`, `intercom-attachments-1.com` to
`intercom-attachments-9.com`, `intercom-attachments.eu` and `intercom-attachments.com` (19 domains). Patch:
`research/patches/batch-q-relayed-rows-30-44.patch`.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `intercom.io` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercom.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercomcdn.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercomcdn.eu` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercom-messenger.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercomusercontent.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercom-sheets.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercom-reporting.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercom.help` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercomassets.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercomassets.eu` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercom-attachments-1.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercom-attachments-2.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercom-attachments-3.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercom-attachments-4.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercom-attachments-5.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercom-attachments-6.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercom-attachments-7.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercom-attachments-8.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercom-attachments-9.com` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercom-attachments.eu` | not yet verified (added after round 2; not yet queued for a live round) |
| `intercom-attachments.com` | not yet verified (added after round 2; not yet queued for a live round) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `intercom`: collaboration / instant-messaging, client-server; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
