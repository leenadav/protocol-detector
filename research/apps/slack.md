# Slack

- Content-pack id today: `slack` (`slack.com`, `slack-edge.com`, `slack-msgs.com`, `slack-files.com`)
- Status: **PARTIAL**, NAME. `slack.com` is verified. The other three domains have no public primary source: Slack's URL list is shown only to signed-in workspace members
- Sources accessed: 2026-11-18

## 1. What it is

Team messaging (Salesforce). Its shadow-IT concern is personal or external workspaces, not the
application itself.

## 2. Transport and ports

"Slack uses WebSockets over port 443" [S1].

## 3. Observable evidence

- Slack tells admins to "Visit https://my.slack.com/help/urls and add all specified URLs to your
  allowlist", per workspace or org [S1]. That page needs a sign-in; this lane cannot read it.
- Named publicly: `wss-primary.slack.com`, `wss-backup.slack.com`, `wss-mobile.slack.com`, to exempt
  from SSL decryption if the proxy lacks WebSocket support [S1].
- Workspace restriction uses proxy-inserted headers `X-Slack-Allowed-Workspaces-Requester` and
  `X-Slack-Allowed-Workspaces` on "traffic to slack.com", which requires "SSL interception" [S2].
  That is outside the visibility phase. Workspace ids are identifiers and must never be logged as identity.

## 4. Encrypted-traffic caveats

Which workspace a user is in is not visible in SNI: workspace names appear as subdomains of
`slack.com` in browser use. That is `UNVERIFIED` from the sources read, and a tenant label would
not be logged anyway.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `slack.com` | **N3** Slack | |
| `slack-edge.com`, `slack-msgs.com`, `slack-files.com` (pack) | **U** | No public primary source |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `wss-primary.slack.com`, ALPN `http/1.1` | `slack` (checked in scratch) |
| N1 | SNI `slack.com.example.invalid` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M and N as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `a.slack-edge.com` | one of `slack` | `slack` | PASS |
| O+ | `campaign.slackhq.com` | one of `slack` | no application | GAP (unmapped) |
| O+ | `slack.com` | one of `slack` | `slack` | PASS |
| D- | `12632256.fls.doubleclick.net` | not slack (third party) | `google-ads` | PASS |
| D- | `ad.doubleclick.net` | not slack (third party) | `google-ads` | PASS |
| D- | `adservice.google.com` | not slack (shared vendor infra) | `google-base` | PASS |
| D- | `alb.reddit.com` | not slack (shared vendor infra) | `reddit-base` | PASS |
| D- | `analytics.google.com` | not slack (shared vendor infra) | `google-base` | PASS |
| D- | `api.company-target.com` | not slack (third party (unclassified)) | no application | PASS |
| D- | `c.contentsquare.net` | not slack (third party (unclassified)) | no application | PASS |
| D- | `cdn.cookielaw.org` | not slack (third party) | no application | PASS |
| D- | `cdn.schemaapp.com` | not slack (third party (unclassified)) | no application | PASS |
| D- | `csxd.contentsquare.net` | not slack (third party (unclassified)) | no application | PASS |
| D- | `data.schemaapp.com` | not slack (third party (unclassified)) | no application | PASS |
| D- | `dc.ads.linkedin.com` | not slack (shared vendor infra) | `linkedin-base` | PASS |
| D- | `dsum-sec.casalemedia.com` | not slack (third party (unclassified)) | no application | PASS |
| D- | `geolocation.onetrust.com` | not slack (third party) | no application | PASS |
| D- | `googleads.g.doubleclick.net` | not slack (third party) | `google-ads` | PASS |
| D- | `ibc-flow.techtarget.com` | not slack (third party (unclassified)) | no application | PASS |
| D- | `id.rlcdn.com` | not slack (third party (unclassified)) | no application | PASS |
| D- | `image2.pubmatic.com` | not slack (third party) | `pubmatic` | PASS |
| D- | `k-aus1.contentsquare.net` | not slack (third party (unclassified)) | no application | PASS |
| D- | `partners.tremorhub.com` | not slack (third party (unclassified)) | no application | PASS |
| D- | `pi.pardot.com` | not slack (third party (unclassified)) | no application | PASS |
| D- | `pixel-config.reddit.com` | not slack (shared vendor infra) | `reddit-base` | PASS |
| D- | `pixel.rubiconproject.com` | not slack (third party) | `magnite` | PASS |
| D- | `px.ads.linkedin.com` | not slack (shared vendor infra) | `linkedin-base` | PASS |
| D- | `px4.ads.linkedin.com` | not slack (shared vendor infra) | `linkedin-base` | PASS |
| D- | `s.company-target.com` | not slack (third party (unclassified)) | no application | PASS |
| D- | `segments.company-target.com` | not slack (third party (unclassified)) | no application | PASS |
| D- | `snap.licdn.com` | not slack (shared vendor infra) | `linkedin-base` | PASS |
| D- | `srm.bf.contentsquare.net` | not slack (third party (unclassified)) | no application | PASS |
| D- | `stats.g.doubleclick.net` | not slack (third party) | `google-ads` | PASS |
| D- | `t.contentsquare.net` | not slack (third party (unclassified)) | no application | PASS |
| D- | `tag-logger.demandbase.com` | not slack (third party (unclassified)) | no application | PASS |
| D- | `tag.demandbase.com` | not slack (third party (unclassified)) | no application | PASS |
| D- | `trk.techtarget.com` | not slack (third party (unclassified)) | no application | PASS |
| D- | `www.google.co.il` | not slack (third party (unclassified)) | no application | PASS |
| D- | `www.google.com` | not slack (shared vendor infra) | `google-base` | PASS |
| D- | `www.googletagmanager.com` | not slack (third party) | `google-analytics` | PASS |
| D- | `www.linkedin.com` | not slack (third party) | `linkedin` | PASS |
| D- | `www.redditstatic.com` | not slack (shared vendor infra) | `reddit-base` | PASS |
| L- | `xslack.com` | not slack (label boundary) | no application | PASS |
| L- | `slack.com.example.invalid` | not slack (suffix look-alike) | no application | PASS |
| L- | `xslack-edge.com` | not slack (label boundary) | no application | PASS |
| L- | `slack-edge.com.example.invalid` | not slack (suffix look-alike) | no application | PASS |
| L- | `xslack-msgs.com` | not slack (label boundary) | no application | PASS |
| L- | `slack-msgs.com.example.invalid` | not slack (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Slack Help Center, "Manage Slack connection issues",
  `https://slack.com/help/articles/360001603387-Manage-Slack-connection-issues`, accessed 2026-11-18.
- [S2] Slack Help Center, "Approve Slack workspaces for your network",
  `https://slack.com/help/articles/360024821873-Approve-Slack-workspaces-for-your-network`, accessed 2026-11-18.

## 8. Catalog delta and recommendation

No change. **Request to Hermes**: the contents of `my.slack.com/help/urls` from a signed-in
workspace member (domain names only) would verify the three remaining domains.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 5 of 2026-11-21 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `slack.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `slack.com`, no subject organisation (domain-validated) (issuer Let's Encrypt) |
| `slack-edge.com` | apex has no address (normal for a suffix entry); suffix **verified** through documented `a.slack-edge.com` (round 2, cdn,h3) |
| `slack-msgs.com` | **L** resolves; TLSv1.3, ALPN `None`, cert `slack-msgs.com`, no subject organisation (domain-validated) (issuer Let's Encrypt) |
| `slack-files.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `slack-files.com`, no subject organisation (domain-validated) (issuer Let's Encrypt) |

## 10. Observed web-client hosts (dependency mapping)

- `https://slack.com/signin`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `slack.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `12632256.fls.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `a.slack-edge.com` | seen | app-owned | `slack` | cdn,h3 |  |
| `ad.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `adservice.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `alb.reddit.com` | seen | shared vendor infra | `reddit-base` | not checked |  |
| `analytics.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `api.company-target.com` | seen | third party (unclassified) | no application | not checked |  |
| `c.contentsquare.net` | seen | third party (unclassified) | no application | not checked |  |
| `campaign.slackhq.com` | seen | app-owned (unmapped) | no application | not checked | Slack marketing; NOT mapped: round 3 certificate is domain-validated (no organisation, issuer Let's Encrypt; CNAME to pardot.com) |
| `cdn.cookielaw.org` | seen | third party | no application | not checked | OneTrust consent banner |
| `cdn.schemaapp.com` | seen | third party (unclassified) | no application | not checked |  |
| `csxd.contentsquare.net` | seen | third party (unclassified) | no application | not checked |  |
| `data.schemaapp.com` | seen | third party (unclassified) | no application | not checked |  |
| `dc.ads.linkedin.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `dsum-sec.casalemedia.com` | seen | third party (unclassified) | no application | not checked |  |
| `geolocation.onetrust.com` | seen | third party | no application | not checked | OneTrust consent geolocation |
| `googleads.g.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `ibc-flow.techtarget.com` | seen (some failed) | third party (unclassified) | no application | not checked |  |
| `id.rlcdn.com` | seen | third party (unclassified) | no application | not checked |  |
| `image2.pubmatic.com` | seen | third party | `pubmatic` | not checked |  |
| `k-aus1.contentsquare.net` | seen | third party (unclassified) | no application | not checked |  |
| `partners.tremorhub.com` | seen | third party (unclassified) | no application | not checked |  |
| `pi.pardot.com` | seen | third party (unclassified) | no application | not checked |  |
| `pixel-config.reddit.com` | seen | shared vendor infra | `reddit-base` | not checked |  |
| `pixel.rubiconproject.com` | seen | third party | `magnite` | not checked |  |
| `px.ads.linkedin.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `px4.ads.linkedin.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `s.company-target.com` | seen | third party (unclassified) | no application | not checked |  |
| `segments.company-target.com` | seen | third party (unclassified) | no application | not checked |  |
| `slack.com` | seen | app-owned | `slack` |  |  |
| `snap.licdn.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `srm.bf.contentsquare.net` | seen | third party (unclassified) | no application | not checked |  |
| `stats.g.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `t.contentsquare.net` | seen | third party (unclassified) | no application | not checked |  |
| `tag-logger.demandbase.com` | seen | third party (unclassified) | no application | not checked |  |
| `tag.demandbase.com` | seen | third party (unclassified) | no application | not checked |  |
| `trk.techtarget.com` | seen | third party (unclassified) | no application | not checked |  |
| `www.google.co.il` | seen | third party (unclassified) | no application | not checked |  |
| `www.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `www.googletagmanager.com` | seen | third party | `google-analytics` | not checked |  |
| `www.linkedin.com` | seen | third party | `linkedin` | not checked |  |
| `www.redditstatic.com` | seen | shared vendor infra | `reddit-base` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `slack`: collaboration / instant-messaging, browser-based; characteristics `widely-used`, `transfers-files`; **risk 2**: widely used by enterprises; moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `api.company-target.com`, `c.contentsquare.net`, `cdn.cookielaw.org`, `cdn.schemaapp.com`, `csxd.contentsquare.net`, `data.schemaapp.com`, `dsum-sec.casalemedia.com`, `geolocation.onetrust.com`, `google-ads`, `google-analytics`, `google-base`, `ibc-flow.techtarget.com`, `id.rlcdn.com`, `k-aus1.contentsquare.net`, `linkedin`, `linkedin-base`, `magnite`, `partners.tremorhub.com`, `pi.pardot.com`, `pubmatic`, `reddit-base`, `s.company-target.com`, `segments.company-target.com`, `srm.bf.contentsquare.net`, `t.contentsquare.net`, `tag-logger.demandbase.com`, `tag.demandbase.com`, `trk.techtarget.com`, `www.google.co.il`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `slack-edge.com`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
