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

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L and J)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `a.slack-edge.com` | one of `slack` | `slack` | PASS |
| O+ | `b.slack-edge.com` | one of `slack` | `slack` | PASS |
| O+ | `slack.com` | one of `slack` | `slack` | PASS |
| D- | `cdn.cookielaw.org` | not slack (third party) | no application | PASS |
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

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `slack.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `slack.com` (SAN covers name: True) |
| `slack-edge.com` | apex has no address (normal for a suffix entry); suffix **verified** through documented `a.slack-edge.com` (TLS TLSv1.3, cert `slack-edge.com`, cdn,h3) |
| `slack-msgs.com` | **L** resolves; TLSv1.3, ALPN `None`, cert `slack-msgs.com` (SAN covers name: True) |
| `slack-files.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `slack-files.com` (SAN covers name: True) |

## 10. Observed web-client hosts (dependency mapping)

- `https://slack.com/signin`, loaded 2026-11-19 without signing in: HTTP 200, final host `slack.com`.

Pass 1 is a lower bound. The proxy refuses hosts not on the allowlist ("failed" below), so hosts that only scripts from a refused host would contact are missing.

| Host | Requests (refused) | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `a.slack-edge.com` | 24 (24) | app-owned | `slack` | cdn,h3 |  |
| `b.slack-edge.com` | 12 (12) | app-owned | `slack` | cdn |  |
| `cdn.cookielaw.org` | 3 (3) | third party | no application | not checked | OneTrust consent banner |
| `slack.com` | 12 (0) | app-owned | `slack` |  |  |

## 11. Attributes (App-ID model) and re-verify date

- `slack`: collaboration / instant-messaging, browser-based; characteristics `widely-used`, `transfers-files`; **risk 2**: widely used by enterprises; moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `cdn.cookielaw.org`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `slack-edge.com`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
