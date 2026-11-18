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

## 7. Sources

- [S1] Slack Help Center, "Manage Slack connection issues",
  `https://slack.com/help/articles/360001603387-Manage-Slack-connection-issues`, accessed 2026-11-18.
- [S2] Slack Help Center, "Approve Slack workspaces for your network",
  `https://slack.com/help/articles/360024821873-Approve-Slack-workspaces-for-your-network`, accessed 2026-11-18.

## 8. Catalog delta and recommendation

No change. **Request to Hermes**: the contents of `my.slack.com/help/urls` from a signed-in
workspace member (domain names only) would verify the three remaining domains.
