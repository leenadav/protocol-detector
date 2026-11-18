# Anthropic Claude (claude.ai apps, Claude API, Claude Code)

- Content-pack id today: `anthropic-claude` (`claude.ai`, `anthropic.com`, `claude.com`); no separate API id
- Status: **READY** for host names and IPv4 ranges
- Sources accessed: 2026-11-18

## 1. What it is

Anthropic's generative-AI assistant (claude.ai web, desktop and mobile apps), its developer API
("The Claude API is a RESTful API at https://api.anthropic.com" [S2]), and Claude Code, a coding
agent that uses the same API and accounts [S3]. Chat and programmatic API use are different risk
questions for an operator, as with OpenAI (`openai-chatgpt` vs `openai-platform`).

## 2. Transport and ports

HTTPS on TCP 443. Fixed IPv4 ranges, as published [S1]:

| Direction | Ranges | Meaning (as published) |
|---|---|---|
| Inbound to Anthropic | `160.79.104.0/23`, `153.61.224.0/22` | "IP addresses where Anthropic services receive incoming connections" |
| Outbound from Anthropic | `160.79.104.0/21`, `153.61.208.0/20` | "stable IP addresses that Anthropic uses for outbound requests (for example, when making MCP tool calls to external servers)" |
| Phased out | `34.162.46.92/32`, `34.162.102.82/32`, `34.162.136.91/32`, `34.162.142.92/32`, `34.162.183.95/32` | "no longer in use by Anthropic" |

Anthropic says these addresses are for "secure access to the Claude API and Claude Console" and
"will not change without notice" [S1]. Claude Platform on AWS is the exception: its inbound
endpoint `aws-external-anthropic.{region}.api.aws` "resolves to AWS IP ranges" [S1].

## 3. Observable evidence

Host names published by Anthropic [S2, S3] (Claude Code's "Network access requirements" table):

| Host | Purpose (as published) |
|---|---|
| `api.anthropic.com` | "Claude API requests" (also Claude Code feature flags and telemetry) |
| `claude.ai` | "claude.ai account authentication" |
| `claude.com` | sign-in page that "redirects to claude.ai"; documentation lookups |
| `platform.claude.com` | "Anthropic Console account authentication", OAuth token exchange |
| `sso.claude.com` | browser sign-in for organizations using SSO |
| `mcp-proxy.anthropic.com` | "MCP connectors from claude.ai" |
| `downloads.claude.ai` | plugin downloads, native installer and auto-updater |
| `bridge.claudeusercontent.com` | "Claude in Chrome extension WebSocket bridge" |
| `*.frame.claudeusercontent.com` | "Artifact content reads" |
| `code.claude.com` | Claude Code documentation lookups |

Third-party hosts in the same table (`storage.googleapis.com`, `registry.npmjs.org`, `github.com`,
`raw.githubusercontent.com`, two Datadog intake hosts, `formulae.brew.sh`) belong to other operators.
They are not Anthropic evidence.

Request structure: the API uses the `x-api-key` or `Authorization` headers and the
`anthropic-version` header [S2]. These are inside TLS, so the detector never sees them. If
decryption is ever used, they are credentials and must never be logged (AGENTS.md).

ALPN: nothing published by Anthropic. `UNVERIFIED`.

## 4. Encrypted-traffic caveats

- SNI only on the CONNECT path. Claude Code sends its API requests to `api.anthropic.com` [S3], also
  when it is signed in through a claude.ai account (the same table lists `claude.ai` for that
  sign-in). So `api.anthropic.com` means "Claude API, including Claude Code", not "developer
  integration" alone. `UNVERIFIED`: which hosts the claude.ai web and mobile chat apps use beyond
  `claude.ai`; no primary page read here lists them.
- `anthropic.com` (apex) and `claude.com` also serve Anthropic's public website and docs. In the
  current pack they name the application `anthropic-claude`, so visiting the website or docs counts
  as using the product.
- Claude Platform on AWS reaches `aws-external-anthropic.{region}.api.aws`, which resolves to AWS IP
  ranges [S1]. S3 refers to Claude Code sessions on Amazon Bedrock, Google Cloud's Agent Platform and Microsoft Foundry.
  Those connections go to the cloud provider and are not visible as Anthropic.
- IPv4 ranges: the detector is IPv4-only and the ranges are IPv4 [S1]. A destination address in the
  inbound ranges, together with an Anthropic SNI, is two consistent assertions. Neither alone
  authenticates.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI `api.anthropic.com` | **N3** Claude API | Includes Claude Code. Not "chat" |
| SNI `claude.ai` | **N3** Claude apps | Also downloads (`downloads.claude.ai`) |
| SNI `platform.claude.com`, `sso.claude.com` | **N2** account/console | Sign-in, not use |
| SNI `*.claudeusercontent.com` | **N3** | Artifacts and the browser-extension bridge |
| SNI `anthropic.com` apex/`www`, `claude.com` | **N1** | Marketing and docs. Should be a web front, not use |
| Destination in `160.79.104.0/23` or `153.61.224.0/22` | **N2** corroboration | Supporting signal only. Never names an app alone (v0.65 contract) |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `api.anthropic.com`, ALPN `h2` | Claude API (today `anthropic-claude`) |
| P2 | SNI `claude.ai`, ALPN `h2`, `http/1.1` | `anthropic-claude` |
| P3 | SNI `bridge.claudeusercontent.com` | `anthropic-claude` (today unmapped) |
| N1 | SNI `www.anthropic.com` | web front, no use (proposed) |
| N2 | SNI `claude.ai.example.invalid`, `notclaude.ai` | no application |
| N3 | `ech_outer()` with outer SNI `claude.ai` | no application |

## 7. Sources

- [S1] Claude Platform Docs, "IP addresses", `https://platform.claude.com/docs/en/api/ip-addresses`
  (redirected from `https://docs.anthropic.com/en/api/ip-addresses`), accessed 2026-11-18.
- [S2] Claude Platform Docs, "API overview", `https://platform.claude.com/docs/en/api/overview`,
  accessed 2026-11-18.
- [S3] Claude Code Docs, "Enterprise network configuration", section "Network access requirements",
  `https://code.claude.com/docs/en/network-config`, accessed 2026-11-18.

## 8. Catalog delta and recommendation

1. Split the API from the apps, as the pack already does for OpenAI: `api.anthropic.com` →
   `anthropic-api` (new id: generative-ai). This changes reported application names, so it is an
   Engine-lane decision.
2. Add `claudeusercontent.com` → `anthropic-claude`, and `mcp-proxy.anthropic.com` →
   `anthropic-claude` (a connector proxy, not the API).
3. Make `anthropic.com` (apex and `www`) and `claude.com` web fronts ("provider affiliation only", as `openai.com` already is in PROTOCOLS.md), so
   that visiting the marketing site is not reported as product use.
4. Optional corroboration: record the published inbound ranges in content with their source. They are
   evidence, never identification.
