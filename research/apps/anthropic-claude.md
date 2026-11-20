# Anthropic Claude (claude.ai apps, Claude API, Claude Code)

- Content-pack id today: `anthropic-claude` (`claude.ai`, `anthropic.com`, `claude.com`); no separate API id
- Decided (Lee via Hermes, 2026-11-18): `api.anthropic.com` gets its own API id, `anthropic-api`, consistent with `openai-platform`
- Status: **READY**, NAME-BASED, batch A (`research/patches/batch-a-name-based.patch`). The `anthropic.com` web front is PARTIAL
- Implemented: content release 2026.11.3 on `claude/go-migration` (`baa07b9`); verified in the pack at `47b2743`, 2026-11-18
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
- `claude.com` (apex) is Anthropic's product page with sign-in. Fetched directly 2026-11-18, it had the title
  "Claude by Anthropic | The AI for problem solvers" and showed plans, downloads and "Continue with SSO" [S4].
  So the apex is provider web presence, not proof of use. `anthropic.com` (apex) could not be fetched from
  this session (host not allowed). Whether it is marketing only is `UNVERIFIED`.
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
| SNI `claude.com` apex, `code.claude.com` | **N1** | Product page and sign-in [S4]; documentation [S3]. Web fronts in batch A |
| SNI `anthropic.com` apex/`www` | **U** | Not fetched; still a service domain in the pack |
| Destination in `160.79.104.0/23` or `153.61.224.0/22` | **N2** corroboration | Supporting signal only. Never names an app alone (v0.65 contract) |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `api.anthropic.com`, ALPN `h2` | `anthropic-api` (today `anthropic-claude`) |
| P1b | SNI `platform.claude.com` | `anthropic-api` (Console, the counterpart of `platform.openai.com`) |
| P1c | SNI `sso.claude.com` | `anthropic-claude` (service under `claude.com`) |
| P2 | SNI `claude.ai`, ALPN `h2`, `http/1.1` | `anthropic-claude` |
| P3 | SNI `bridge.claudeusercontent.com` | `anthropic-claude` (today unmapped) |
| N1 | SNI `claude.com`, `code.claude.com` | web front of `anthropic-claude` (provider affiliation, no use asserted) |
| N2 | SNI `claude.ai.example.invalid`, `notclaude.ai` | no application |
| N3 | `ech_outer()` with outer SNI `claude.ai` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J and K)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `claude.ai` | one of `anthropic-claude`, `anthropic-api` | `anthropic-claude` | PASS |
| O+ | `platform.claude.com` | one of `anthropic-claude`, `anthropic-api` | `anthropic-api` | PASS |
| O+ | `s-cdn.anthropic.com` | one of `anthropic-claude`, `anthropic-api` | `anthropic-claude` | PASS |
| D- | `15e17cac5f6a.w.hcaptcha.com` | not anthropic-claude/anthropic-api (third party (unclassified)) | no application | PASS |
| D- | `251360e3903c.w.hcaptcha.com` | not anthropic-claude/anthropic-api (third party (unclassified)) | no application | PASS |
| D- | `655f30477866.w.hcaptcha.com` | not anthropic-claude/anthropic-api (third party (unclassified)) | no application | PASS |
| D- | `accounts.google.com` | not anthropic-claude/anthropic-api (shared vendor infra) | `google-accounts` | PASS |
| D- | `api.hcaptcha.com` | not anthropic-claude/anthropic-api (third party (unclassified)) | no application | PASS |
| D- | `browser-intake-us5-datadoghq.com` | not anthropic-claude/anthropic-api (third party) | no application | PASS |
| D- | `challenges.cloudflare.com` | not anthropic-claude/anthropic-api (third party) | no application | PASS |
| D- | `e9ec84599f3b.w.hcaptcha.com` | not anthropic-claude/anthropic-api (third party (unclassified)) | no application | PASS |
| D- | `hagen.challenges.cloudflare.com` | not anthropic-claude/anthropic-api (third party (unclassified)) | no application | PASS |
| D- | `js.hcaptcha.com` | not anthropic-claude/anthropic-api (third party) | no application | PASS |
| D- | `newassets.hcaptcha.com` | not anthropic-claude/anthropic-api (third party (unclassified)) | no application | PASS |
| L- | `xclaude.ai` | not anthropic-claude/anthropic-api (label boundary) | no application | PASS |
| L- | `claude.ai.example.invalid` | not anthropic-claude/anthropic-api (suffix look-alike) | no application | PASS |
| L- | `xanthropic.com` | not anthropic-claude/anthropic-api (label boundary) | no application | PASS |
| L- | `anthropic.com.example.invalid` | not anthropic-claude/anthropic-api (suffix look-alike) | no application | PASS |
| L- | `xclaude.com` | not anthropic-claude/anthropic-api (label boundary) | no application | PASS |
| L- | `claude.com.example.invalid` | not anthropic-claude/anthropic-api (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Claude Platform Docs, "IP addresses", `https://platform.claude.com/docs/en/api/ip-addresses`
  (redirected from `https://docs.anthropic.com/en/api/ip-addresses`), accessed 2026-11-18.
- [S2] Claude Platform Docs, "API overview", `https://platform.claude.com/docs/en/api/overview`,
  accessed 2026-11-18.
- [S3] Claude Code Docs, "Enterprise network configuration", section "Network access requirements",
  `https://code.claude.com/docs/en/network-config`, accessed 2026-11-18.
- [S4] `https://claude.com/`, rendered 2026-11-18 (page title and visible sign-in and plan content).

## 8. Catalog delta and recommendation

Decided and in batch A (`research/patches/batch-a-name-based.patch`, base `claude/go-migration` `6b280a6`):

```python
("anthropic-claude", "business-systems", "generative-ai", "browser-based", 3, "Anthropic Claude",
 ("transfers-files",), ("claude.ai", "anthropic.com", "claude.com", "claudeusercontent.com"), ("claude.com", "code.claude.com")),
("anthropic-api", "business-systems", "generative-ai", "client-server", 3, "Anthropic Claude developer platform and API",
 ("transfers-files",), ("api.anthropic.com", "platform.claude.com")),
```

- `platform.claude.com` goes with the API, as `platform.openai.com` does in `openai-platform` (consistent with
  the decision). It is the Console and also the OAuth host for claude.ai sign-in [S3]. That is a known
  imprecision: a claude.ai sign-in token exchange is reported as `anthropic-api`.
- `mcp-proxy.anthropic.com` needs no entry: it falls under `anthropic.com`, which is `anthropic-claude`.
- Not in batch A (PARTIAL): making `anthropic.com` and `www.anthropic.com` web fronts. That needs a read
  of `anthropic.com`, whose host is not allowed in this session.
- Optional later (not proposed): the published inbound IPv4 ranges as corroborating content.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `claude.ai` | **L** resolves; TLSv1.3, ALPN `h2`, cert `claude.ai` (SAN covers name: True); HTTPS record offers `h3` (QUIC path) |
| `anthropic.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `anthropic.com` (SAN covers name: True); HTTPS record offers `h3` (QUIC path) |
| `claude.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `claude.com` (SAN covers name: True); HTTPS record offers `h3` (QUIC path) |
| `claudeusercontent.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `claudeusercontent.com` (SAN covers name: True); HTTPS record offers `h3` (QUIC path) |
| `api.anthropic.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `api.anthropic.com` (SAN covers name: True) |
| `platform.claude.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `platform.claude.com` (SAN covers name: True); HTTPS record offers `h3` (QUIC path) |

## 10. Observed web-client hosts (dependency mapping)

- `https://claude.ai/login`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP None (page.goto: Timeout 45000ms exceeded.), final host `claude.ai`.
- `https://platform.claude.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `platform.claude.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `15e17cac5f6a.w.hcaptcha.com` | seen (some failed) | third party (unclassified) | no application | not checked |  |
| `251360e3903c.w.hcaptcha.com` | seen (some failed) | third party (unclassified) | no application | not checked |  |
| `655f30477866.w.hcaptcha.com` | seen | third party (unclassified) | no application | not checked |  |
| `accounts.google.com` | seen | shared vendor infra | `google-accounts` |  |  |
| `api.hcaptcha.com` | seen | third party (unclassified) | no application | not checked |  |
| `browser-intake-us5-datadoghq.com` | seen | third party | no application | not checked | Datadog browser telemetry |
| `challenges.cloudflare.com` | seen | third party | no application | not checked | Cloudflare Turnstile bot check |
| `claude.ai` | seen | app-owned | `anthropic-claude` | h3 |  |
| `e9ec84599f3b.w.hcaptcha.com` | seen (some failed) | third party (unclassified) | no application | not checked |  |
| `hagen.challenges.cloudflare.com` | seen | third party (unclassified) | no application | not checked |  |
| `js.hcaptcha.com` | seen | third party | no application | not checked | hCaptcha |
| `newassets.hcaptcha.com` | seen | third party (unclassified) | no application | not checked |  |
| `platform.claude.com` | seen | app-owned | `anthropic-api` | h3 |  |
| `s-cdn.anthropic.com` | seen | app-owned | `anthropic-claude` |  |  |

## 11. Attributes (App-ID model) and re-verify date

- `anthropic-claude`: business-systems / generative-ai, browser-based; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- `anthropic-api`: business-systems / generative-ai, client-server; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- Functions separated by name: `anthropic-claude` (Anthropic Claude), `anthropic-api` (Anthropic Claude developer platform and API).
- Variant: web app and API/console separated by name (`claude.ai` vs `api.anthropic.com`, `platform.claude.com`).
- Dependencies (observed, never attributed to this app): `15e17cac5f6a.w.hcaptcha.com`, `251360e3903c.w.hcaptcha.com`, `655f30477866.w.hcaptcha.com`, `api.hcaptcha.com`, `browser-intake-us5-datadoghq.com`, `challenges.cloudflare.com`, `e9ec84599f3b.w.hcaptcha.com`, `google-accounts`, `hagen.challenges.cloudflare.com`, `js.hcaptcha.com`, `newassets.hcaptcha.com`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `claude.ai`, `anthropic.com`, `claude.com`, `claudeusercontent.com`, `platform.claude.com`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
