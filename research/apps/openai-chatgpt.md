# OpenAI ChatGPT and OpenAI API

- Content-pack ids today: `openai-chatgpt` (`chatgpt.com`, `chat.openai.com`, `oaiusercontent.com`, `oaistatic.com`; web fronts `openai.com`, `www.openai.com`), `openai-platform` (`api.openai.com`, `platform.openai.com`)
- Status: `openai-chatgpt` and `openai-platform` **DONE** for their domains (all sourced, no domain change). Web fronts `help.openai.com` and `developers.openai.com` are **READY**, NAME, batch B
- Implemented: content release 2026.11.4 on `claude/go-migration` (`6ab434d`); verified in the pack at `47b2743`, 2026-11-18
- Sources accessed: 2026-11-18

## 1. What it is

OpenAI's generative-AI assistant (ChatGPT, including Codex in ChatGPT) and its developer API. Operator
value is this lane's assessment, not a sourced prevalence figure.

## 2. Transport and ports

From OpenAI's article "Network recommendations for ChatGPT errors on web and apps" [S1]:

- HTTPS on TCP 443 to the allowlisted names (section 3).
- WebSocket over TCP 443 to `wss://ws.chatgpt.com` (ChatGPT) and `wss://chatgpt.com/` (Codex).
- ChatGPT Voice over **UDP 3478** to the IP ranges in `chatgpt-voice.json`, with TCP 443 as the fallback.

`https://openai.com/chatgpt-voice.json`, read directly 2026-11-18 [S2]: `creationTime`
`2026-11-16T01:33:53.175979+00:00`, 411 `ipv4Prefix` entries. Its purpose is now stated by [S1].

## 3. Observable evidence

The article's allowlist [S1], split by who operates each name. Only names under OpenAI's own domains
qualify as evidence (Hermes's instruction, consistent with the v0.65 operator-owned-domain rule):

| Group | Names (as listed) | Use as evidence |
|---|---|---|
| OpenAI ChatGPT domains | `*.chatgpt.com`, `chat.openai.com`, `android.chat.openai.com`, `desktop.chat.openai.com`, `ios.chat.openai.com`, `tcr9i.chat.openai.com`, `*.oaistatic.com`, `*.oaiusercontent.com` | **N3** `openai-chatgpt` (all already under the pack's four domains) |
| OpenAI sign-in | `*.auth.openai.com`, `setup.auth.openai.com`, `auth0.openai.com` | **N2**: sign-in, not use; unmapped today (only the exact `openai.com` and `www.openai.com` are fronts) |
| OpenAI, other | `*.openai.com`, `cdn.platform.openai.com` | see section 5 |
| Ownership not stated | `*.oaistatsig.com`, `cdn.openaimerge.com` | **U**: listed as required, but the article does not say who operates these domains. Not mapped |
| Third-party, shared with other customers | `*.ct.sendgrid.net`, `*.intercom.io`, `*.intercomcdn.com`, `js.intercomcdn.com`, `cdn.workos.com`, `forwarder.workos.com`, `frontend-apps-multi-region.workos.com`, `images.workoscdn.com`, `setup.workos.com`, `workos.imgix.net`, `js.stripe.com`, `o207216.ingest.sentry.io`, `o33249.ingest.sentry.io`, `rum.browser-intake-datadoghq.com`, `challenges.cloudflare.com`, `humb.apple.com` | **never** OpenAI evidence (SendGrid, Intercom, WorkOS, imgix, Stripe, Sentry, Datadog, Cloudflare, Apple) |

ALPN and handshake structure: not published. `UNVERIFIED`.

## 4. Encrypted-traffic caveats

- **Codex vs ChatGPT**: both use `chatgpt.com` names (`ws.chatgpt.com` for ChatGPT, `chatgpt.com/` for
  Codex) [S1]. The path is inside TLS, so on the CONNECT path Codex in ChatGPT cannot be told apart from
  ChatGPT.
- **Voice** uses UDP 3478 to published ranges [S1, S2]. That is off the visibility-phase path, and a
  TCP 443 fallback exists [S1]. Voice is not separable from other ChatGPT use on TCP.
- **Third-party services** (WorkOS sign-in, Intercom support, Stripe payments, Sentry and Datadog
  telemetry, Cloudflare challenges) are shared by many companies. Their presence says nothing about
  OpenAI.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `chatgpt.com`, `chat.openai.com`, `oaistatic.com`, `oaiusercontent.com` | **N3** `openai-chatgpt` | Includes Codex in ChatGPT; personal vs business accounts not separable by name (no source) |
| SNI `cdn.platform.openai.com` | **N2**, attribution risk | Listed for **ChatGPT** [S1], but the pack names it `openai-platform` through `platform.openai.com`. A ChatGPT session may therefore also log `openai-platform` |
| SNI `api.openai.com` | **N3** `openai-platform` | API base `https://api.openai.com/v1` [S3] |
| SNI `platform.openai.com` | **N2** `openai-platform` | Developer console: sign-in, API keys, organization settings, all linked from the API reference [S3]. Not API traffic itself |
| SNI `developers.openai.com`, `help.openai.com` | web fronts (batch B) | API documentation [S3]; help centre [S1]. Not use |
| `oaistatsig.com`, `openaimerge.com` | **U** | Ownership not stated |
| UDP 3478 to `chatgpt-voice.json` ranges | **N2**, later phase | IP and port only; UDP is not observed in this phase |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `ws.chatgpt.com`, ALPN `http/1.1` | `openai-chatgpt` |
| P2 | SNI `ios.chat.openai.com` | `openai-chatgpt` |
| P3 | SNI `files.oaiusercontent.com` (synthetic label) | `openai-chatgpt` |
| N1 | SNI `cdn.workos.com`, `js.stripe.com`, `challenges.cloudflare.com` | never an OpenAI application (`js.stripe.com` is `stripe`; the others are unmapped) |
| N2 | SNI `auth.openai.com` | no application (sign-in; not a front, not a service domain) |
| N3 | SNI `www.openai.com`, `help.openai.com` | web front of `openai-chatgpt` (affiliation only; `help.` from batch B) |
| N3b | SNI `developers.openai.com` | web front of `openai-platform` (batch B); never the API |
| P4 | SNI `api.openai.com` | `openai-platform` |
| N4 | SNI `chatgpt.com.example.invalid`, `notchatgpt.com` | no application |
| N5 | `ech_outer()` with outer SNI `chatgpt.com` | no application |
| R1 | SNI `cdn.platform.openai.com` | today `openai-platform`: documents the attribution risk in section 5 |

Every row except N5 (which needs the full engine, not the name lookup) was checked against `attribution_for_host` on `claude/go-migration` `6b280a6` in scratch, 2026-11-18. All give the expected result.

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R and L)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `chatgpt.com` | one of `openai-chatgpt`, `openai-platform` | `openai-chatgpt` | PASS |
| O+ | `platform.openai.com` | one of `openai-chatgpt`, `openai-platform` | `openai-platform` | PASS |
| D- | `challenges.cloudflare.com` | not openai-chatgpt/openai-platform (third party) | no application | PASS |
| L- | `xchatgpt.com` | not openai-chatgpt/openai-platform (label boundary) | no application | PASS |
| L- | `chatgpt.com.example.invalid` | not openai-chatgpt/openai-platform (suffix look-alike) | no application | PASS |
| L- | `xopenai.com` | not openai-chatgpt/openai-platform (label boundary) | no application | PASS |
| L- | `chat.openai.com.example.invalid` | not openai-chatgpt/openai-platform (suffix look-alike) | no application | PASS |
| L- | `xoaiusercontent.com` | not openai-chatgpt/openai-platform (label boundary) | no application | PASS |
| L- | `oaiusercontent.com.example.invalid` | not openai-chatgpt/openai-platform (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] OpenAI Help Center, "Network recommendations for ChatGPT errors on web and apps",
  `https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps`.
  **Read by Lee in a normal browser on 2026-11-18** (article updated two days earlier, per Lee). Its
  allowlist and transport statements were relayed by Hermes in this lane's chat on 2026-11-18. This
  lane's own fetch met a Cloudflare challenge, which it did not bypass. Access date 2026-11-18.
- [S2] `https://openai.com/chatgpt-voice.json`, read directly 2026-11-18.
- [S3] OpenAI API reference, "API Overview", `https://developers.openai.com/api/reference/overview` (the
  redirect target of `platform.openai.com/docs/api-reference/introduction`, per Lee's browser, relayed by
  Hermes 2026-11-18). **Read directly by this lane on 2026-11-18**: examples `curl https://api.openai.com/v1/models`
  and `/v1/chat/completions`; response headers `openai-organization`, `openai-processing-ms`,
  `openai-version`, `x-request-id`; links to `platform.openai.com/login` and
  `platform.openai.com/settings/organization/api-keys`. Those headers are inside TLS and are request
  metadata, never identity.

## 8. Catalog delta and recommendation

- `openai-chatgpt` and `openai-platform` domains: **no change** (all sourced: [S1] and [S3]).
- Batch B (`research/patches/batch-b-name-based.patch`): web fronts, provider affiliation only:

```python
("openai-chatgpt", ..., ("chatgpt.com", "chat.openai.com", "oaiusercontent.com", "oaistatic.com"), ("openai.com", "www.openai.com", "help.openai.com")),
("openai-platform", ..., ("api.openai.com", "platform.openai.com"), ("developers.openai.com",)),
```

  `developers.openai.com` is the documentation, so it is never attributed to the API itself (Hermes,
  2026-11-18). Today it and `help.openai.com` are unmapped.
- `cdn.platform.openai.com`: the attribution risk stays recorded (section 5); no change.
- Do not add the auth hosts, `oaistatsig.com`, `openaimerge.com` or any third-party name.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `chatgpt.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `chatgpt.com` (SAN covers name: True) |
| `chat.openai.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `chat.openai.com` (SAN covers name: True); CNAME into shared front end `chat.openai.com.cdn.cloudflare.net`: name usable, IPs never |
| `oaiusercontent.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `oaistatic.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `oaistatic.com` (SAN covers name: True); HTTPS record offers `h3` (QUIC path) |
| `api.openai.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `api.openai.com` (SAN covers name: True) |
| `platform.openai.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `platform.openai.com` (SAN covers name: True); CNAME into shared front end `platform.openai.com.cdn.cloudflare.net`: name usable, IPs never |

## 10. Observed web-client hosts (dependency mapping)

- `https://chatgpt.com/`, loaded 2026-11-19 without signing in: HTTP None (page.goto: Timeout 45000ms exceeded.), final host `chatgpt.com`.
- `https://platform.openai.com/`, loaded 2026-11-19 without signing in: HTTP None (page.goto: Timeout 45000ms exceeded.), final host `platform.openai.com`.

Pass 1 is a lower bound. The proxy refuses hosts not on the allowlist ("failed" below), so hosts that only scripts from a refused host would contact are missing.

| Host | Requests (refused) | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `challenges.cloudflare.com` | 8 (7) | third party | no application | not checked | Cloudflare Turnstile bot check |
| `chatgpt.com` | 16 (0) | app-owned | `openai-chatgpt` |  |  |
| `platform.openai.com` | 20 (3) | app-owned | `openai-platform` | cdn |  |

## 11. Attributes (App-ID model) and re-verify date

- `openai-chatgpt`: business-systems / generative-ai, browser-based; characteristics `transfers-files`, `widely-used`; **risk 3**: moves files out of the organisation; widely used by enterprises.
- `openai-platform`: business-systems / generative-ai, client-server; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- Functions separated by name: `openai-chatgpt` (OpenAI ChatGPT), `openai-platform` (OpenAI developer platform and API).
- Variant: web app and API platform separated by name (`chatgpt.com` vs `api.openai.com`, `platform.openai.com`).
- Dependencies (observed, never attributed to this app): `challenges.cloudflare.com`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `oaistatic.com`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
