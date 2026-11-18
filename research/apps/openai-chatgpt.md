# OpenAI ChatGPT and OpenAI API

- Content-pack ids today: `openai-chatgpt` (`chatgpt.com`, `chat.openai.com`, `oaiusercontent.com`, `oaistatic.com`; web fronts `openai.com`, `www.openai.com`), `openai-platform` (`api.openai.com`, `platform.openai.com`)
- Status: `openai-chatgpt` **DONE**, NAME-BASED (all four domains now sourced, no catalog change needed). `openai-platform` is **BLOCKED** (the API docs could not be read)
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
| SNI `api.openai.com`, `platform.openai.com` | **U** | Not in the ChatGPT article; API docs blocked |
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
| N3 | SNI `www.openai.com` | web front of `openai-chatgpt` (affiliation only) |
| N4 | SNI `chatgpt.com.example.invalid`, `notchatgpt.com` | no application |
| N5 | `ech_outer()` with outer SNI `chatgpt.com` | no application |
| R1 | SNI `cdn.platform.openai.com` | today `openai-platform`: documents the attribution risk in section 5 |

Every row except N5 (which needs the full engine, not the name lookup) was checked against `attribution_for_host` on `claude/go-migration` `6b280a6` in scratch, 2026-11-18. All give the expected result.

## 7. Sources

- [S1] OpenAI Help Center, "Network recommendations for ChatGPT errors on web and apps",
  `https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps`.
  **Read by Lee in a normal browser on 2026-11-18** (article updated two days earlier, per Lee). Its
  allowlist and transport statements were relayed by Hermes in this lane's chat on 2026-11-18. This
  lane's own fetch met a Cloudflare challenge, which it did not bypass. Access date 2026-11-18.
- [S2] `https://openai.com/chatgpt-voice.json`, read directly 2026-11-18.
- [BLOCKED] `https://platform.openai.com/docs/api-reference/introduction`: Cloudflare challenge page,
  2026-11-18. Needed to verify `openai-platform`.

## 8. Catalog delta and recommendation

- `openai-chatgpt`: **no change**. Its four domains are now sourced [S1].
- `cdn.platform.openai.com`: the attribution risk is recorded and no change is proposed. Moving it to
  `openai-chatgpt` would need evidence that the platform does not use it, and none is published.
- Do not add the auth hosts, `oaistatsig.com`, `openaimerge.com` or any third-party name.
- `openai-platform` stays BLOCKED. A copy of OpenAI's API reference "Introduction" page (base URL) from
  Lee's browser would unblock it, in the same way as [S1].
