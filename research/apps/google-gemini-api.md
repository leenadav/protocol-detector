# Google Gemini API

- Content-pack id today: none (today `generativelanguage.googleapis.com` resolves to `google-base`)
- Status: **READY**, NAME, batch G: new id `google-gemini-api` (follows the `anthropic-api` split decision)
- Sources: read by this lane, 2026-11-19 (Google AI Studio docs in Markdown). The AI Studio get-started page relayed by Hermes did not name the host, so this lane read the API reference itself

## 1. What it is

Google's Gemini developer API (API-key access from Google AI Studio), separate from the Gemini consumer app (`google-gemini`).

## 2. Transport and ports

HTTPS (REST, streaming) and WebSocket (`wss://generativelanguage.googleapis.com/ws/...`) for the Live API [S1].

## 3. Observable evidence

"To call an endpoint, send HTTPS requests to `https://generativelanguage.googleapis.com/{version}/{endpoint}` using `v1beta` or `v1`" [S1]. The quickstart uses `https://generativelanguage.googleapis.com/v1beta/interactions` [S2]. Sample media is fetched from `storage.googleapis.com/generativeai-downloads/...` [S2] (a path on shared Cloud Storage, not a host name).

## 4. Encrypted-traffic caveats

The host is a single exact name on shared `googleapis.com`; only that exact name is proposed. Vertex AI Gemini uses other Google Cloud hosts that are not on these pages and stay `google-base` (`UNVERIFIED`). This replaces the earlier N1 vector in `google-gemini.md`, written while no dedicated host was verified.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI `generativelanguage.googleapis.com` | **N3** (exact host) | API-key clients, SDKs and coding agents |
| Other `googleapis.com` names | `google-base` | Shared |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D, E, F and G): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `generativelanguage.googleapis.com` | `google-gemini-api` (today `google-base`) |
| N1 | SNI `aiplatform.googleapis.com` | `google-base` |
| N2 | SNI `gemini.google.com` | `google-gemini` |

## 7. Sources

- [S1] Google AI Studio docs, "API reference", `https://aistudio.google.com/api-reference.md` (where `https://ai.google.dev/api` redirects), accessed 2026-11-19.
- [S2] Google AI Studio docs, "Get started", `https://aistudio.google.com/docs/get-started.md`, accessed 2026-11-19; the rendered page was also read by Hermes, relayed, 2026-11-19.

## 8. Catalog delta and recommendation

```python
("google-gemini-api", "business-systems", "generative-ai", "client-server", 3, "Google Gemini API",
 ("transfers-files",), ("generativelanguage.googleapis.com",)),
```

The id split mirrors `anthropic-api`; Hermes may instead fold the host into `google-gemini`.
