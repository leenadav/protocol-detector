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

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R and L)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| D- | `aistudio.google.com` | not google-gemini-api (shared vendor infra) | `google-ai-studio` | PASS |
| D- | `apis.google.com` | not google-gemini-api (shared vendor infra) | `google-base` | PASS |
| D- | `fonts.googleapis.com` | not google-gemini-api (shared vendor infra) | `google-base` | PASS |
| D- | `fonts.gstatic.com` | not google-gemini-api (shared vendor infra) | `google-base` | PASS |
| D- | `www.googletagmanager.com` | not google-gemini-api (shared vendor infra) | `google-analytics` | PASS |
| D- | `www.gstatic.com` | not google-gemini-api (shared vendor infra) | `google-base` | PASS |
| L- | `xgoogleapis.com` | not google-gemini-api (label boundary) | no application | PASS |
| L- | `generativelanguage.googleapis.com.example.invalid` | not google-gemini-api (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Google AI Studio docs, "API reference", `https://aistudio.google.com/api-reference.md` (where `https://ai.google.dev/api` redirects), accessed 2026-11-19.
- [S2] Google AI Studio docs, "Get started", `https://aistudio.google.com/docs/get-started.md`, accessed 2026-11-19; the rendered page was also read by Hermes, relayed, 2026-11-19.

## 8. Catalog delta and recommendation

```python
("google-gemini-api", "business-systems", "generative-ai", "client-server", 3, "Google Gemini API",
 ("transfers-files",), ("generativelanguage.googleapis.com",)),
```

The id split mirrors `anthropic-api`; Hermes may instead fold the host into `google-gemini`.

**Decision applied (2026-11-20, Hermes delegated it to this lane):** the separate `google-gemini-api` id stays.
Reason: the API is a different function from the consumer app, with its own exact host and its own risk profile
(API keys, automated data transfer). The split is the same as `anthropic-api` and `openai-platform`. Live check:
`generativelanguage.googleapis.com` resolves and serves Google's shared front-end certificate
(`upload.video.google.com`, SAN covers the name), as expected for a `googleapis.com` name.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `generativelanguage.googleapis.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `upload.video.google.com` (SAN covers name: True) |

## 10. Observed web-client hosts (dependency mapping)

- `https://aistudio.google.com/`, loaded 2026-11-19 without signing in: HTTP 200, final host `aistudio.google.com`.

Pass 1 is a lower bound. The proxy refuses hosts not on the allowlist ("failed" below), so hosts that only scripts from a refused host would contact are missing.

| Host | Requests (refused) | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `aistudio.google.com` | 2 (0) | shared vendor infra | `google-ai-studio` |  |  |
| `apis.google.com` | 1 (1) | shared vendor infra | `google-base` | not checked |  |
| `fonts.googleapis.com` | 3 (0) | shared vendor infra | `google-base` | not checked |  |
| `fonts.gstatic.com` | 3 (0) | shared vendor infra | `google-base` | not checked |  |
| `www.googletagmanager.com` | 1 (1) | shared vendor infra | `google-analytics` | not checked |  |
| `www.gstatic.com` | 31 (5) | shared vendor infra | `google-base` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `google-gemini-api`: business-systems / generative-ai, client-server; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `google-ai-studio`, `google-analytics`, `google-base`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
