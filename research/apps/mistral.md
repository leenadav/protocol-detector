# Mistral AI (Le Chat and API)

- Content-pack id today: `mistral-ai` (`mistral.ai`)
- Status: API host **READY**, NAME, batch B2 (`research/patches/batch-b2-api-split.patch`), confirmed by Hermes (2026-11-18) for the API hosts confirmed in vendor docs. Chat-app hosts are PARTIAL (no primary source names them)
- Implemented: content release 2026.11.5 on `claude/go-migration` (`7dcabb7`); verified in the pack at `47b2743`, 2026-11-18
- Sources accessed: 2026-11-18

## 1. What it is

Mistral AI's assistant and its developer API. Chat and programmatic API use are different operator questions, as with OpenAI and Anthropic.

## 2. Transport and ports

HTTPS on TCP 443 to the API host [S1]. No other port is published on the pages read.

## 3. Observable evidence

- The API reference documents `https://api.mistral.ai/v1/chat/completions` [S1].
- `chat.mistral.ai` and other hosts: `UNVERIFIED`. No primary page read here names the chat application's hosts. They stay under the existing `mistral-ai` entry through its domain.
- ALPN and handshake structure: not published. `UNVERIFIED`.

## 4. Encrypted-traffic caveats

SNI only on the CONNECT path (README, shared facts). API keys travel in headers inside TLS and are never observable or logged. API calls made through third-party clouds or aggregators reach those providers' hosts and are not visible as this vendor.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI `api.mistral.ai` (and its subdomains) | **N3** API | Documented API host [S1] |
| Other names under the vendor domain | **U** for "chat" | Named only by the domain's ownership, as today |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `api.mistral.ai`, ALPN `h2` | `mistral-api` (today `mistral-ai`) |
| P2 | SNI `chat.mistral.ai` | `mistral-ai` (unchanged) |
| N1 | SNI `api.mistral.ai.example.invalid` | no application |
| N2 | `ech_outer()` with outer SNI `api.mistral.ai` | no application |

P1, P2 and N1 were checked with `attribution_for_host` in scratch (batches A, B and B2 applied): all as expected.

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K and M as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `chat.mistral.ai` | one of `mistral-ai`, `mistral-api` | `mistral-ai` | PASS |
| D- | `challenges.cloudflare.com` | not mistral-ai/mistral-api (third party) | no application | PASS |
| D- | `hagen.challenges.cloudflare.com` | not mistral-ai/mistral-api (third party (unclassified)) | no application | PASS |
| L- | `xmistral.ai` | not mistral-ai/mistral-api (label boundary) | no application | PASS |
| L- | `mistral.ai.example.invalid` | not mistral-ai/mistral-api (suffix look-alike) | no application | PASS |
| L- | `api.mistral.ai.example.invalid` | not mistral-ai/mistral-api (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Mistral docs, API reference "Chat", `https://docs.mistral.ai/api` (redirected from `/api/`), accessed 2026-11-18.

## 8. Catalog delta and recommendation

Batch B2 (pending confirmation):

```python
("mistral-api", "business-systems", "generative-ai", "client-server", 3, "...", ("transfers-files",), ("api.mistral.ai",)),
```

The description is in the patch. The existing `mistral-ai` entry is unchanged. Without B2, the API
host keeps resolving to `mistral-ai` through its domain, which is correct but less precise.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and round 4 of 2026-11-21 where it has the name (`research/live-results-2026-11-21-r4.tsv`, partial relay; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `mistral.ai` | **L** resolves; TLSv1.3, ALPN `h2`, cert `mistral.ai`, no subject organisation (domain-validated) (issuer Google Trust Services); HTTPS record offers `h3` (QUIC path) |
| `api.mistral.ai` | **L** resolves; TLSv1.3, ALPN `h2`, cert `api.mistral.ai`, no subject organisation (domain-validated) (issuer Google Trust Services); HTTPS record offers `h3` (QUIC path) |

## 10. Observed web-client hosts (dependency mapping)

- `https://chat.mistral.ai/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP None (page.goto: Timeout 45000ms exceeded.), final host `chat.mistral.ai`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `challenges.cloudflare.com` | seen | third party | no application | not checked | Cloudflare Turnstile bot check |
| `chat.mistral.ai` | seen | app-owned | `mistral-ai` | h3 |  |
| `hagen.challenges.cloudflare.com` | seen | third party (unclassified) | no application | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `mistral-ai`: business-systems / generative-ai, browser-based; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- `mistral-api`: business-systems / generative-ai, client-server; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- Functions separated by name: `mistral-ai` (Mistral AI), `mistral-api` (Mistral AI API).
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `challenges.cloudflare.com`, `hagen.challenges.cloudflare.com`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `mistral.ai`, `api.mistral.ai`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
