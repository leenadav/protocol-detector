# Perplexity

- Content-pack id today: `perplexity` (`perplexity.ai`)
- Status: API host **READY**, NAME, batch B2 (`research/patches/batch-b2-api-split.patch`), confirmed by Hermes (2026-11-18) for the API hosts confirmed in vendor docs. Chat-app hosts are PARTIAL (no primary source names them)
- Implemented: content release 2026.11.5 on `claude/go-migration` (`7dcabb7`); verified in the pack at `47b2743`, 2026-11-18
- Sources accessed: 2026-11-18

## 1. What it is

Perplexity's answer engine and its developer API. Chat and programmatic API use are different operator questions, as with OpenAI and Anthropic.

## 2. Transport and ports

HTTPS on TCP 443 to the API host [S1]. No other port is published on the pages read.

## 3. Observable evidence

- The quickstart uses `https://api.perplexity.ai` endpoints, among them `/v1`, `/search`, `/v1/agent` and `/orchestrator/v1/chat/completions` [S1].
- `www.perplexity.ai` and the app hosts: `UNVERIFIED`. No primary page read here names the chat application's hosts. They stay under the existing `perplexity` entry through its domain.
- ALPN and handshake structure: not published. `UNVERIFIED`.

## 4. Encrypted-traffic caveats

SNI only on the CONNECT path (README, shared facts). API keys travel in headers inside TLS and are never observable or logged. API calls made through third-party clouds or aggregators reach those providers' hosts and are not visible as this vendor.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI `api.perplexity.ai` (and its subdomains) | **N3** API | Documented API host [S1] |
| Other names under the vendor domain | **U** for "chat" | Named only by the domain's ownership, as today |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `api.perplexity.ai`, ALPN `h2` | `perplexity-api` (today `perplexity`) |
| P2 | SNI `www.perplexity.ai` | `perplexity` (unchanged) |
| N1 | SNI `api.perplexity.ai.example.invalid` | no application |
| N2 | `ech_outer()` with outer SNI `api.perplexity.ai` | no application |

P1, P2 and N1 were checked with `attribution_for_host` in scratch (batches A, B and B2 applied): all as expected.

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O and P as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `count.perplexity.ai` | one of `perplexity`, `perplexity-api` | `perplexity` | PASS |
| O+ | `edge.perplexity.ai` | one of `perplexity`, `perplexity-api` | `perplexity` | PASS |
| O+ | `experimentation-cdn.perplexity.ai` | one of `perplexity`, `perplexity-api` | `perplexity` | PASS |
| O+ | `frontend-cdn.perplexity.ai` | one of `perplexity`, `perplexity-api` | `perplexity` | PASS |
| O+ | `pplx-next-static-public.perplexity.ai` | one of `perplexity`, `perplexity-api` | `perplexity` | PASS |
| O+ | `r2cdn.perplexity.ai` | one of `perplexity`, `perplexity-api` | `perplexity` | PASS |
| O+ | `www.perplexity.ai` | one of `perplexity`, `perplexity-api` | `perplexity` | PASS |
| D- | `accounts.google.com` | not perplexity/perplexity-api (shared vendor infra) | `google-accounts` | PASS |
| D- | `api.cr-relay.com` | not perplexity/perplexity-api (third party (unclassified)) | no application | PASS |
| D- | `browser-intake-datadoghq.com` | not perplexity/perplexity-api (shared vendor infra) | `datadog-base` | PASS |
| D- | `cdn.cr-relay.com` | not perplexity/perplexity-api (third party (unclassified)) | no application | PASS |
| D- | `commonroom.pplxmeasure.com` | not perplexity/perplexity-api (third party) | no application | PASS |
| D- | `connect.facebook.net` | not perplexity/perplexity-api (shared vendor infra) | `meta-base` | PASS |
| D- | `fscdn.eppo.cloud` | not perplexity/perplexity-api (third party (unclassified)) | no application | PASS |
| D- | `google.com` | not perplexity/perplexity-api (shared vendor infra) | `google-base` | PASS |
| D- | `google.pplxmeasure.com` | not perplexity/perplexity-api (third party) | no application | PASS |
| D- | `googleads.g.doubleclick.net` | not perplexity/perplexity-api (third party) | `google-ads` | PASS |
| D- | `linkedin.pplxmeasure.com` | not perplexity/perplexity-api (third party) | no application | PASS |
| D- | `meta.pplxmeasure.com` | not perplexity/perplexity-api (third party) | no application | PASS |
| D- | `px.ads.linkedin.com` | not perplexity/perplexity-api (shared vendor infra) | `linkedin-base` | PASS |
| D- | `sdk-api-v1.singular.net` | not perplexity/perplexity-api (third party (unclassified)) | no application | PASS |
| D- | `snap.licdn.com` | not perplexity/perplexity-api (shared vendor infra) | `linkedin-base` | PASS |
| D- | `static.cloudflareinsights.com` | not perplexity/perplexity-api (third party) | no application | PASS |
| D- | `www.google.co.il` | not perplexity/perplexity-api (third party (unclassified)) | no application | PASS |
| D- | `www.google.com` | not perplexity/perplexity-api (shared vendor infra) | `google-base` | PASS |
| D- | `www.googletagmanager.com` | not perplexity/perplexity-api (third party) | `google-analytics` | PASS |
| D- | `www.linkedin.com` | not perplexity/perplexity-api (third party) | `linkedin` | PASS |
| L- | `xperplexity.ai` | not perplexity/perplexity-api (label boundary) | no application | PASS |
| L- | `perplexity.ai.example.invalid` | not perplexity/perplexity-api (suffix look-alike) | no application | PASS |
| L- | `api.perplexity.ai.example.invalid` | not perplexity/perplexity-api (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Perplexity docs, quickstart, `https://docs.perplexity.ai/docs/getting-started/quickstart` (redirected from `/getting-started/quickstart`), accessed 2026-11-18.

## 8. Catalog delta and recommendation

Batch B2 (pending confirmation):

```python
("perplexity-api", "business-systems", "generative-ai", "client-server", 3, "...", ("transfers-files",), ("api.perplexity.ai",)),
```

The description is in the patch. The existing `perplexity` entry is unchanged. Without B2, the API
host keeps resolving to `perplexity` through its domain, which is correct but less precise.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 6 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `perplexity.ai` | **L** resolves; TLSv1.3, ALPN `h2`, cert `perplexity.ai`, no subject organisation (domain-validated) (issuer Google Trust Services); HTTPS record offers `h3` (QUIC path) |
| `api.perplexity.ai` | **L** resolves; TLSv1.3, ALPN `h2`, cert `perplexity.ai`, no subject organisation (domain-validated) (issuer Let's Encrypt); HTTPS record offers `h3` (QUIC path) |

## 10. Observed web-client hosts (dependency mapping)

- `https://www.perplexity.ai/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP None (page.goto: Timeout 45000ms exceeded.), final host `www.perplexity.ai`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `accounts.google.com` | seen | shared vendor infra | `google-accounts` |  |  |
| `api.cr-relay.com` | seen | third party (unclassified) | no application | not checked |  |
| `browser-intake-datadoghq.com` | seen | shared vendor infra | `datadog-base` | not checked |  |
| `cdn.cr-relay.com` | seen | third party (unclassified) | no application | not checked |  |
| `commonroom.pplxmeasure.com` | seen | third party | no application | not checked | measurement proxy; owner not verified |
| `connect.facebook.net` | seen | shared vendor infra | `meta-base` | not checked |  |
| `count.perplexity.ai` | seen | app-owned | `perplexity` | not checked |  |
| `edge.perplexity.ai` | seen | app-owned | `perplexity` | not checked |  |
| `experimentation-cdn.perplexity.ai` | seen | app-owned | `perplexity` | not checked |  |
| `frontend-cdn.perplexity.ai` | seen | app-owned | `perplexity` | not checked |  |
| `fscdn.eppo.cloud` | seen | third party (unclassified) | no application | not checked |  |
| `google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `google.pplxmeasure.com` | seen | third party | no application | not checked | measurement proxy; owner not verified |
| `googleads.g.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `linkedin.pplxmeasure.com` | seen | third party | no application | not checked | measurement proxy; owner not verified |
| `meta.pplxmeasure.com` | seen | third party | no application | not checked | measurement proxy; owner not verified |
| `pplx-next-static-public.perplexity.ai` | seen | app-owned | `perplexity` | not checked |  |
| `px.ads.linkedin.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `r2cdn.perplexity.ai` | seen | app-owned | `perplexity` | not checked |  |
| `sdk-api-v1.singular.net` | seen | third party (unclassified) | no application | not checked |  |
| `snap.licdn.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `static.cloudflareinsights.com` | seen (some failed) | third party | no application | not checked | Cloudflare Web Analytics beacon |
| `www.google.co.il` | seen (some failed) | third party (unclassified) | no application | not checked |  |
| `www.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `www.googletagmanager.com` | seen | third party | `google-analytics` | not checked |  |
| `www.linkedin.com` | seen (some failed) | third party | `linkedin` | not checked |  |
| `www.perplexity.ai` | seen (some failed) | app-owned | `perplexity` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `perplexity`: business-systems / generative-ai, browser-based; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- `perplexity-api`: business-systems / generative-ai, client-server; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- Functions separated by name: `perplexity` (Perplexity AI), `perplexity-api` (Perplexity API).
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `api.cr-relay.com`, `cdn.cr-relay.com`, `commonroom.pplxmeasure.com`, `datadog-base`, `fscdn.eppo.cloud`, `google-accounts`, `google-ads`, `google-analytics`, `google-base`, `google.pplxmeasure.com`, `linkedin`, `linkedin-base`, `linkedin.pplxmeasure.com`, `meta-base`, `meta.pplxmeasure.com`, `sdk-api-v1.singular.net`, `static.cloudflareinsights.com`, `www.google.co.il`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `perplexity.ai`, `api.perplexity.ai`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
