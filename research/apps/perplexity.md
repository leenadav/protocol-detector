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

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R and L)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
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

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `perplexity.ai` | **L** resolves; TLSv1.3, ALPN `h2`, cert `perplexity.ai` (SAN covers name: True); HTTPS record offers `h3` (QUIC path) |
| `api.perplexity.ai` | **L** resolves; TLSv1.3, ALPN `h2`, cert `perplexity.ai` (SAN covers name: True); HTTPS record offers `h3` (QUIC path) |

## 10. Observed web-client hosts (dependency mapping)

- `https://www.perplexity.ai/`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

## 11. Attributes (App-ID model) and re-verify date

- `perplexity`: business-systems / generative-ai, browser-based; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- `perplexity-api`: business-systems / generative-ai, client-server; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- Functions separated by name: `perplexity` (Perplexity AI), `perplexity-api` (Perplexity API).
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `perplexity.ai`, `api.perplexity.ai`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
