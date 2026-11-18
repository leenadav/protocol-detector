# xAI Grok (grok.com and API)

- Content-pack id today: `xai-grok` (`grok.com`, `x.ai`)
- Status: API host **READY**, NAME, batch B2 (`research/patches/batch-b2-api-split.patch`), confirmed by Hermes (2026-11-18) for the API hosts confirmed in vendor docs. Chat-app hosts are PARTIAL (no primary source names them)
- Implemented: content release 2026.11.5 on `claude/go-migration` (`7dcabb7`); verified in the pack at `47b2743`, 2026-11-18
- Sources accessed: 2026-11-18

## 1. What it is

xAI's Grok assistant and its developer API. The docs pages read here carry the title "SpaceXSI Docs", and the page metadata names the author organization "SpaceX Super Intelligence" with the URL `https://x.ai` [S1, S2]. This lane records that branding without interpreting it. Catalog descriptions stay neutral and domain-based (Hermes, 2026-11-18): the pack uses "xAI (x.ai) developer API". Chat and programmatic API use are different operator questions, as with OpenAI and Anthropic.

## 2. Transport and ports

HTTPS on TCP 443 to the API host [S1]. No other port is published on the pages read.

## 3. Observable evidence

- "https://api.x.ai is the global endpoint"; a US regional endpoint is `https://us.api.x.ai/v1` [S2]; examples use `base_url="https://api.x.ai/v1"` [S1]. The overview links to `https://grok.com` [S1].
- `grok.com`: `UNVERIFIED`. No primary page read here names the chat application's hosts. They stay under the existing `xai-grok` entry through its domain.
- ALPN and handshake structure: not published. `UNVERIFIED`.

## 4. Encrypted-traffic caveats

SNI only on the CONNECT path (README, shared facts). API keys travel in headers inside TLS and are never observable or logged. API calls made through third-party clouds or aggregators reach those providers' hosts and are not visible as this vendor.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI `api.x.ai` (and its subdomains) | **N3** API | Documented API host [S1] |
| Other names under the vendor domain | **U** for "chat" | Named only by the domain's ownership, as today |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `us.api.x.ai`, ALPN `h2` | `xai-api` (today `xai-grok`) |
| P2 | SNI `grok.com` | `xai-grok` (unchanged) |
| N1 | SNI `api.x.ai.example.invalid` | no application |
| N2 | `ech_outer()` with outer SNI `api.x.ai` | no application |

P1, P2 and N1 were checked with `attribution_for_host` in scratch (batches A, B and B2 applied): all as expected.

## 7. Sources

- [S1] xAI docs overview, `https://docs.x.ai/overview` (redirected from `/docs/overview`), accessed 2026-11-18.
- [S2] xAI docs, "Regional Endpoints", `https://docs.x.ai/developers/advanced-api-usage/regions`, accessed 2026-11-18.

## 8. Catalog delta and recommendation

Batch B2 (pending confirmation):

```python
("xai-api", "business-systems", "generative-ai", "client-server", 3, "...", ("transfers-files",), ("api.x.ai",)),
```

The description is in the patch. The existing `xai-grok` entry is unchanged. Without B2, the API
host keeps resolving to `xai-grok` through its domain, which is correct but less precise.
