# DeepSeek

- Content-pack id today: `deepseek` (`deepseek.com`)
- Status: API host **READY**, NAME, batch B2 (`research/patches/batch-b2-api-split.patch`), **pending Hermes's confirmation** that the API-split rule decided for Anthropic applies to this vendor. Chat-app hosts are PARTIAL (no primary source names them)
- Sources accessed: 2026-11-18

## 1. What it is

DeepSeek's generative-AI assistant and its developer API. Chat and programmatic API use are different operator questions, as with OpenAI and Anthropic.

## 2. Transport and ports

HTTPS on TCP 443 to the API host [S1]. No other port is published on the pages read.

## 3. Observable evidence

- The API docs give `base_url` "https://api.deepseek.com" for the OpenAI-compatible format and "https://api.deepseek.com/anthropic" for the Anthropic-compatible one; requests go to `https://api.deepseek.com/chat/completions` [S1].
- `chat.deepseek.com` and other chat hosts: `UNVERIFIED`. No primary page read here names the chat application's hosts. They stay under the existing `deepseek` entry through its domain.
- ALPN and handshake structure: not published. `UNVERIFIED`.

## 4. Encrypted-traffic caveats

SNI only on the CONNECT path (README, shared facts). API keys travel in headers inside TLS and are never observable or logged. API calls made through third-party clouds or aggregators reach those providers' hosts and are not visible as this vendor.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI `api.deepseek.com` (and its subdomains) | **N3** API | Documented API host [S1] |
| Other names under the vendor domain | **U** for "chat" | Named only by the domain's ownership, as today |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `api.deepseek.com`, ALPN `h2` | `deepseek-api` (today `deepseek`) |
| P2 | SNI `chat.deepseek.com` | `deepseek` (unchanged) |
| N1 | SNI `api.deepseek.com.example.invalid` | no application |
| N2 | `ech_outer()` with outer SNI `api.deepseek.com` | no application |

P1, P2 and N1 were checked with `attribution_for_host` in scratch (batches A, B and B2 applied): all as expected.

## 7. Sources

- [S1] DeepSeek API Docs, "Your First API Call", `https://api-docs.deepseek.com/`, accessed 2026-11-18.

## 8. Catalog delta and recommendation

Batch B2 (pending confirmation):

```python
("deepseek-api", "business-systems", "generative-ai", "client-server", 3, "...", ("transfers-files",), ("api.deepseek.com",)),
```

The description is in the patch. The existing `deepseek` entry is unchanged. Without B2, the API
host keeps resolving to `deepseek` through its domain, which is correct but less precise.
