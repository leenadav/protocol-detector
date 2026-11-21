# DeepSeek

- Content-pack id today: `deepseek` (`deepseek.com`)
- Status: API host **READY**, NAME, batch B2 (`research/patches/batch-b2-api-split.patch`), confirmed by Hermes (2026-11-18) for the API hosts confirmed in vendor docs. Chat-app hosts are PARTIAL (no primary source names them)
- Implemented: content release 2026.11.5 on `claude/go-migration` (`7dcabb7`); verified in the pack at `47b2743`, 2026-11-18
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

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K and M as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `chat.deepseek.com` | one of `deepseek` | `deepseek` | PASS |
| L- | `xdeepseek.com` | not deepseek (label boundary) | no application | PASS |
| L- | `deepseek.com.example.invalid` | not deepseek (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] DeepSeek API Docs, "Your First API Call", `https://api-docs.deepseek.com/`, accessed 2026-11-18.

## 8. Catalog delta and recommendation

Batch B2 (pending confirmation):

```python
("deepseek-api", "business-systems", "generative-ai", "client-server", 3, "...", ("transfers-files",), ("api.deepseek.com",)),
```

The description is in the patch. The existing `deepseek` entry is unchanged. Without B2, the API
host keeps resolving to `deepseek` through its domain, which is correct but less precise.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 and 4 of 2026-11-21 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `research/live-results-2026-11-21-r4.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `deepseek.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `deepseek.com`, no subject organisation (domain-validated) (issuer Amazon) |

## 10. Observed web-client hosts (dependency mapping)

- `https://chat.deepseek.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 403, final host `chat.deepseek.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `chat.deepseek.com` | seen | app-owned | `deepseek` | cdn |  |

## 11. Attributes (App-ID model) and re-verify date

- `deepseek`: business-systems / generative-ai, browser-based; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
