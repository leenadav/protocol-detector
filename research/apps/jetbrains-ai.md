# JetBrains AI (AI Assistant, AI Enterprise)

- Content-pack id today: none for AI; `jetbrains` (`jetbrains.com`)
- Status: **READY**, NAME, batch F: new id `jetbrains-ai`
- Sources accessed: 2026-11-19

## 1. What it is

JetBrains' AI features in its IDEs. Generative-AI use by developers is a visibility question separate from the IDE vendor's
other traffic (licensing, plugins, downloads), in the same way that `github-copilot` is separate from `github`.

## 2. Transport and ports

HTTPS [S1].

## 3. Observable evidence

"api.jetbrains.ai and dynamic URLs – required for AI Enterprise functioning" [S1]. The same page lists IDE and Toolbox
hosts: `resources.`, `download.`, `plugins.`, `downloads.marketplace.`, `data.services.` and `account.jetbrains.com`.

## 4. Encrypted-traffic caveats

"Dynamic URLs" are not named [S1], so AI traffic to other hosts is not visible by name.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI `api.jetbrains.ai` | **N3** JetBrains AI | Only the named host |
| `jetbrains.com` names | `jetbrains` | IDE, licensing, plugins |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `api.jetbrains.ai` | `jetbrains-ai` |
| N1 | SNI `jetbrains.ai` | no application (only the exact host is sourced) |
| N2 | SNI `account.jetbrains.com` | `jetbrains` |

Checked in scratch (`c08773f` plus D, E and F).

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O and P as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `account.jetbrains.com` | one of `jetbrains-ai`, `jetbrains` | `jetbrains` | PASS |
| O+ | `resources.jetbrains.com` | one of `jetbrains-ai`, `jetbrains` | `jetbrains` | PASS |
| D- | `426-qvd-114.mktoresp.com` | not jetbrains-ai/jetbrains (third party (unclassified)) | no application | PASS |
| D- | `analytics.google.com` | not jetbrains-ai/jetbrains (shared vendor infra) | `google-base` | PASS |
| D- | `bzr.openai.com` | not jetbrains-ai/jetbrains (third party) | no application | PASS |
| D- | `bzrcdn.openai.com` | not jetbrains-ai/jetbrains (third party) | no application | PASS |
| D- | `cdn.cookiehub.eu` | not jetbrains-ai/jetbrains (third party (unclassified)) | no application | PASS |
| D- | `munchkin.marketo.net` | not jetbrains-ai/jetbrains (third party (unclassified)) | no application | PASS |
| D- | `o245151.ingest.us.sentry.io` | not jetbrains-ai/jetbrains (third party) | `sentry` | PASS |
| D- | `stats.g.doubleclick.net` | not jetbrains-ai/jetbrains (third party) | `google-ads` | PASS |
| D- | `www.google.co.il` | not jetbrains-ai/jetbrains (third party (unclassified)) | no application | PASS |
| D- | `www.googletagmanager.com` | not jetbrains-ai/jetbrains (third party) | `google-analytics` | PASS |
| L- | `xjetbrains.ai` | not jetbrains-ai/jetbrains (label boundary) | no application | PASS |
| L- | `api.jetbrains.ai.example.invalid` | not jetbrains-ai/jetbrains (suffix look-alike) | no application | PASS |
| L- | `xjetbrains.com` | not jetbrains-ai/jetbrains (label boundary) | no application | PASS |
| L- | `jetbrains.com.example.invalid` | not jetbrains-ai/jetbrains (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] JetBrains, IDE Services Cloud Documentation, "Network access requirements",
  `https://www.jetbrains.com/help/ide-services-cloud/network-access-requirements.html`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

```python
("jetbrains-ai", "business-systems", "generative-ai", "client-server", 3, "JetBrains AI",
 ("transfers-files",), ("api.jetbrains.ai",)),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 6 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `api.jetbrains.ai` | **L** resolves; TLSv1.3, ALPN `h2`, cert `api.jetbrains.ai`, no subject organisation (domain-validated) (issuer Amazon); CNAME into shared front end `dvxdiz880bm14.cloudfront.net`: name usable, IPs never; HTTPS record offers `h3` (QUIC path) |
| `jetbrains.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `jetbrains.com`, no subject organisation (domain-validated) (issuer Amazon) |

## 10. Observed web-client hosts (dependency mapping)

- `https://account.jetbrains.com/login`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `account.jetbrains.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `426-qvd-114.mktoresp.com` | seen | third party (unclassified) | no application | not checked |  |
| `account.jetbrains.com` | seen | app-owned | `jetbrains` |  |  |
| `analytics.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `bzr.openai.com` | seen | third party | no application | not checked | OpenAI measurement host loaded by unrelated pages (not mapped: openai.com is a web front only) |
| `bzrcdn.openai.com` | seen | third party | no application | not checked | as above |
| `cdn.cookiehub.eu` | seen | third party (unclassified) | no application | not checked |  |
| `munchkin.marketo.net` | seen | third party (unclassified) | no application | not checked |  |
| `o245151.ingest.us.sentry.io` | seen | third party | `sentry` | not checked |  |
| `resources.jetbrains.com` | seen | app-owned | `jetbrains` |  |  |
| `stats.g.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `www.google.co.il` | seen | third party (unclassified) | no application | not checked |  |
| `www.googletagmanager.com` | seen | third party | `google-analytics` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `jetbrains-ai`: business-systems / generative-ai, client-server; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- `jetbrains`: business-systems / software-development, client-server; characteristics `transfers-files`; **risk 1**: moves files out of the organisation.
- Functions separated by name: `jetbrains-ai` (JetBrains AI), `jetbrains` (JetBrains tools and account services).
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `426-qvd-114.mktoresp.com`, `bzr.openai.com`, `bzrcdn.openai.com`, `cdn.cookiehub.eu`, `google-ads`, `google-analytics`, `google-base`, `munchkin.marketo.net`, `sentry`, `www.google.co.il`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `api.jetbrains.ai`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
