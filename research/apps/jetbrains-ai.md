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

### Method v2 vectors (checked 2026-11-19 against `c08773f` plus batches D to I and retrofit R)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `account.jetbrains.com` | one of `jetbrains-ai`, `jetbrains` | `jetbrains` | PASS |
| O+ | `resources.jetbrains.com` | one of `jetbrains-ai`, `jetbrains` | `jetbrains` | PASS |
| D- | `o245151.ingest.us.sentry.io` | not jetbrains-ai/jetbrains (third party) | `sentry` | PASS |
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

**BLOCKED in the research environment** (2026-11-19): its egress proxy re-terminates TLS, so a handshake would show the proxy, and direct DNS is not permitted. The tool is `research/tools/live_verify.py`; it runs from an unproxied vantage point or, DNS only, through an approved DoH resolver. No host below carries an `L` result yet.

Names to verify (catalog domains of `jetbrains-ai`, `jetbrains`): `api.jetbrains.ai`, `jetbrains.com`.

## 10. Observed web-client hosts (dependency mapping)

- `https://account.jetbrains.com/login`, loaded 2026-11-19 without signing in: HTTP 200, final host `account.jetbrains.com`.

Pass 1 is a lower bound. The proxy refuses hosts not on the allowlist ("failed" below), so hosts that only scripts from a refused host would contact are missing.

| Host | Requests (refused) | Class | Attribution today | Note |
|---|---|---|---|---|
| `account.jetbrains.com` | 7 (0) | app-owned | `jetbrains` |  |
| `o245151.ingest.us.sentry.io` | 1 (1) | third party | `sentry` |  |
| `resources.jetbrains.com` | 4 (4) | app-owned | `jetbrains` |  |
| `www.googletagmanager.com` | 1 (1) | third party | `google-analytics` |  |

## 11. Attributes (App-ID model) and re-verify date

- `jetbrains-ai`: business-systems / generative-ai, client-server; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- `jetbrains`: business-systems / software-development, client-server; characteristics `transfers-files`; **risk 1**: moves files out of the organisation.
- Functions separated by name: `jetbrains-ai` (JetBrains AI), `jetbrains` (JetBrains tools and account services).
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `google-analytics`, `sentry`.
- Evasive (ECH, DoH, proxy modes): ECH support unknown until a live HTTPS-record check (section 9); other modes as stated in sections 2 to 4.
- Re-verify by: **2027-02-17** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
