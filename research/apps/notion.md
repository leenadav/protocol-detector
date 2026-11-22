# Notion

- Content-pack id today: `notion` (`notion.so`, `notion.site`)
- Status: **READY**, NAME, batch D
- Sources accessed: 2026-11-19

## 1. What it is

Workspace and documents app.

## 2. Transport and ports

HTTPS; fixed outgoing IP blocks are published [S1].

## 3. Observable evidence

"Notion IP addresses and domains" [S1]: `notion.com`, `notion.site`, `notion-custom.com`, `app.notion.com`, `api.notion.com`, `img.notionusercontent.com`, `notionusercontent.com`, `secure.notion-static.com`, `audioprocessor.app.notion.com`.

## 4. Encrypted-traffic caveats

`notion-custom.com` is not proposed: its name suggests customers' custom domains (tenant hosting), and the page does not say what it serves (`UNVERIFIED`). Only the exact `secure.notion-static.com` is proposed, not the whole `notion-static.com` domain.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `notion.com`, `notion.so`, `notionusercontent.com`; exact `secure.notion-static.com` | **N3** |  |
| `notion-custom.com` | **U** | Not mapped |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `www.notion.com`, `img.notionusercontent.com`, `secure.notion-static.com` | `notion` |
| N1 | SNI `x.notion-static.com`, `x.notion-custom.com` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O and P as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `aif.notion.so` | one of `notion` | `notion` | PASS |
| O+ | `app.notion.com` | one of `notion` | `notion` | PASS |
| O+ | `exp.notion.com` | one of `notion` | `notion` | PASS |
| O+ | `identity.notion.com` | one of `notion` | `notion` | PASS |
| O+ | `www.notion.so` | one of `notion` | `notion` | PASS |
| D- | `accounts.google.com` | not notion (shared vendor infra) | `google-accounts` | PASS |
| D- | `analytics.twitter.com` | not notion (shared vendor infra) | `x-base` | PASS |
| D- | `api.ipify.org` | not notion (third party (unclassified)) | no application | PASS |
| D- | `bat.bing.com` | not notion (shared vendor infra) | `ms-base` | PASS |
| D- | `c.bing.com` | not notion (shared vendor infra) | `ms-base` | PASS |
| D- | `c.clarity.ms` | not notion (third party (unclassified)) | no application | PASS |
| D- | `cdn.cr-relay.com` | not notion (third party (unclassified)) | no application | PASS |
| D- | `cdn.metadata.io` | not notion (third party (unclassified)) | no application | PASS |
| D- | `connect.facebook.net` | not notion (shared vendor infra) | `meta-base` | PASS |
| D- | `google.com` | not notion (shared vendor infra) | `google-base` | PASS |
| D- | `googleads.g.doubleclick.net` | not notion (third party) | `google-ads` | PASS |
| D- | `h.clarity.ms` | not notion (third party (unclassified)) | no application | PASS |
| D- | `http-inputs-notion.splunkcloud.com` | not notion (third party) | `splunk-cloud` | PASS |
| D- | `o324374.ingest.sentry.io` | not notion (third party) | `sentry` | PASS |
| D- | `px.ads.linkedin.com` | not notion (shared vendor infra) | `linkedin-base` | PASS |
| D- | `px4.ads.linkedin.com` | not notion (shared vendor infra) | `linkedin-base` | PASS |
| D- | `scripts.clarity.ms` | not notion (third party (unclassified)) | no application | PASS |
| D- | `snap.licdn.com` | not notion (shared vendor infra) | `linkedin-base` | PASS |
| D- | `static.ads-twitter.com` | not notion (third party) | no application | PASS |
| D- | `t.co` | not notion (shared vendor infra) | `x-base` | PASS |
| D- | `www.clarity.ms` | not notion (third party (unclassified)) | no application | PASS |
| D- | `www.google.co.il` | not notion (third party (unclassified)) | no application | PASS |
| D- | `www.google.com` | not notion (shared vendor infra) | `google-base` | PASS |
| D- | `www.googleadservices.com` | not notion (third party) | `google-ads` | PASS |
| D- | `www.googletagmanager.com` | not notion (third party) | `google-analytics` | PASS |
| D- | `www.linkedin.com` | not notion (third party) | `linkedin` | PASS |
| L- | `xnotion.so` | not notion (label boundary) | no application | PASS |
| L- | `notion.so.example.invalid` | not notion (suffix look-alike) | no application | PASS |
| L- | `xnotion.site` | not notion (label boundary) | no application | PASS |
| L- | `notion.site.example.invalid` | not notion (suffix look-alike) | no application | PASS |
| L- | `xnotion.com` | not notion (label boundary) | no application | PASS |
| L- | `notion.com.example.invalid` | not notion (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Notion Help, "Notion IP addresses & domains to allowlist", `https://www.notion.com/help/allowlist-ip`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("notion", ..., ("notion.so", "notion.site", "notion.com", "notionusercontent.com", "secure.notion-static.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `notion.so` | **L** resolves; TLSv1.3, ALPN `h2`, cert `notion.so`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `notion.site` | **L** resolves; TLSv1.3, ALPN `h2`, cert `notion.site`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `notion.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `notion.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `notionusercontent.com` | apex has no address (normal for a suffix entry); suffix **verified** through documented `img.notionusercontent.com` (round 2) |
| `secure.notion-static.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |

## 10. Observed web-client hosts (dependency mapping)

- `https://www.notion.so/login`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP None (page.goto: Timeout 45000ms exceeded.), final host `app.notion.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `accounts.google.com` | seen | shared vendor infra | `google-accounts` |  |  |
| `aif.notion.so` | seen | app-owned | `notion` | not checked |  |
| `analytics.twitter.com` | seen | shared vendor infra | `x-base` | not checked |  |
| `api.ipify.org` | seen | third party (unclassified) | no application | not checked |  |
| `app.notion.com` | seen | app-owned | `notion` | not checked |  |
| `bat.bing.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `c.bing.com` | seen | shared vendor infra | `ms-base` | not checked |  |
| `c.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `cdn.cr-relay.com` | seen | third party (unclassified) | no application | not checked |  |
| `cdn.metadata.io` | seen | third party (unclassified) | no application | not checked |  |
| `connect.facebook.net` | seen | shared vendor infra | `meta-base` | not checked |  |
| `exp.notion.com` | seen | app-owned | `notion` | not checked |  |
| `google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `googleads.g.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `h.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `http-inputs-notion.splunkcloud.com` | seen (some failed) | third party | `splunk-cloud` | not checked |  |
| `identity.notion.com` | seen | app-owned | `notion` | not checked |  |
| `o324374.ingest.sentry.io` | seen | third party | `sentry` | not checked |  |
| `px.ads.linkedin.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `px4.ads.linkedin.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `scripts.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `snap.licdn.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `static.ads-twitter.com` | seen | third party | no application | not checked | X advertising tag |
| `t.co` | seen | shared vendor infra | `x-base` | not checked |  |
| `www.clarity.ms` | seen | third party (unclassified) | no application | not checked |  |
| `www.google.co.il` | seen | third party (unclassified) | no application | not checked |  |
| `www.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `www.googleadservices.com` | seen | third party | `google-ads` | not checked |  |
| `www.googletagmanager.com` | seen | third party | `google-analytics` | not checked |  |
| `www.linkedin.com` | seen | third party | `linkedin` | not checked |  |
| `www.notion.so` | seen | app-owned | `notion` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `notion`: business-systems / office-programs, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `api.ipify.org`, `c.clarity.ms`, `cdn.cr-relay.com`, `cdn.metadata.io`, `google-accounts`, `google-ads`, `google-analytics`, `google-base`, `h.clarity.ms`, `linkedin`, `linkedin-base`, `meta-base`, `ms-base`, `scripts.clarity.ms`, `sentry`, `splunk-cloud`, `static.ads-twitter.com`, `www.clarity.ms`, `www.google.co.il`, `x-base`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
