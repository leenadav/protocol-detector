# Atlassian Cloud (Jira, Confluence, Bitbucket)

- Content-pack id today: `atlassian` (`atlassian.net`, `atlassian.com`, `bitbucket.org`)
- Status: **READY**, NAME, batch C (`research/patches/batch-c-name-based.patch`)
- Sources accessed: 2026-11-18

## 1. What it is

Atlassian's cloud collaboration and developer apps.

## 2. Transport and ports

HTTPS. The page asks admins to permit domains "and multiple levels of subdomains" [S1].

## 3. Observable evidence

"For Atlassian apps to operate, allow these first-party Atlassian domains and their levels of subdomains.
These domains are directly operated and managed by Atlassian" [S1]: `*.atl-paas.net`, `*.atlassian.com`,
`*.ss-inf.net`, `*.atlassian.net`, `*.jira.com`, `*.bitbucket.org`, `*.atlassian-dev.net`,
`*.atlassian-3p.com`, and `www.teamworkgraph.com` / `teamworkgraph.com` ("Teamwork Graph uses these
domains"). Government Cloud uses separate `*.atlassian-us-gov-mod.*` domains. "Partner domains" are third
parties (CloudFront, Google, Sentry, Segment, `*.slack-edge.com` and others) [S1].

The page advises: "strongly consider excluding the Atlassian first-party domains from TLS
interception/inspection" [S1].

## 4. Encrypted-traffic caveats

- `<site>.atlassian.net` carries the customer's site name. The application is logged; the site label is
  an identifier and is never logged (AGENTS.md).
- `atlassian-dev.net` and `atlassian-3p.com`: first-party by Atlassian's statement, but the page does not
  say what they serve. If they host customers' or third parties' apps, they are tenant hosting. Not proposed.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `atlassian.net`, `atlassian.com`, `bitbucket.org`, `jira.com`, `atl-paas.net`, `ss-inf.net`, `teamworkgraph.com` | **N3** Atlassian | |
| `atlassian-dev.net`, `atlassian-3p.com` | **U** for purpose | Not mapped |
| Government Cloud domains | not proposed | Separate product scope |

## 6. Synthetic test vectors

Checked in scratch: all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `x.atl-paas.net`, `x.ss-inf.net`, `x.jira.com`, `www.teamworkgraph.com` | `atlassian` (today unmapped) |
| N1 | SNI `x.atlassian-3p.com` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J and K as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `api.atlassian.com` | one of `atlassian` | `atlassian` | PASS |
| O+ | `as.atlassian.com` | one of `atlassian` | `atlassian` | PASS |
| O+ | `id-frontend.prod-east.frontend.public.atl-paas.net` | one of `atlassian` | `atlassian` | PASS |
| O+ | `id.atlassian.com` | one of `atlassian` | `atlassian` | PASS |
| O+ | `xp.atlassian.com` | one of `atlassian` | `atlassian` | PASS |
| D- | `99a173f17960.d3c8cc30.eu-central-1.token.awswaf.com` | not atlassian (third party (unclassified)) | no application | PASS |
| D- | `accounts.google.com` | not atlassian (shared vendor infra) | `google-accounts` | PASS |
| D- | `fonts.gstatic.com` | not atlassian (shared vendor infra) | `google-base` | PASS |
| D- | `google.com` | not atlassian (shared vendor infra) | `google-base` | PASS |
| D- | `o55978.ingest.sentry.io` | not atlassian (third party) | `sentry` | PASS |
| D- | `www.gstatic.com` | not atlassian (shared vendor infra) | `google-base` | PASS |
| D- | `www.recaptcha.net` | not atlassian (third party (unclassified)) | no application | PASS |
| L- | `xatlassian.net` | not atlassian (label boundary) | no application | PASS |
| L- | `atlassian.net.example.invalid` | not atlassian (suffix look-alike) | no application | PASS |
| L- | `xatlassian.com` | not atlassian (label boundary) | no application | PASS |
| L- | `atlassian.com.example.invalid` | not atlassian (suffix look-alike) | no application | PASS |
| L- | `xbitbucket.org` | not atlassian (label boundary) | no application | PASS |
| L- | `bitbucket.org.example.invalid` | not atlassian (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Atlassian Support, "IP addresses and domains for Atlassian cloud apps",
  `https://support.atlassian.com/organization-administration/docs/ip-addresses-and-domains-for-atlassian-cloud-products/`, accessed 2026-11-18.

## 8. Catalog delta and recommendation

```python
("atlassian", "business-systems", "software-development", "browser-based", 2, "Atlassian cloud (Jira, Confluence, Bitbucket)",
 ("widely-used", "transfers-files"), ("atlassian.net", "atlassian.com", "bitbucket.org", "atl-paas.net", "ss-inf.net", "jira.com",
                                      "teamworkgraph.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `atlassian.net` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.atlassian.net`, no subject organisation (domain-validated) (issuer Amazon) |
| `atlassian.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.frontend.public.atl-paas.net`, no subject organisation (domain-validated) (issuer Amazon); HTTPS record offers `h3` (QUIC path) |
| `bitbucket.org` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.bitbucket.org`, no subject organisation (domain-validated) (issuer Amazon) |
| `atl-paas.net` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.atl-paas.net`, no subject organisation (domain-validated) (issuer Amazon) |
| `ss-inf.net` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `jira.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.atlassian.net`, no subject organisation (domain-validated) (issuer Amazon); HTTPS record offers `h3` (QUIC path) |
| `teamworkgraph.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.frontend.public.atl-paas.net`, no subject organisation (domain-validated) (issuer Amazon) |

## 10. Observed web-client hosts (dependency mapping)

- `https://id.atlassian.com/login`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP None (page.goto: Timeout 45000ms exceeded.), final host `id.atlassian.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `99a173f17960.d3c8cc30.eu-central-1.token.awswaf.com` | seen | third party (unclassified) | no application | not checked |  |
| `accounts.google.com` | seen | shared vendor infra | `google-accounts` |  |  |
| `api.atlassian.com` | seen | app-owned | `atlassian` | not checked |  |
| `as.atlassian.com` | seen | app-owned | `atlassian` | not checked |  |
| `fonts.gstatic.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `id-frontend.prod-east.frontend.public.atl-paas.net` | seen | app-owned | `atlassian` | not checked |  |
| `id.atlassian.com` | seen | app-owned | `atlassian` | not checked |  |
| `o55978.ingest.sentry.io` | seen | third party | `sentry` | not checked |  |
| `www.gstatic.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `www.recaptcha.net` | seen | third party (unclassified) | no application | not checked |  |
| `xp.atlassian.com` | seen | app-owned | `atlassian` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `atlassian`: business-systems / software-development, browser-based; characteristics `widely-used`, `transfers-files`; **risk 2**: widely used by enterprises; moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `99a173f17960.d3c8cc30.eu-central-1.token.awswaf.com`, `google-accounts`, `google-base`, `sentry`, `www.recaptcha.net`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `atlassian.com`, `jira.com`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
