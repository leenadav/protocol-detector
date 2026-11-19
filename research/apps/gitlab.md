# GitLab.com

- Content-pack id today: `gitlab` (`gitlab.com`)
- Status: **READY**, NAME, batch D
- Sources accessed: 2026-11-19

## 1. What it is

Hosted Git and DevOps platform.

## 2. Transport and ports

HTTPS and SSH: the page lists limits for "SSH fetches and clones" but no port numbers [S1].

## 3. Observable evidence

"Pages on GitLab.com load content from these hostnames": `*.gitlab-static.net`; container registry `registry.gitlab.com` with CDN `cdn.registry.gitlab-static.net` [S1]. GitLab Pages sites are customers' sites (tenant hosting) and are not mapped.

## 4. Encrypted-traffic caveats

`gitlab.io` (Pages) is tenant hosting, deliberately absent, as `github.io` is for GitHub.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `gitlab.com`, `gitlab-static.net` | **N3** |  |
| `gitlab.io` | do not map | Tenant hosting |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `x.gitlab-static.net` | `gitlab` |
| N1 | SNI `x.gitlab.io` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-19 against `c08773f` plus batches D to I and retrofit R)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `gitlab.com` | one of `gitlab` | `gitlab` | PASS |
| O+ | `new-sentry.gitlab.net` | one of `gitlab` | `gitlab` | PASS |
| O+ | `snowplowprd.trx.gitlab.net` | one of `gitlab` | `gitlab` | PASS |
| D- | `cdn.cookielaw.org` | not gitlab (third party) | no application | PASS |
| D- | `challenges.cloudflare.com` | not gitlab (third party) | no application | PASS |
| D- | `geolocation.onetrust.com` | not gitlab (third party) | no application | PASS |
| D- | `www.googletagmanager.com` | not gitlab (third party) | `google-analytics` | PASS |
| L- | `xgitlab.com` | not gitlab (label boundary) | no application | PASS |
| L- | `gitlab.com.example.invalid` | not gitlab (suffix look-alike) | no application | PASS |
| L- | `xgitlab-static.net` | not gitlab (label boundary) | no application | PASS |
| L- | `gitlab-static.net.example.invalid` | not gitlab (suffix look-alike) | no application | PASS |
| L- | `xgitlab.net` | not gitlab (label boundary) | no application | PASS |
| L- | `gitlab.net.example.invalid` | not gitlab (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] GitLab Docs, "GitLab.com settings", `https://docs.gitlab.com/user/gitlab_com/`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("gitlab", ..., ("gitlab.com", "gitlab-static.net")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

**BLOCKED in the research environment** (2026-11-19): its egress proxy re-terminates TLS, so a handshake would show the proxy, and direct DNS is not permitted. The tool is `research/tools/live_verify.py`; it runs from an unproxied vantage point or, DNS only, through an approved DoH resolver. No host below carries an `L` result yet.

Names to verify (catalog domains of `gitlab`): `gitlab.com`, `gitlab-static.net`, `gitlab.net`.

## 10. Observed web-client hosts (dependency mapping)

- `https://gitlab.com/users/sign_in`, loaded 2026-11-19 without signing in: HTTP 403, final host `gitlab.com`.

Pass 1 is a lower bound. The proxy refuses hosts not on the allowlist ("failed" below), so hosts that only scripts from a refused host would contact are missing.

| Host | Requests (refused) | Class | Attribution today | Note |
|---|---|---|---|---|
| `cdn.cookielaw.org` | 2 (2) | third party | no application | OneTrust consent banner |
| `challenges.cloudflare.com` | 1 (1) | third party | no application | Cloudflare Turnstile bot check |
| `geolocation.onetrust.com` | 1 (1) | third party | no application | OneTrust consent geolocation |
| `gitlab.com` | 53 (0) | app-owned | `gitlab` |  |
| `new-sentry.gitlab.net` | 1 (1) | app-owned | `gitlab` |  |
| `snowplowprd.trx.gitlab.net` | 1 (1) | app-owned | `gitlab` |  |
| `www.googletagmanager.com` | 1 (1) | third party | `google-analytics` |  |

## 11. Attributes (App-ID model) and re-verify date

- `gitlab`: business-systems / software-development, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `cdn.cookielaw.org`, `challenges.cloudflare.com`, `geolocation.onetrust.com`, `google-analytics`.
- Evasive (ECH, DoH, proxy modes): ECH support unknown until a live HTTPS-record check (section 9); other modes as stated in sections 2 to 4.
- Re-verify by: **2027-02-17** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
