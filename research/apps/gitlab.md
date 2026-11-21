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

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K and M as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `gitlab.com` | one of `gitlab` | `gitlab` | PASS |
| D- | `challenges.cloudflare.com` | not gitlab (third party) | no application | PASS |
| D- | `hagen.challenges.cloudflare.com` | not gitlab (third party (unclassified)) | no application | PASS |
| L- | `xgitlab.com` | not gitlab (label boundary) | no application | PASS |
| L- | `gitlab.com.example.invalid` | not gitlab (suffix look-alike) | no application | PASS |
| L- | `xgitlab-static.net` | not gitlab (label boundary) | no application | PASS |
| L- | `gitlab-static.net.example.invalid` | not gitlab (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] GitLab Docs, "GitLab.com settings", `https://docs.gitlab.com/user/gitlab_com/`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("gitlab", ..., ("gitlab.com", "gitlab-static.net")),
```

**Patch R decision (2026-11-21, live round 2):** `gitlab.net` is **not** added. `new-sentry.gitlab.net` and `snowplowprd.trx.gitlab.net` serve domain-validated certificates (no subject organisation, 1 SAN each), so ownership is not shown (decision 3). Both stay unmapped until a GitLab document names `gitlab.net`.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and round 4 of 2026-11-21 where it has the name (`research/live-results-2026-11-21-r4.tsv`, partial relay; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `gitlab.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `gitlab.com`, no subject organisation (domain-validated) (issuer Sectigo Limited) |
| `gitlab-static.net` | apex has no address (normal for a suffix entry); suffix **verified** through documented `cdn.registry.gitlab-static.net` (round 2) |

## 10. Observed web-client hosts (dependency mapping)

- `https://gitlab.com/users/sign_in`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP None (page.goto: Timeout 45000ms exceeded.), final host `gitlab.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `challenges.cloudflare.com` | seen | third party | no application | not checked | Cloudflare Turnstile bot check |
| `gitlab.com` | seen | app-owned | `gitlab` |  |  |
| `hagen.challenges.cloudflare.com` | seen | third party (unclassified) | no application | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `gitlab`: business-systems / software-development, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `challenges.cloudflare.com`, `hagen.challenges.cloudflare.com`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
