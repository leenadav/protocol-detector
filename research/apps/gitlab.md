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

## 7. Sources

- [S1] GitLab Docs, "GitLab.com settings", `https://docs.gitlab.com/user/gitlab_com/`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("gitlab", ..., ("gitlab.com", "gitlab-static.net")),
```
