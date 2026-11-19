# Docker Hub and Docker Desktop

- Content-pack id today: `docker-hub` (`docker.com`, `docker.io`)
- Status: **READY**, NAME, batch D
- Sources accessed: 2026-11-19

## 1. What it is

Container registry and the Docker Desktop client.

## 2. Transport and ports

HTTPS [S1].

## 3. Observable evidence

Allowlist table [S1]: `auth.docker.io`, `login.docker.com`, `auth.docker.com`, `desktop.docker.com`, `hub.docker.com`, `registry-1.docker.io`, `production.cloudfront.docker.com`, `api.dso.docker.com`, `api.docker.com`, `api.offload.docker.com`, `api.sandboxes-cloud.docker.com`, `dhi.io` ("Docker Hardened Images"), `registry.scout.docker.com`, `ai-backend-service.docker.com`; third parties (Bugsnag, Auth0, an S3 bucket for troubleshooting).

## 4. Encrypted-traffic caveats

Image layers can be served from CDN hosts; `production.cloudfront.docker.com` is under `docker.com` and is already covered.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `docker.com`, `docker.io`, `dhi.io` | **N3** |  |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `dhi.io` | `docker-hub` (today unmapped) |
| P2 | SNI `registry-1.docker.io` | `docker-hub` |

## 7. Sources

- [S1] Docker Docs, "Allowlist for Docker Desktop", `https://docs.docker.com/desktop/enterprise/allow-list.md` (the `/desktop/setup/allow-list/` page redirects there), accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("docker-hub", ..., ("docker.com", "docker.io", "dhi.io")),
```
