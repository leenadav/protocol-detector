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

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R and L)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xdocker.com` | not docker-hub (label boundary) | no application | PASS |
| L- | `docker.com.example.invalid` | not docker-hub (suffix look-alike) | no application | PASS |
| L- | `xdocker.io` | not docker-hub (label boundary) | no application | PASS |
| L- | `docker.io.example.invalid` | not docker-hub (suffix look-alike) | no application | PASS |
| L- | `xdhi.io` | not docker-hub (label boundary) | no application | PASS |
| L- | `dhi.io.example.invalid` | not docker-hub (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Docker Docs, "Allowlist for Docker Desktop", `https://docs.docker.com/desktop/enterprise/allow-list.md` (the `/desktop/setup/allow-list/` page redirects there), accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("docker-hub", ..., ("docker.com", "docker.io", "dhi.io")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `docker.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `docker.com` (SAN covers name: True) |
| `docker.io` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.docker.com` (SAN covers name: True) |
| `dhi.io` | **L** resolves; TLSv1.3, ALPN `h2`, cert `dhi.io` (SAN covers name: True) |

## 10. Observed web-client hosts (dependency mapping)

- `https://hub.docker.com/`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

## 11. Attributes (App-ID model) and re-verify date

- `docker-hub`: business-systems / software-development, client-server; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
