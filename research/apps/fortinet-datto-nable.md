# Fortinet, Datto RMM, N-able (not researched)

- Content-pack id today: none for any of the three
- Status: **BLOCKED**, NAME, low priority
- Sources: attempted 2026-11-19

## 1. What it is

FortiClient and FortiGuard (Fortinet), Datto RMM (Kaseya), N-able RMM.

## 2. Transport and ports

Not assessed.

## 3. Observable evidence

`docs.fortinet.com` loads, but this lane did not locate a FortiClient or FortiGuard server-name page through it (the site needs its JavaScript search). The Datto RMM allow-list URL this lane tried (`https://rmm.datto.com/help/en/Content/1INTRODUCTION/Requirements/AllowList.htm`) returns 404. `documentation.n-able.com` returns 403.

## 4. Encrypted-traffic caveats

Not assessed.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| Any name | **U** | No source read |

## 6. Synthetic test vectors

None (no catalog change).


## 7. Sources

- Attempts only, 2026-11-19; no content read.

## 8. Catalog delta and recommendation

None. Next: exact article URLs for each, which would go in `blocked-urls.md`.
