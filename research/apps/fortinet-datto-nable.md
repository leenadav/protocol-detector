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


<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R and L)

No catalog id: none.

<!-- method-v2-vectors:end -->

## 7. Sources

- Attempts only, 2026-11-19; no content read.

## 8. Catalog delta and recommendation

None. Next: exact article URLs for each, which would go in `blocked-urls.md`.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

No catalog names.

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- No catalog entry.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
