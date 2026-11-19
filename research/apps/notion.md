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

### Method v2 vectors (checked 2026-11-19 against `c08773f` plus batches D to I and retrofit R)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
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

**BLOCKED in the research environment** (2026-11-19): its egress proxy re-terminates TLS, so a handshake would show the proxy, and direct DNS is not permitted. The tool is `research/tools/live_verify.py`; it runs from an unproxied vantage point or, DNS only, through an approved DoH resolver. No host below carries an `L` result yet.

Names to verify (catalog domains of `notion`): `notion.so`, `notion.site`, `notion.com`, `notionusercontent.com`, `secure.notion-static.com`.

## 10. Observed web-client hosts (dependency mapping)

- `https://www.notion.so/login`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

## 11. Attributes (App-ID model) and re-verify date

- `notion`: business-systems / office-programs, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): ECH support unknown until a live HTTPS-record check (section 9); other modes as stated in sections 2 to 4.
- Re-verify by: **2027-02-17** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
