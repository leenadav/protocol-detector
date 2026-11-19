# Canva

- Content-pack id today: `canva` (`canva.com`)
- Status: **READY**, NAME, batch G (`research/patches/batch-g-name-based.patch`)
- Sources: read by Hermes, relayed, 2026-11-19; the page shows no date

## 1. What it is

Online design platform.

## 2. Transport and ports

HTTPS; "Make sure WebSockets are enabled for: www.canva.com:443" [S1].

## 3. Observable evidence

"Make sure your firewall allows these Canva domains" [S1]: `*.canva.com` (all subdomains), `*.canvacode.com` ("Required for some Canva AI features"), `*.canva-apps.com` ("Required to use Canva Apps"), `challenges.cloudflare.com` ("Required for Cloudflare security check"), `*.canva.link` ("design share links"), `*.canva.ai` ("Canva AI features"). "Some Canva Apps use additional third-party domains."

## 4. Encrypted-traffic caveats

`challenges.cloudflare.com` is Cloudflare's shared challenge service and is not proposed. `canva-apps.com` hosts apps on Canva's platform, some of them by third parties; it is still Canva's own domain.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `canva.com` | **N3** | Already mapped |
| SNI under `canvacode.com`, `canva-apps.com`, `canva.link`, `canva.ai` | **N3** | Share links also match when opened by a browser |
| `challenges.cloudflare.com` | not Canva | Shared |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D, E, F and G): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `www.canva.com` | `canva` |
| P2 | SNI `x.canvacode.com`, `x.canva-apps.com`, `canva.link`, `canva.ai` | `canva` (today unmapped) |
| N1 | SNI `challenges.cloudflare.com` | unmapped |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-19 against `c08773f` plus batches D to I and retrofit R)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `status.canva.com` | one of `canva` | `canva` | PASS |
| O+ | `www.canva.com` | one of `canva` | `canva` | PASS |
| D- | `challenges.cloudflare.com` | not canva (third party) | no application | PASS |
| L- | `xcanva.com` | not canva (label boundary) | no application | PASS |
| L- | `canva.com.example.invalid` | not canva (suffix look-alike) | no application | PASS |
| L- | `xcanvacode.com` | not canva (label boundary) | no application | PASS |
| L- | `canvacode.com.example.invalid` | not canva (suffix look-alike) | no application | PASS |
| L- | `xcanva-apps.com` | not canva (label boundary) | no application | PASS |
| L- | `canva-apps.com.example.invalid` | not canva (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Canva Help Center, "Allow Canva through your firewall", `https://www.canva.com/help/allow-canva-through-firewall/`, read by Hermes, relayed, 2026-11-19.

## 8. Catalog delta and recommendation

```python
("canva", ..., ("canva.com", "canvacode.com", "canva-apps.com", "canva.link", "canva.ai")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

**BLOCKED in the research environment** (2026-11-19): its egress proxy re-terminates TLS, so a handshake would show the proxy, and direct DNS is not permitted. The tool is `research/tools/live_verify.py`; it runs from an unproxied vantage point or, DNS only, through an approved DoH resolver. No host below carries an `L` result yet.

Names to verify (catalog domains of `canva`): `canva.com`, `canvacode.com`, `canva-apps.com`, `canva.link`, `canva.ai`.

## 10. Observed web-client hosts (dependency mapping)

- `https://www.canva.com/login`, loaded 2026-11-19 without signing in: HTTP None (page.goto: Timeout 45000ms exceeded.), final host `www.canva.com`.

Pass 1 is a lower bound. The proxy refuses hosts not on the allowlist ("failed" below), so hosts that only scripts from a refused host would contact are missing.

| Host | Requests (refused) | Class | Attribution today | Note |
|---|---|---|---|---|
| `challenges.cloudflare.com` | 3 (3) | third party | no application | Cloudflare Turnstile bot check |
| `status.canva.com` | 4 (4) | app-owned | `canva` |  |
| `www.canva.com` | 15 (0) | app-owned | `canva` |  |

## 11. Attributes (App-ID model) and re-verify date

- `canva`: business-systems / office-programs, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `challenges.cloudflare.com`.
- Evasive (ECH, DoH, proxy modes): ECH support unknown until a live HTTPS-record check (section 9); other modes as stated in sections 2 to 4.
- Re-verify by: **2027-02-17** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
