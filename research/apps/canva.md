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

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M and N as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `status.canva.com` | one of `canva` | `canva` | PASS |
| O+ | `www.canva.com` | one of `canva` | `canva` | PASS |
| D- | `challenges.cloudflare.com` | not canva (third party) | no application | PASS |
| D- | `hagen.challenges.cloudflare.com` | not canva (third party (unclassified)) | no application | PASS |
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

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 5 of 2026-11-21 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `canva.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `canva.com`, no subject organisation (domain-validated) (issuer Amazon) |
| `canvacode.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `canvacode.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |
| `canva-apps.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `canva.link` | **L** resolves; TLSv1.3, ALPN `h2`, cert `canva.link`, no subject organisation (domain-validated) (issuer Google Trust Services); HTTPS record offers `h3` (QUIC path) |
| `canva.ai` | **L** resolves; TLSv1.3, ALPN `h2`, cert `canva.ai`, no subject organisation (domain-validated) (issuer Google Trust Services) |

## 10. Observed web-client hosts (dependency mapping)

- `https://www.canva.com/login`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP None (page.goto: Timeout 45000ms exceeded.), final host `www.canva.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `challenges.cloudflare.com` | seen | third party | no application | not checked | Cloudflare Turnstile bot check |
| `hagen.challenges.cloudflare.com` | seen | third party (unclassified) | no application | not checked |  |
| `status.canva.com` | seen | app-owned | `canva` | cdn |  |
| `www.canva.com` | seen | app-owned | `canva` | cdn |  |

## 11. Attributes (App-ID model) and re-verify date

- `canva`: business-systems / office-programs, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `challenges.cloudflare.com`, `hagen.challenges.cloudflare.com`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): `canva.link`.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
