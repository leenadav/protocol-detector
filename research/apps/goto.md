# GoTo (GoTo Meeting and family)

- Content-pack id today: `goto-meeting` (`gotomeeting.com`, `goto.com`), `gotomypc`, `logmein`
- Status: **READY**, NAME, batch D (meeting-specific domains). **DECISION** pending on `goto.com` attribution
- Sources accessed: 2026-11-19

## 1. What it is

GoTo's meeting, webinar, remote-support and remote-access products.

## 2. Transport and ports

"Outbound TCP 443 Required, used by all products. Needs to support WebSocket connections over HTTPS"; TCP 80; UDP 8200 and 1853 (VoIP and in-session); TCP/UDP 3478 (TURN); others for rooms and telepresence [S1].

## 3. Observable evidence

"Universally required domains", described as "used by multiple GoTo products": `*.accounts.logme.in`, `*app.goto.com`, `*.cdngetgo.com`, `*.expertcity.com`, `*.getgo.com`, `*.getgocdn.com`, `*.getgoservices.com`, `*.getgoservices.net`, `*.goto.com`, `*.goto.eu`, `*.gotoinc.com`, `*.goto-rtc.com`, `*.logmein.com`, `*.logmeininc.com`, `*logmein.eu`; "GoTo Meeting-specific domains": `*.gotomeet.at`, `*.gotomeet.me`, `*.gotomeeting.com`, `*.joingotomeeting.com`, `*.openvoice.com` [S1].

## 4. Encrypted-traffic caveats

**Attribution risk:** the pack maps `goto.com` to `goto-meeting`, but GoTo describes it as "Product domain used by multiple GoTo products" [S1], including remote support and access. Traffic of GoTo Resolve or LogMeIn products on `goto.com` is therefore logged as GoTo Meeting.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| Meeting-specific domains | **N3** GoTo Meeting |  |
| `goto.com`, `getgo.com` and other universal domains | **N2** GoTo (vendor) | Not product-specific |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `global.gotomeet.me`, `x.openvoice.com` | `goto-meeting` |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L and J)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `app.goto.com` | one of `goto-meeting`, `gotomypc`, `logmein` | `goto-meeting` | PASS |
| O+ | `app.gotomeeting.com` | one of `goto-meeting`, `gotomypc`, `logmein` | `goto-meeting` | PASS |
| O+ | `chameleon.goto.com` | one of `goto-meeting`, `gotomypc`, `logmein` | `goto-meeting` | PASS |
| O+ | `conferences.goto.com` | one of `goto-meeting`, `gotomypc`, `logmein` | `goto-meeting` | PASS |
| O+ | `content.ipd.goto.com` | one of `goto-meeting`, `gotomypc`, `logmein` | `goto-meeting` | PASS |
| D- | `api.jive.com` | not goto-meeting/gotomypc/logmein (shared vendor infra (unmapped)) | no application | PASS |
| D- | `cdn.userreport.com` | not goto-meeting/gotomypc/logmein (third party) | no application | PASS |
| D- | `logging.getgo.com` | not goto-meeting/gotomypc/logmein (shared vendor infra (unmapped)) | no application | PASS |
| D- | `res.cdn.office.net` | not goto-meeting/gotomypc/logmein (shared vendor infra) | `ms-base` | PASS |
| D- | `zn39psorncmg7xc7k-logmeinvoc.siteintercept.qualtrics.com` | not goto-meeting/gotomypc/logmein (third party) | no application | PASS |
| L- | `xgotomeeting.com` | not goto-meeting/gotomypc/logmein (label boundary) | no application | PASS |
| L- | `gotomeeting.com.example.invalid` | not goto-meeting/gotomypc/logmein (suffix look-alike) | no application | PASS |
| L- | `xgoto.com` | not goto-meeting/gotomypc/logmein (label boundary) | no application | PASS |
| L- | `goto.com.example.invalid` | not goto-meeting/gotomypc/logmein (suffix look-alike) | no application | PASS |
| L- | `xgotomeet.at` | not goto-meeting/gotomypc/logmein (label boundary) | no application | PASS |
| L- | `gotomeet.at.example.invalid` | not goto-meeting/gotomypc/logmein (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] GoTo Support, "Allowlisting and Firewall Configuration for GoTo Meeting", `https://support.goto.com/meeting/help/allowlisting-and-firewall-configuration`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("goto-meeting", ..., ("gotomeeting.com", "goto.com", "gotomeet.at", "gotomeet.me", "joingotomeeting.com", "openvoice.com")),
```

**DECISION for Hermes or the Engine lane:** keep `goto.com` in `goto-meeting` (current), or move it and the other universal domains to a vendor-level id (for example `goto`) so that remote-support traffic is not reported as meetings. The patch leaves `goto.com` where it is.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20 (`research/live-results-2026-11-20.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `gotomeeting.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `www.gotomeeting.com` (SAN covers name: True) |
| `goto.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.goto.com` (SAN covers name: True) |
| `gotomeet.at` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `gotomeet.me` | **L** resolves; TLSv1.3, ALPN `h2`, cert `meet.goto.com` (SAN covers name: True) |
| `joingotomeeting.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `joingotomeeting.com` (SAN covers name: True) |
| `openvoice.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `www.gotomeeting.com` (SAN covers name: True) |
| `gotomypc.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `gotomypc.com` (SAN covers name: True) |
| `logmein.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `logmein.com` (SAN covers name: True) |
| `logmeininc.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `logmeininc.com` (SAN covers name: True) |

## 10. Observed web-client hosts (dependency mapping)

- `https://app.goto.com/`, loaded 2026-11-19 without signing in: HTTP 200, final host `app.goto.com`.

Pass 1 is a lower bound. The proxy refuses hosts not on the allowlist ("failed" below), so hosts that only scripts from a refused host would contact are missing.

| Host | Requests (refused) | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `api.jive.com` | 3 (3) | shared vendor infra (unmapped) | no application | not checked | GoTo Connect API (jive.com), a separate GoTo product |
| `app.goto.com` | 50 (0) | app-owned | `goto-meeting` |  |  |
| `app.gotomeeting.com` | 1 (1) | app-owned | `goto-meeting` |  |  |
| `cdn.userreport.com` | 1 (1) | third party | no application | not checked | UserReport survey widget |
| `chameleon.goto.com` | 1 (1) | app-owned | `goto-meeting` |  |  |
| `conferences.goto.com` | 2 (2) | app-owned | `goto-meeting` |  |  |
| `content.ipd.goto.com` | 1 (1) | app-owned | `goto-meeting` |  |  |
| `logging.getgo.com` | 4 (4) | shared vendor infra (unmapped) | no application | not checked | GoTo logging (getgo.com; for the Engine lane's goto vendor id) |
| `res.cdn.office.net` | 3 (3) | shared vendor infra | `ms-base` | cdn,h3 |  |
| `zn39psorncmg7xc7k-logmeinvoc.siteintercept.qualtrics.com` | 1 (1) | third party | no application | not checked | Qualtrics survey (customer-named) |

## 11. Attributes (App-ID model) and re-verify date

- `goto-meeting`: collaboration / voip-video, client-server; characteristics `excessive-bandwidth`; **risk 2**: high bandwidth.
- `gotomypc`: networking / remote-access, client-server; characteristics `tunnels-other-applications`, `prone-to-misuse`; **risk 4**: carries other traffic or remote control; commonly misused (unsanctioned remote access, data exfiltration).
- `logmein`: networking / remote-access, client-server; characteristics `tunnels-other-applications`, `prone-to-misuse`; **risk 4**: carries other traffic or remote control; commonly misused (unsanctioned remote access, data exfiltration).
- Functions separated by name: `goto-meeting` (GoTo Meeting), `gotomypc` (GoToMyPC remote access), `logmein` (LogMeIn remote access).
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `cdn.userreport.com`, `ms-base`, `zn39psorncmg7xc7k-logmeinvoc.siteintercept.qualtrics.com`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
