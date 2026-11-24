# ConnectWise ScreenConnect

- Content-pack id today: `connectwise-control` (`screenconnect.com`, `connectwise.com`; web fronts apex and `www` of `screenconnect.com`)
- Status: **PARTIAL**, NAME. Low priority; research continues when the source is reachable
- Sources accessed: 2026-11-18

## 1. What it is

ConnectWise ScreenConnect. See the catalog entry for its category.

## 2. Transport and ports

`UNVERIFIED`: the primary source could not be read.

## 3. Observable evidence

No official ConnectWise page listing ScreenConnect Cloud firewall hosts was found. An on-premises page about relay addresses exists on docs.connectwise.com, but this lane has not read it, so nothing from it is stated here.

## 4. Encrypted-traffic caveats

Not assessed beyond the README's shared facts.

## 5. Confidence and false-positive risks

| Observable | Level |
|---|---|
| Current pack names | **U** (not verified by this lane) |

## 6. Synthetic test vectors

Pending a readable source.

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O, P and Q as rebuilt 2026-11-24)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xscreenconnect.com` | not connectwise-control (label boundary) | no application | PASS |
| L- | `screenconnect.com.example.invalid` | not connectwise-control (suffix look-alike) | no application | PASS |
| L- | `xconnectwise.com` | not connectwise-control (label boundary) | no application | PASS |
| L- | `connectwise.com.example.invalid` | not connectwise-control (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- none read

## 8. Catalog delta and recommendation

None. Next: Find an official ScreenConnect Cloud allowlist; otherwise leave the names as they are.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `screenconnect.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `screenconnect.com`, no subject organisation (domain-validated) (issuer Amazon) |
| `connectwise.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `connectwise.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `connectwise-control`: networking / remote-access, client-server; characteristics `tunnels-other-applications`, `prone-to-misuse`, `used-by-malware`; **risk 4**: carries other traffic or remote control; commonly misused (unsanctioned remote access, data exfiltration); seen in malware campaigns.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
