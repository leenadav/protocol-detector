# Chrome Remote Desktop

- Content-pack id today: `chrome-remote-desktop` (`remotedesktop.google.com`)
- Status: **READY**, NAME, batch E (`research/patches/batch-e-name-based.patch`)
- Sources accessed: 2026-11-19

## 1. What it is

Google's browser-based remote access and remote support.

## 2. Transport and ports

"443 + 3478", "TCP + UDP". A dynamic UDP range can be limited with the `RemoteAccessHostUdpPortRange` policy.
STUN and TURN use 3478, and "UDP is preferred over TCP due to superior performance. Chrome Remote Desktop will
fallback to TCP if UDP is blocked" [S1].

## 3. Observable evidence

Domains to allow [S1]: `instantmessaging-pa.googleapis.com`, `remotedesktop.google.com`,
`remotedesktop-pa.googleapis.com`.

## 4. Encrypted-traffic caveats

Session media goes over UDP or TCP on dynamic ports to Google addresses ("IP addresses are dynamic depending on
location") [S1], so it is not visible by name. `instantmessaging-pa.googleapis.com` is not proposed: the page does
not say it is exclusive to Chrome Remote Desktop, and the name suggests a shared Google messaging API (`UNVERIFIED`).

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI `remotedesktop.google.com` | **N3** | Already mapped |
| SNI `remotedesktop-pa.googleapis.com` | **N3** (exact host) | On shared `googleapis.com`; only this exact name |
| `instantmessaging-pa.googleapis.com` | **N1** | Not mapped |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C, D and E).

| # | Input | Expected |
|---|---|---|
| P1 | SNI `remotedesktop-pa.googleapis.com` | `chrome-remote-desktop` (today `google-base`) |
| P2 | SNI `remotedesktop.google.com` | `chrome-remote-desktop` |
| N1 | SNI `instantmessaging-pa.googleapis.com` | `google-base` |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O, P and Q as rebuilt 2026-11-24)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `remotedesktop.google.com` | one of `chrome-remote-desktop` | `chrome-remote-desktop` | PASS |
| D- | `fonts.gstatic.com` | not chrome-remote-desktop (shared vendor infra) | `google-base` | PASS |
| D- | `ogads-pa.clients6.google.com` | not chrome-remote-desktop (shared vendor infra) | `google-base` | PASS |
| D- | `play.google.com` | not chrome-remote-desktop (shared vendor infra) | `google-base` | PASS |
| D- | `ssl.gstatic.com` | not chrome-remote-desktop (shared vendor infra) | `google-base` | PASS |
| D- | `www.gstatic.com` | not chrome-remote-desktop (shared vendor infra) | `google-base` | PASS |
| L- | `xgoogle.com` | not chrome-remote-desktop (label boundary) | no application | PASS |
| L- | `remotedesktop.google.com.example.invalid` | not chrome-remote-desktop (suffix look-alike) | no application | PASS |
| L- | `xgoogleapis.com` | not chrome-remote-desktop (label boundary) | no application | PASS |
| L- | `remotedesktop-pa.googleapis.com.example.invalid` | not chrome-remote-desktop (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Chrome Enterprise and Education Help, "Network guide for Chrome Remote Desktop",
  `https://support.google.com/chrome/a/answer/16364503?hl=en`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

```python
("chrome-remote-desktop", ..., ("remotedesktop.google.com", "remotedesktop-pa.googleapis.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `remotedesktop.google.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.google.com`, no subject organisation (domain-validated) (issuer Google Trust Services); CNAME into shared front end `www3.l.google.com`: name usable, IPs never |
| `remotedesktop-pa.googleapis.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `upload.video.google.com`, no subject organisation (domain-validated) (issuer Google Trust Services) |

## 10. Observed web-client hosts (dependency mapping)

- `https://remotedesktop.google.com/`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `remotedesktop.google.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `fonts.gstatic.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `ogads-pa.clients6.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `play.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `remotedesktop.google.com` | seen | app-owned | `chrome-remote-desktop` | cdn |  |
| `ssl.gstatic.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `www.gstatic.com` | seen | shared vendor infra | `google-base` | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `chrome-remote-desktop`: networking / remote-access, browser-based; characteristics `tunnels-other-applications`, `prone-to-misuse`; **risk 4**: carries other traffic or remote control; commonly misused (unsanctioned remote access, data exfiltration).
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `google-base`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
