# Signal

- Content-pack id today: `signal` (`signal.org`, `signal.art`, `whispersystems.org`)
- Status: **READY**, NAME, batch G (`research/patches/batch-g-name-based.patch`)
- Sources: read by Hermes, relayed, 2026-11-19; the page shows no date

## 1. What it is

End-to-end encrypted messaging and calls.

## 2. Transport and ports

"Allow traffic to and from *.signal.org on TCP port 443 and all UDP ports". A proxy "needs to support WebSockets". Signal "uses a non-standard TCP port to catch filtering issues at the signaling step and also utilizes a random UDP port". Group calls: "TCP 443, UDP 10000"; 1:1 calls: "TCP 443 only" required, "TCP 443, UDP 3478" recommended for relay only, "TCP 443, all UDP" recommended. "Other ports may be used if they are available." [S1]

## 3. Observable evidence

`*.signal.org`, plus "other domains to support sharing group links, sticker packs, usernames, etc.": `signal.art`, `signal.group`, `signal.link`, `signal.me`, `signal.tube`. Calling hosts `turn3.voip.signal.org` and `sfu.voip.signal.org` are named and "subject to change at anytime" [S1].

## 4. Encrypted-traffic caveats

Call media on UDP (10000, 3478 or random ports) carries no server name, so calls are visible by name only through their TCP 443 signalling. The relayed page says nothing about censorship-circumvention proxies; a separate "Proxy Support" article is linked but was not relayed (`UNVERIFIED`). `whispersystems.org` stays in the catalog but is not on this page (not re-verified; no removal proposed).

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `signal.org` | **N3** |  |
| SNI under `signal.art`, `signal.group`, `signal.link`, `signal.me`, `signal.tube` | **N3** | Link and sticker hosts: a browser opening a shared link also matches |
| UDP call media | **U** | No name |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D, E, F and G): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `chat.signal.org`, `sfu.voip.signal.org` | `signal` |
| P2 | SNI `signal.group`, `x.signal.link`, `signal.me`, `signal.tube` | `signal` (today unmapped) |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-19 against `c08773f` plus batches D to I and retrofit R)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xsignal.org` | not signal (label boundary) | no application | PASS |
| L- | `signal.org.example.invalid` | not signal (suffix look-alike) | no application | PASS |
| L- | `xsignal.art` | not signal (label boundary) | no application | PASS |
| L- | `signal.art.example.invalid` | not signal (suffix look-alike) | no application | PASS |
| L- | `xwhispersystems.org` | not signal (label boundary) | no application | PASS |
| L- | `whispersystems.org.example.invalid` | not signal (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Signal Support, "Firewall and Internet settings", `https://support.signal.org/hc/en-us/articles/360007320291-Firewall-and-Internet-settings`, read by Hermes, relayed, 2026-11-19.

## 8. Catalog delta and recommendation

```python
("signal", ..., ("signal.org", "signal.art", "whispersystems.org", "signal.group", "signal.link", "signal.me", "signal.tube")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

**BLOCKED in the research environment** (2026-11-19): its egress proxy re-terminates TLS, so a handshake would show the proxy, and direct DNS is not permitted. The tool is `research/tools/live_verify.py`; it runs from an unproxied vantage point or, DNS only, through an approved DoH resolver. No host below carries an `L` result yet.

Names to verify (catalog domains of `signal`): `signal.org`, `signal.art`, `whispersystems.org`, `signal.group`, `signal.link`, `signal.me`, `signal.tube`.

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `signal`: collaboration / instant-messaging, client-server; characteristics `transfers-files`, `evasive`; **risk 3**: moves files out of the organisation; designed to avoid inspection (relays, proxies or circumvention modes).
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): ECH support unknown until a live HTTPS-record check (section 9); other modes as stated in sections 2 to 4.
- Re-verify by: **2027-02-17** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
