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

## 7. Sources

- [S1] Signal Support, "Firewall and Internet settings", `https://support.signal.org/hc/en-us/articles/360007320291-Firewall-and-Internet-settings`, read by Hermes, relayed, 2026-11-19.

## 8. Catalog delta and recommendation

```python
("signal", ..., ("signal.org", "signal.art", "whispersystems.org", "signal.group", "signal.link", "signal.me", "signal.tube")),
```
