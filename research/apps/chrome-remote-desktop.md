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

## 7. Sources

- [S1] Chrome Enterprise and Education Help, "Network guide for Chrome Remote Desktop",
  `https://support.google.com/chrome/a/answer/16364503?hl=en`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

```python
("chrome-remote-desktop", ..., ("remotedesktop.google.com", "remotedesktop-pa.googleapis.com")),
```
