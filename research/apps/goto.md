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

## 7. Sources

- [S1] GoTo Support, "Allowlisting and Firewall Configuration for GoTo Meeting", `https://support.goto.com/meeting/help/allowlisting-and-firewall-configuration`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("goto-meeting", ..., ("gotomeeting.com", "goto.com", "gotomeet.at", "gotomeet.me", "joingotomeeting.com", "openvoice.com")),
```

**DECISION for Hermes or the Engine lane:** keep `goto.com` in `goto-meeting` (current), or move it and the other universal domains to a vendor-level id (for example `goto`) so that remote-support traffic is not reported as meetings. The patch leaves `goto.com` where it is.
