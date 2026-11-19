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

### Method v2 vectors (checked 2026-11-19 against `c08773f` plus batches D to I and retrofit R)

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

**BLOCKED in the research environment** (2026-11-19): its egress proxy re-terminates TLS, so a handshake would show the proxy, and direct DNS is not permitted. The tool is `research/tools/live_verify.py`; it runs from an unproxied vantage point or, DNS only, through an approved DoH resolver. No host below carries an `L` result yet.

Names to verify (catalog domains of `connectwise-control`): `screenconnect.com`, `connectwise.com`.

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `connectwise-control`: networking / remote-access, client-server; characteristics `tunnels-other-applications`, `prone-to-misuse`, `used-by-malware`; **risk 4**: carries other traffic or remote control; commonly misused (unsanctioned remote access, data exfiltration); seen in malware campaigns.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): ECH support unknown until a live HTTPS-record check (section 9); other modes as stated in sections 2 to 4.
- Re-verify by: **2027-02-17** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
