# Apple Business, Apple School Manager and device enrollment

- Content-pack id today: none (today `apple-base` by suffix)
- Status: **READY**, NAME, batch M: new id `apple-device-management`
- Sources: [AP] read in the research cloud (egress proxy), 2026-11-21; no page date shown

## 1. What it is

Apple's organisational device services: Automated Device Enrollment, the Apple Business and Apple School Manager portals and APIs, Apps and Books licensing, and Apple Business's own device management. Third-party MDM servers (Jamf, Intune) use them.

## 2. Transport and ports

443/TCP for every name below; `*.business.apple.com` and `*.school.apple.com` also 80/TCP; APNs (`*.push.apple.com`) on 443, 80, 5223 and 2197 [AP].

## 3. Observable evidence

[AP] device management: `deviceenrollment.apple.com` ("DEP provisional enrollment"), `deviceservices-external.apple.com` (Activation Lock), `gdmf.apple.com` (managed software updates), `identity.apple.com` ("APNs certificate request portal"), `iprofiles.apple.com`, `mdmenrollment.apple.com` (enrollment profiles), `setup.icloud.com` (Shared iPad), `vpp.itunes.apple.com` (Apps and Books), `*.appattest.apple.com` (attestation), `axm-servicediscovery.apple.com` (account-driven enrollment). Portals: `*.business.apple.com`, `*.school.apple.com`; APIs `api-business.apple.com`, `api-school.apple.com`. Apple Business device management: `axm-adm-enroll.apple.com`, `axm-adm-mdm.apple.com`, `axm-adm-scep.apple.com`, `axm-app.apple.com`, `*.apple-mapkit.com` (Lost Mode), `icons.axm-usercontent-apple.com`. Classroom: `ws.school.apple.com`.

## 4. Encrypted-traffic caveats

Today every `apple.com` name falls to `apple-base` (and `vpp.itunes.apple.com` to `apple-app-store`). The proposal lists exact names, never `apple.com` subtrees beyond the two portal suffixes. Not proposed: `gdmf.apple.com` (also used by ordinary software updates on the same page), `setup.icloud.com` (iCloud), `*.appattest.apple.com` and `*.apple-mapkit.com` (general Apple services), APNs (`apple-push`). `ws.school.apple.com` (Classroom roster) falls under `school.apple.com`, which is acceptable: it is an Apple School service. Devices reach these names during enrollment and management, so a match means organisational management activity, not a user choice (risk 1, as `ms-intune` and `jamf-pro`).

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| Exact enrollment and management names | **N3** (exact) | Device-originated |
| SNI under `business.apple.com`, `school.apple.com` | **N3** | Portals |
| Exact `identity.apple.com`, `vpp.itunes.apple.com` | **N2** (exact) | Admin and licensing |
| `gdmf`, `appattest`, MapKit, APNs | other ids | Shared Apple services |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K and M): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `mdmenrollment.apple.com`, `deviceenrollment.apple.com`, `axm-adm-mdm.apple.com` | `apple-device-management` (today `apple-base`) |
| P2 | SNI `x.business.apple.com`, `icons.axm-usercontent-apple.com`, `vpp.itunes.apple.com` | `apple-device-management` |
| N1 | SNI `gdmf.apple.com`, `itunes.apple.com`, `xaxm-usercontent-apple.com` | not `apple-device-management` |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K and M as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xapple.com` | not apple-device-management (label boundary) | no application | PASS |
| L- | `deviceenrollment.apple.com.example.invalid` | not apple-device-management (suffix look-alike) | no application | PASS |
| L- | `deviceservices-external.apple.com.example.invalid` | not apple-device-management (suffix look-alike) | no application | PASS |
| L- | `iprofiles.apple.com.example.invalid` | not apple-device-management (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [AP] Apple Support, "Use Apple products on enterprise networks", `https://support.apple.com/en-us/101555`, read in the research cloud (egress proxy), 2026-11-21.

## 8. Catalog delta and recommendation

```python
("apple-device-management", "business-systems", "management", "client-server", 1,
 "Apple Business, Apple School Manager and device enrollment services", ("widely-used",),
 ("deviceenrollment.apple.com", "deviceservices-external.apple.com", "iprofiles.apple.com", "mdmenrollment.apple.com",
  "identity.apple.com", "vpp.itunes.apple.com", "axm-servicediscovery.apple.com", "business.apple.com", "school.apple.com",
  "api-business.apple.com", "api-school.apple.com", "axm-adm-enroll.apple.com", "axm-adm-mdm.apple.com",
  "axm-adm-scep.apple.com", "axm-app.apple.com", "axm-usercontent-apple.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `deviceenrollment.apple.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `deviceservices-external.apple.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `iprofiles.apple.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `mdmenrollment.apple.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `identity.apple.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `vpp.itunes.apple.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `axm-servicediscovery.apple.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `business.apple.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `school.apple.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `api-business.apple.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `api-school.apple.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `axm-adm-enroll.apple.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `axm-adm-mdm.apple.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `axm-adm-scep.apple.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `axm-app.apple.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `axm-usercontent-apple.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `apple-device-management`: business-systems / management, client-server; characteristics `widely-used`; **risk 1**: widely used by enterprises.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
