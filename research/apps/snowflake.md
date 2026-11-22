# Snowflake

- Content-pack id today: `snowflake` (`snowflakecomputing.com`)
- Status: **DONE**, verified, no catalog change (no fixed public host list)
- Sources: read by Research Lab from the Hermes server, relayed by Hermes (PRO-108, PRO-121), 2026-11-21 (the `.md` version); no page date shown

## 1. What it is

Cloud data platform (warehouse, data sharing).

## 2. Transport and ports

443 for standard traffic and 80 for OCSP certificate checks [SF]; the customer's cloud storage (S3, GCS or Azure) must also be reachable.

## 3. Observable evidence

[SF]: host names are per account and region; `SYSTEM$ALLOWLIST()` (`/en/sql-reference/functions/system_allowlist`) returns them with ports. There is no fixed public list.

## 4. Encrypted-traffic caveats

Account host names carry the customer's account identifier: the catalog names the application only and never emits it. The returned names are not public, so nothing is added; `snowflakecomputing.com` stays the only domain. OCSP on port 80 goes to the certificate authorities' responders, which are not Snowflake. Stage traffic to cloud storage carries the storage provider's names and is not attributed to Snowflake.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `snowflakecomputing.com` | **N3** | Already mapped; per-account names |
| Cloud storage, OCSP | not mapped | Shared |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K, M and N): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `acme-xy12345.snowflakecomputing.com` | `snowflake` |
| N1 | SNI `xsnowflakecomputing.com`, `x.s3.amazonaws.com` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N and O as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xsnowflakecomputing.com` | not snowflake (label boundary) | no application | PASS |
| L- | `snowflakecomputing.com.example.invalid` | not snowflake (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [SF] Snowflake Documentation, hostname allowlist page (title not relayed), `https://docs.snowflake.com/en/user-guide/hostname-allowlist`, read by Research Lab from the Hermes server, relayed by Hermes (PRO-108, PRO-121), 2026-11-21.

## 8. Catalog delta and recommendation

None.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 5 of 2026-11-21 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `snowflakecomputing.com` | round 5 (2026-11-21); **L** resolves; TLSv1.3, cert `snowflakecomputing.com`, no subject organisation (domain-validated) (issuer Let's Encrypt) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `snowflake`: business-systems / management, client-server; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
