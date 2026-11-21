# Amazon Q Developer (formerly CodeWhisperer)

- Content-pack id today: none
- Status: **READY**, NAME, batch M: new id `amazon-q-developer`
- Sources: [Q] read in the research cloud (egress proxy), 2026-11-21; no page date shown

## 1. What it is

AWS's generative-AI coding assistant in IDEs (VS Code, JetBrains, Visual Studio, Eclipse), the command line and the console.

## 2. Transport and ports

HTTPS on 443 through an HTTP or HTTPS proxy; "SOCKS proxies and Proxy Auto-Configuration (PAC) files are not supported" [Q].

## 3. Observable evidence

[Q] authentication: `<directory>.awsapps.com`, `oidc.<sso-region>.amazonaws.com`, `*.sso.<sso-region>.amazonaws.com`, `*.sso-portal.<sso-region>.amazonaws.com`, `*.aws.dev`, `*.awsstatic.com`, `*.console.aws.a2z.com`, `*.sso.amazonaws.com`. Features: `codewhisperer.us-east-1.amazonaws.com`, `q.<profile-region>.amazonaws.com`. IDE: `idetoolkits-hostedfiles.amazonaws.com`, `idetoolkits.amazonwebservices.com` (configuration, endpoints), `q-developer-integration.us-east-1.api.aws`, `aws-toolkit-language-servers.amazonaws.com`, `aws-language-servers.us-east-1.amazonaws.com` (language processing), `client-telemetry.us-east-1.amazonaws.com`, `cognito-identity.us-east-1.amazonaws.com` (telemetry). AWS-owned S3 buckets (code reviews, code transformation), "only in the Region where the Amazon Q Developer profile is installed": `amazonq-code-scan-us-east-1-29121b44f7b`, `amazonq-code-scan-eu-central-1-9374e402cc5`, `amazonq-code-transformation-us-east-1-c6160f047e0`, `amazonq-code-transformation-eu-central-1-a0a89cc2b94` (`.s3.amazonaws.com`).

## 4. Encrypted-traffic caveats

`q.<profile-region>.amazonaws.com` is proposed for `us-east-1` and `eu-central-1` only: the page gives the region as a placeholder, and the buckets exist in those two regions, so the two profile regions are inferred (**N2**; other regions stay unmapped until a region list is read). Sign-in, telemetry and Cognito names are shared AWS names. The toolkit and language-server hosts serve the AWS Toolkit generally, so they are not proposed. Code sent for review or transformation goes to the exact bucket names, which are AWS-owned and Q-specific (the WeTransfer and Asana bucket precedent). Risk 3, as for the other coding assistants.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| Exact `codewhisperer.us-east-1.amazonaws.com`, `q-developer-integration.us-east-1.api.aws` | **N3** (exact) | Inference and IDE endpoints |
| Exact `q.us-east-1.amazonaws.com`, `q.eu-central-1.amazonaws.com` | **N2** (exact) | Region inferred |
| Exact four bucket hosts | **N3** (exact) | Uploads for reviews and transformations |
| SSO, telemetry, Cognito, toolkit hosts | not mapped | Shared AWS |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K and M): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `codewhisperer.us-east-1.amazonaws.com`, `q.eu-central-1.amazonaws.com` | `amazon-q-developer` (today unmapped) |
| P2 | SNI `amazonq-code-scan-us-east-1-29121b44f7b.s3.amazonaws.com`, `q-developer-integration.us-east-1.api.aws` | `amazon-q-developer` (today unmapped) |
| N1 | SNI `client-telemetry.us-east-1.amazonaws.com`, `q.us-west-2.amazonaws.com`, `x.s3.amazonaws.com` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K and M as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xamazonaws.com` | not amazon-q-developer (label boundary) | no application | PASS |
| L- | `codewhisperer.us-east-1.amazonaws.com.example.invalid` | not amazon-q-developer (suffix look-alike) | no application | PASS |
| L- | `q.us-east-1.amazonaws.com.example.invalid` | not amazon-q-developer (suffix look-alike) | no application | PASS |
| L- | `q.eu-central-1.amazonaws.com.example.invalid` | not amazon-q-developer (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [Q] AWS Documentation, "Configuring a firewall, proxy server, or data perimeter for Amazon Q Developer", `https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/firewall.html`, read in the research cloud (egress proxy), 2026-11-21.

## 8. Catalog delta and recommendation

```python
("amazon-q-developer", "business-systems", "generative-ai", "client-server", 3, "Amazon Q Developer (CodeWhisperer)",
 ("transfers-files",), ("codewhisperer.us-east-1.amazonaws.com", "q.us-east-1.amazonaws.com", "q.eu-central-1.amazonaws.com",
  "q-developer-integration.us-east-1.api.aws", "amazonq-code-scan-us-east-1-29121b44f7b.s3.amazonaws.com",
  "amazonq-code-scan-eu-central-1-9374e402cc5.s3.amazonaws.com", "amazonq-code-transformation-us-east-1-c6160f047e0.s3.amazonaws.com",
  "amazonq-code-transformation-eu-central-1-a0a89cc2b94.s3.amazonaws.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `codewhisperer.us-east-1.amazonaws.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `q.us-east-1.amazonaws.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `q.eu-central-1.amazonaws.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `q-developer-integration.us-east-1.api.aws` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `amazonq-code-scan-us-east-1-29121b44f7b.s3.amazonaws.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `amazonq-code-scan-eu-central-1-9374e402cc5.s3.amazonaws.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `amazonq-code-transformation-us-east-1-c6160f047e0.s3.amazonaws.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |
| `amazonq-code-transformation-eu-central-1-a0a89cc2b94.s3.amazonaws.com` | not yet verified (added after round 2; in `live-hosts-r4.txt` for the next run) |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `amazon-q-developer`: business-systems / generative-ai, client-server; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
