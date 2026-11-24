# DocuSign eSignature

- Content-pack id today: `docusign` (`docusign.com`, `docusign.net`)
- Status: **READY**, NAME, batch N: `docucdn-a.akamaihd.net` added; domain list read in full (PRO-138); `*.docusign.pdfeditor.com` not mapped (live round 6)
- Sources: read by Research Lab from the Hermes server, relayed by Hermes (PRO-108, PRO-121), 2026-11-21; full section re-read by Research Lab from the Hermes server (PRO-138), relayed by Hermes (PRO-139), 2026-11-22; fetched 2026-11-21, HTTP 200, no sign-in; no page date on the page

## 1. What it is

Electronic signature service.

## 2. Transport and ports

Not stated in the text read. "Because of Akamai, IP allowlisting is no longer supported for web access" [DS].

## 3. Observable evidence

[DS] "Allowlists for Docusign eSignature service", full list of 8 entries: connections to DocuSign `*.docusign.com`, `*.docusign.net`, `*.docusign.pdfeditor.com`; Akamai CDN/WAF `*.edgekey.net`, `*.akamaiedge.net`, `docucdn-a.akamaihd.net`, `ronp-a.akamaihd.net`; Optimizely content delivery `*cdn.optimizely.com`. Email and Connect ("Connections from Docusign") are IP ranges only (JSON feed `https://www.docusign.com/trust/ip-ranges.json`); the page has no domain section for either.

## 4. Encrypted-traffic caveats

`docucdn-a.akamaihd.net` carries the vendor's name on Akamai's shared `akamaihd.net`, so it is proposed as an exact name (the bucket-host precedent). `ronp-a.akamaihd.net` does not, and `edgekey.net`, `akamaiedge.net` and Optimizely are shared CDN or third party: none is proposed. `*.docusign.pdfeditor.com` is a DocuSign-listed subtree of `pdfeditor.com`, a registrable domain that is not DocuSign's. Live round 6 (2026-11-22): `docusign.pdfeditor.com` CNAMEs to `saas-origin.gonitro.com` (Nitro's SaaS origin) and presents a domain-validated certificate (Google Trust Services, no organisation), so DocuSign ownership is **not shown**: it stays unmapped (decision 3), as a third-party PDF editor host DocuSign lists. Connect webhooks and email arrive from DocuSign IP ranges, which the catalog does not use. Live round 5 (2026-11-21): `docucdn-a.akamaihd.net` presents Akamai's generic certificate (`a248.e.akamai.net`, Akamai Technologies) with no DocuSign identity, so it is a shared Akamai edge name: usable only as the exact SNI (**N2**), never the `akamaihd.net` suffix or the IPs. `docusign.com` presents a certificate naming DocuSign, Inc.; `docusign.net` resolves but the handshake fails, which is not a removal reason.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `docusign.com`, `docusign.net` | **N3** | Already mapped |
| Exact `docucdn-a.akamaihd.net` | **N2** (exact) | Vendor-named CDN host |
| Akamai and Optimizely names | not mapped | Shared CDN, third party |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K, M and N): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `app.docusign.com` | `docusign` |
| P2 | SNI `docucdn-a.akamaihd.net` | `docusign` (today unmapped) |
| N1 | SNI `ronp-a.akamaihd.net`, `x.edgekey.net`, `cdn.optimizely.com` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O, P and Q as rebuilt 2026-11-24)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xdocusign.com` | not docusign (label boundary) | no application | PASS |
| L- | `docusign.com.example.invalid` | not docusign (suffix look-alike) | no application | PASS |
| L- | `xdocusign.net` | not docusign (label boundary) | no application | PASS |
| L- | `docusign.net.example.invalid` | not docusign (suffix look-alike) | no application | PASS |
| L- | `xakamaihd.net` | not docusign (label boundary) | no application | PASS |
| L- | `docucdn-a.akamaihd.net.example.invalid` | not docusign (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [DS] DocuSign, "Allowlists for Docusign eSignature service", `https://www.docusign.com/trust/security/esignature`, read by Research Lab from the Hermes server, relayed by Hermes (PRO-108, PRO-121), 2026-11-21.

## 8. Catalog delta and recommendation

```python
("docusign", ..., ("docusign.com", "docusign.net", "docucdn-a.akamaihd.net")),
```

Open item: none. `docusign.pdfeditor.com` stays unmapped: round 6 shows a Nitro-operated host with a domain-validated certificate.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `docusign.com` | round 5 (2026-11-21); **L** resolves; TLSv1.3, cert `www.docusign.com`, subject organisation **DocuSign, Inc.** (issuer DigiCert Inc) |
| `docusign.net` | round 5 (2026-11-21); resolves; TLS handshake failed (error not relayed, round 5): not a removal reason |
| `docucdn-a.akamaihd.net` | round 5 (2026-11-21); **L** resolves; TLSv1.3, cert `a248.e.akamai.net`, subject organisation **Akamai Technologies, Inc.** (issuer DigiCert Inc); CNAME into shared front end `docucdn-a.akamaihd.net.edgesuite.net>a1737.b.akamai.net`: name usable, IPs never |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `docusign`: business-systems / general-business, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
