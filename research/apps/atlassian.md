# Atlassian Cloud (Jira, Confluence, Bitbucket)

- Content-pack id today: `atlassian` (`atlassian.net`, `atlassian.com`, `bitbucket.org`)
- Status: **READY**, NAME, batch C (`research/patches/batch-c-name-based.patch`)
- Sources accessed: 2026-11-18

## 1. What it is

Atlassian's cloud collaboration and developer apps.

## 2. Transport and ports

HTTPS. The page asks admins to permit domains "and multiple levels of subdomains" [S1].

## 3. Observable evidence

"For Atlassian apps to operate, allow these first-party Atlassian domains and their levels of subdomains.
These domains are directly operated and managed by Atlassian" [S1]: `*.atl-paas.net`, `*.atlassian.com`,
`*.ss-inf.net`, `*.atlassian.net`, `*.jira.com`, `*.bitbucket.org`, `*.atlassian-dev.net`,
`*.atlassian-3p.com`, and `www.teamworkgraph.com` / `teamworkgraph.com` ("Teamwork Graph uses these
domains"). Government Cloud uses separate `*.atlassian-us-gov-mod.*` domains. "Partner domains" are third
parties (CloudFront, Google, Sentry, Segment, `*.slack-edge.com` and others) [S1].

The page advises: "strongly consider excluding the Atlassian first-party domains from TLS
interception/inspection" [S1].

## 4. Encrypted-traffic caveats

- `<site>.atlassian.net` carries the customer's site name. The application is logged; the site label is
  an identifier and is never logged (AGENTS.md).
- `atlassian-dev.net` and `atlassian-3p.com`: first-party by Atlassian's statement, but the page does not
  say what they serve. If they host customers' or third parties' apps, they are tenant hosting. Not proposed.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `atlassian.net`, `atlassian.com`, `bitbucket.org`, `jira.com`, `atl-paas.net`, `ss-inf.net`, `teamworkgraph.com` | **N3** Atlassian | |
| `atlassian-dev.net`, `atlassian-3p.com` | **U** for purpose | Not mapped |
| Government Cloud domains | not proposed | Separate product scope |

## 6. Synthetic test vectors

Checked in scratch: all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `x.atl-paas.net`, `x.ss-inf.net`, `x.jira.com`, `www.teamworkgraph.com` | `atlassian` (today unmapped) |
| N1 | SNI `x.atlassian-3p.com` | no application |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-19 against `c08773f` plus batches D to I and retrofit R)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xatlassian.net` | not atlassian (label boundary) | no application | PASS |
| L- | `atlassian.net.example.invalid` | not atlassian (suffix look-alike) | no application | PASS |
| L- | `xatlassian.com` | not atlassian (label boundary) | no application | PASS |
| L- | `atlassian.com.example.invalid` | not atlassian (suffix look-alike) | no application | PASS |
| L- | `xbitbucket.org` | not atlassian (label boundary) | no application | PASS |
| L- | `bitbucket.org.example.invalid` | not atlassian (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Atlassian Support, "IP addresses and domains for Atlassian cloud apps",
  `https://support.atlassian.com/organization-administration/docs/ip-addresses-and-domains-for-atlassian-cloud-products/`, accessed 2026-11-18.

## 8. Catalog delta and recommendation

```python
("atlassian", "business-systems", "software-development", "browser-based", 2, "Atlassian cloud (Jira, Confluence, Bitbucket)",
 ("widely-used", "transfers-files"), ("atlassian.net", "atlassian.com", "bitbucket.org", "atl-paas.net", "ss-inf.net", "jira.com",
                                      "teamworkgraph.com")),
```

<!-- method-v2:start -->

## 9. Live verification (L)

**BLOCKED in the research environment** (2026-11-19): its egress proxy re-terminates TLS, so a handshake would show the proxy, and direct DNS is not permitted. The tool is `research/tools/live_verify.py`; it runs from an unproxied vantage point or, DNS only, through an approved DoH resolver. No host below carries an `L` result yet.

Names to verify (catalog domains of `atlassian`): `atlassian.net`, `atlassian.com`, `bitbucket.org`, `atl-paas.net`, `ss-inf.net`, `jira.com`, `teamworkgraph.com`.

## 10. Observed web-client hosts (dependency mapping)

- `https://id.atlassian.com/login`: **not loaded**: its host is not yet on the research allowlist (`allowlist-requests.md`, batch R1).

## 11. Attributes (App-ID model) and re-verify date

- `atlassian`: business-systems / software-development, browser-based; characteristics `widely-used`, `transfers-files`; **risk 2**: widely used by enterprises; moves files out of the organisation.
- Functions separated by name: none beyond the single id.
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): ECH support unknown until a live HTTPS-record check (section 9); other modes as stated in sections 2 to 4.
- Re-verify by: **2027-02-17** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
