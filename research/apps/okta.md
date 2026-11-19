# Okta

- Content-pack id today: `okta` (`okta.com`, `oktacdn.com`, `oktapreview.com`)
- Status: **READY**, NAME, batch D
- Sources accessed: 2026-11-19

## 1. What it is

Identity provider (workforce SSO).

## 2. Transport and ports

HTTPS [S1].

## 3. Observable evidence

"Add these domains to your DNS allowlist" [S1]: `*.okta.com`, `*.mtls.okta.com`, `*.oktapreview.com`, `*.mtls.oktapreview.com`, `*.oktacdn.com`, `*.okta-emea.com`, `*.mtls.okta-emea.com`, `*.kerberos.okta.com`, `*.kerberos.okta-emea.com`, `*.kerberos.oktapreview.com`, `*.okta-gov.com`, `*.mtls.okta-gov.com`, `*.okta.mil`, `*.mtls.okta.mil`, `*.awsglobalaccelerator.com`.

## 4. Encrypted-traffic caveats

`<org>.okta.com` carries the customer's org name, which is never logged. `awsglobalaccelerator.com` is AWS (shared) and is not mapped.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under the Okta domains | **N3** | Sign-in, not an application's use |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`claude/go-migration` `bc65e50` plus batches C and D): all as expected, except ECH rows, which need the full engine.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `acme.okta-emea.com`, `x.okta.mil` | `okta`; the org label is not in the output |

## 7. Sources

- [S1] Okta Help, "Allow access to Okta IP addresses", `https://help.okta.com/en-us/content/topics/security/ip-address-allow-listing.htm`, accessed 2026-11-19.

## 8. Catalog delta and recommendation

Batch D (`research/patches/batch-d-name-based.patch`; `...` stands for the unchanged fields):

```python
("okta", ..., ("okta.com", "oktacdn.com", "oktapreview.com", "okta-emea.com", "okta-gov.com", "okta.mil")),
```
