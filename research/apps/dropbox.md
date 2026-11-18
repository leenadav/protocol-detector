# Dropbox

- Content-pack ids today: `dropbox` (`dropbox.com`, `dropboxapi.com`, `dropboxusercontent.com`, `dropboxstatic.com`), `dropbox-sign` (`hellosign.com`)
- Status: **READY**
- Sources accessed: 2026-11-18. Pages "Updated Jul 21, 2025" [S1] and "Updated Aug 13, 2026" [S2]

## 1. What it is

Consumer and business cloud file storage and sharing. Operators watch it for data exfiltration and
shadow IT. The same company runs DocSend (document sharing), Dropbox Sign (formerly HelloSign, e-signature)
and the `dash.ai` product, all listed among Dropbox's verified domains [S1].

## 2. Transport and ports

- Desktop app: "You'll need to give Dropbox access to ports 80 (HTTP) and 443 (HTTPS), and 17600 and
  17603", in the context of letting "third party applications ... open files in Dropbox" [S2]. The
  page does not say whether 17600 and 17603 are local or remote. `UNVERIFIED`; not used.
- Dropbox recommends allowing **domain names** rather than IPs, because "Dropbox also uses IP addresses
  owned by third-party providers or services" [S2].

## 3. Observable evidence

"All Dropbox content should originate from one of the following domains or a subdomain of the
following domains" [S1]: `addtodropbox.com`, `app.hellosign.com`, `dash.ai`, `db.tt`, `docsend.com`,
`dropbox.com`, `dropboxapi.com`, `dropboxbusiness.com`, `dropboxcaptcha.com`, `dropboxexperiment.com`,
`dropboxforums.com`, `dropboxforum.com`, `dropboxinsiders.com`, `dropboxlegal.com`, `dropboxmail.com`,
`dropboxpartners.com`, `dropboxstatic.com`, `dropboxteam.com`, `dropbox.tech`, `dropbox.zendesk.com`,
`getdropbox.com`, `hellofax.com`, `learn.dropbox.com`, `links.dropbox.com`.

"Other verified domains", used "for things like protecting account login pages and DNS requests" [S1]:
`c.evidon.com`, `cdn.arkoselabs.com`, `cfl.dropboxstatic.com`, `consent.dropbox.com`,
`ungated.dropbox.com`, `dropbox-api.arkoselabs.com`, `dropbox-dns.com`.

Sign-in: "`www.dropbox.com` ... is the only domain where Dropbox will ever ask for private information
like the email address and password" [S1].

No ALPN or protocol-structure information is published. `UNVERIFIED`.

## 4. Encrypted-traffic caveats

- **Third-party infrastructure**: Dropbox states it uses third-party IP space [S2], so IPs are not
  evidence.
- `c.evidon.com`, `cdn.arkoselabs.com`, `dropbox-api.arkoselabs.com` and `dropbox.zendesk.com` are
  third-party services (consent, bot protection, support desk). They are verified as *used by*
  Dropbox, not *operated by* Dropbox. Under the v0.65 rule (operator-owned domains only) they must not
  name Dropbox, except the exact `dropbox-api.arkoselabs.com`, and even that is a login-protection
  dependency, not file transfer.
- **Upload vs browse**: hosts cannot separate a file upload from a page view. File-transfer volume is
  a byte-count fact for Culvert, not a detector fact.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `dropbox.com`, `dropboxapi.com`, `getdropbox.com`, `db.tt`, `dropboxbusiness.com` | **N3** Dropbox | |
| SNI under `dropboxstatic.com`, `dropboxcaptcha.com`, `dropboxexperiment.com` | **N2** | Static assets and experiments |
| `dropboxforum(s).com`, `dropboxlegal.com`, `dropboxinsiders.com`, `learn.dropbox.com`, `dropbox.tech` | **N1** | Community, legal, blog: not product use |
| `docsend.com`, `hellosign.com`/`hellofax.com`, `dash.ai` | **N3** for their own products | Separate applications, same company |
| `dropboxusercontent.com` (pack) | **U** | Not on the verified list read here |

## 6. Synthetic test vectors

| # | Input | Expected |
|---|---|---|
| P1 | SNI `content.dropboxapi.com` (synthetic label), ALPN `h2` | `dropbox` |
| P2 | SNI `db.tt` | `dropbox` (today unmapped) |
| P3 | SNI `docsend.com` | DocSend (today unmapped) |
| N1 | SNI `cdn.arkoselabs.com` | no application (third-party) |
| N2 | SNI `dropbox.com.example.invalid`, `mydropbox.com` | no application |
| N3 | `ech_outer()` with outer SNI `www.dropbox.com` | no application |

## 7. Sources

- [S1] Dropbox Help, "What official domains does Dropbox use?",
  `https://help.dropbox.com/security/official-domains` (redirected from
  `/accounts-billing/security/official-domains`), "Updated Jul 21, 2025", accessed 2026-11-18.
- [S2] Dropbox Help, "Allow firewall for the Dropbox desktop app",
  `https://help.dropbox.com/installs/configuring-firewall`, "Updated Aug 13, 2026", accessed 2026-11-18.

## 8. Catalog delta and recommendation

1. Add to `dropbox`: `getdropbox.com`, `db.tt`, `dropboxbusiness.com`, `addtodropbox.com`,
   `dropboxcaptcha.com`, `dropboxexperiment.com`, `dropbox-dns.com`.
2. Treat as web fronts ("provider affiliation only"): `dropboxforum.com`, `dropboxforums.com`,
   `dropboxlegal.com`, `dropboxinsiders.com`, `dropbox.tech`, `learn.dropbox.com`.
3. `dropboxusercontent.com`: not on Dropbox's verified list. Keep, but mark the provenance unverified
   until the Engine lane or this lane finds a primary source.
4. Consider new ids `docsend` (file-sharing) and `dropbox-dash` (`dash.ai`; category to be decided).
   Add `hellofax.com` and `app.hellosign.com` to `dropbox-sign`.
5. Do not map the third-party domains (`evidon`, `arkoselabs`, `zendesk`).
