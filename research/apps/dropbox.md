# Dropbox

- Content-pack ids today: `dropbox` (`dropbox.com`, `dropboxapi.com`, `dropboxusercontent.com`, `dropboxstatic.com`), `dropbox-sign` (`hellosign.com`)
- Status: batch A **DONE** (content 2026.11.3); `www.` web-front variants **READY**, NAME, batch C. `dash.ai` is PARTIAL (purpose not stated by the source)
- Implemented: content release 2026.11.3 on `claude/go-migration` (`baa07b9`); verified in the pack at `47b2743`, 2026-11-18
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

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K and M as rebuilt 2026-11-21)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| O+ | `cfl.dropboxstatic.com` | one of `dropbox`, `docsend`, `dropbox-sign` | `dropbox` | PASS |
| O+ | `dropboxcaptcha.com` | one of `dropbox`, `docsend`, `dropbox-sign` | `dropbox` | PASS |
| O+ | `fp.dropbox.com` | one of `dropbox`, `docsend`, `dropbox-sign` | `dropbox` | PASS |
| O+ | `marketing.dropbox.com` | one of `dropbox`, `docsend`, `dropbox-sign` | `dropbox` | PASS |
| O+ | `www.dropbox.com` | one of `dropbox`, `docsend`, `dropbox-sign` | `dropbox` | PASS |
| D- | `077-zjt-858.mktoresp.com` | not dropbox/docsend/dropbox-sign (third party (unclassified)) | no application | PASS |
| D- | `10906599.fls.doubleclick.net` | not dropbox/docsend/dropbox-sign (third party) | `google-ads` | PASS |
| D- | `15932550.fls.doubleclick.net` | not dropbox/docsend/dropbox-sign (third party) | `google-ads` | PASS |
| D- | `accounts.google.com` | not dropbox/docsend/dropbox-sign (shared vendor infra) | `google-accounts` | PASS |
| D- | `ad.doubleclick.net` | not dropbox/docsend/dropbox-sign (third party) | `google-ads` | PASS |
| D- | `adservice.google.com` | not dropbox/docsend/dropbox-sign (shared vendor infra) | `google-base` | PASS |
| D- | `alb.reddit.com` | not dropbox/docsend/dropbox-sign (shared vendor infra) | `reddit-base` | PASS |
| D- | `analytics.google.com` | not dropbox/docsend/dropbox-sign (shared vendor infra) | `google-base` | PASS |
| D- | `analytics.twitter.com` | not dropbox/docsend/dropbox-sign (shared vendor infra) | `x-base` | PASS |
| D- | `assets.adobedtm.com` | not dropbox/docsend/dropbox-sign (third party (unclassified)) | no application | PASS |
| D- | `bttrack.com` | not dropbox/docsend/dropbox-sign (third party (unclassified)) | no application | PASS |
| D- | `cdn.bttrack.com` | not dropbox/docsend/dropbox-sign (third party (unclassified)) | no application | PASS |
| D- | `cj.dotomi.com` | not dropbox/docsend/dropbox-sign (third party (unclassified)) | no application | PASS |
| D- | `configs.knotch.com` | not dropbox/docsend/dropbox-sign (third party (unclassified)) | no application | PASS |
| D- | `connect.facebook.net` | not dropbox/docsend/dropbox-sign (shared vendor infra) | `meta-base` | PASS |
| D- | `fonts.gstatic.com` | not dropbox/docsend/dropbox-sign (shared vendor infra) | `google-base` | PASS |
| D- | `google.com` | not dropbox/docsend/dropbox-sign (shared vendor infra) | `google-base` | PASS |
| D- | `googleads.g.doubleclick.net` | not dropbox/docsend/dropbox-sign (third party) | `google-ads` | PASS |
| D- | `js.qualified.com` | not dropbox/docsend/dropbox-sign (third party (unclassified)) | no application | PASS |
| D- | `js.zi-scripts.com` | not dropbox/docsend/dropbox-sign (third party (unclassified)) | no application | PASS |
| D- | `munchkin.marketo.net` | not dropbox/docsend/dropbox-sign (third party (unclassified)) | no application | PASS |
| D- | `pixel-config.reddit.com` | not dropbox/docsend/dropbox-sign (shared vendor infra) | `reddit-base` | PASS |
| D- | `play.google.com` | not dropbox/docsend/dropbox-sign (shared vendor infra) | `google-base` | PASS |
| D- | `px.ads.linkedin.com` | not dropbox/docsend/dropbox-sign (shared vendor infra) | `linkedin-base` | PASS |
| D- | `px4.ads.linkedin.com` | not dropbox/docsend/dropbox-sign (shared vendor infra) | `linkedin-base` | PASS |
| D- | `s.yimg.jp` | not dropbox/docsend/dropbox-sign (third party (unclassified)) | no application | PASS |
| D- | `siteintercept.qualtrics.com` | not dropbox/docsend/dropbox-sign (third party (unclassified)) | no application | PASS |
| D- | `snap.licdn.com` | not dropbox/docsend/dropbox-sign (shared vendor infra) | `linkedin-base` | PASS |
| D- | `static.ads-twitter.com` | not dropbox/docsend/dropbox-sign (third party) | no application | PASS |
| D- | `static.cloud.coveo.com` | not dropbox/docsend/dropbox-sign (third party (unclassified)) | no application | PASS |
| D- | `static.xingcdn.com` | not dropbox/docsend/dropbox-sign (third party (unclassified)) | no application | PASS |
| D- | `stats.g.doubleclick.net` | not dropbox/docsend/dropbox-sign (third party) | `google-ads` | PASS |
| D- | `t.co` | not dropbox/docsend/dropbox-sign (shared vendor infra) | `x-base` | PASS |
| D- | `tags.srv.stackadapt.com` | not dropbox/docsend/dropbox-sign (third party (unclassified)) | no application | PASS |
| D- | `ws.zoominfo.com` | not dropbox/docsend/dropbox-sign (third party (unclassified)) | no application | PASS |
| D- | `www.emjcd.com` | not dropbox/docsend/dropbox-sign (third party (unclassified)) | no application | PASS |
| D- | `www.google.co.il` | not dropbox/docsend/dropbox-sign (third party (unclassified)) | no application | PASS |
| D- | `www.google.com` | not dropbox/docsend/dropbox-sign (shared vendor infra) | `google-base` | PASS |
| D- | `www.googleadservices.com` | not dropbox/docsend/dropbox-sign (third party) | `google-ads` | PASS |
| D- | `www.googletagmanager.com` | not dropbox/docsend/dropbox-sign (third party) | `google-analytics` | PASS |
| D- | `www.gstatic.com` | not dropbox/docsend/dropbox-sign (shared vendor infra) | `google-base` | PASS |
| D- | `www.knotch-cdn.com` | not dropbox/docsend/dropbox-sign (third party (unclassified)) | no application | PASS |
| D- | `www.linkedin.com` | not dropbox/docsend/dropbox-sign (third party) | `linkedin` | PASS |
| D- | `www.redditstatic.com` | not dropbox/docsend/dropbox-sign (shared vendor infra) | `reddit-base` | PASS |
| D- | `zn9zbcpytdp6xzcnx-dropbox.siteintercept.qualtrics.com` | not dropbox/docsend/dropbox-sign (third party (unclassified)) | no application | PASS |
| L- | `xdropbox.com` | not dropbox/docsend/dropbox-sign (label boundary) | no application | PASS |
| L- | `dropbox.com.example.invalid` | not dropbox/docsend/dropbox-sign (suffix look-alike) | no application | PASS |
| L- | `xdropboxapi.com` | not dropbox/docsend/dropbox-sign (label boundary) | no application | PASS |
| L- | `dropboxapi.com.example.invalid` | not dropbox/docsend/dropbox-sign (suffix look-alike) | no application | PASS |
| L- | `xdropboxusercontent.com` | not dropbox/docsend/dropbox-sign (label boundary) | no application | PASS |
| L- | `dropboxusercontent.com.example.invalid` | not dropbox/docsend/dropbox-sign (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [S1] Dropbox Help, "What official domains does Dropbox use?",
  `https://help.dropbox.com/security/official-domains` (redirected from
  `/accounts-billing/security/official-domains`), "Updated Jul 21, 2025", accessed 2026-11-18.
- [S2] Dropbox Help, "Allow firewall for the Dropbox desktop app",
  `https://help.dropbox.com/installs/configuring-firewall`, "Updated Aug 13, 2026", accessed 2026-11-18.

## 8. Catalog delta and recommendation

Exact entries in batch A (`research/patches/batch-a-name-based.patch`, base `claude/go-migration` `6b280a6`):

```python
("dropbox", "general-internet", "file-sharing", "client-server", 3, "Dropbox file sync and sharing",
 ("widely-used", "transfers-files"),
 ("dropbox.com", "dropboxapi.com", "dropboxusercontent.com", "dropboxstatic.com",
  "getdropbox.com", "db.tt", "dropboxbusiness.com", "addtodropbox.com", "dropboxcaptcha.com",
  "dropboxexperiment.com", "dropbox-dns.com"),
 ("dropboxforum.com", "dropboxforums.com", "dropboxlegal.com", "dropboxinsiders.com", "dropbox.tech", "learn.dropbox.com",
  # batch C: www variants
  "www.dropboxforum.com", "www.dropboxforums.com", "www.dropboxlegal.com", "www.dropboxinsiders.com", "www.dropbox.tech")),
("docsend", "general-internet", "file-sharing", "browser-based", 3, "DocSend document sharing (Dropbox)",
 ("transfers-files",), ("docsend.com",)),
("dropbox-sign", ..., ("hellosign.com", "hellofax.com")),
```

- Web fronts are exact names (PROTOCOLS.md v0.65; `host_apps.py`), so only the listed names become
  affiliation-only. Batch C adds the `www.` variants explicitly (`www.dropboxforum.com`, `www.dropboxforums.com`,
  `www.dropboxlegal.com`, `www.dropboxinsiders.com`, `www.dropbox.tech`), following the Engine lane's note that
  `www.dropboxforum.com` mapped to nothing. Other subdomains of these domains stay unmapped (they are not service domains). `learn.dropbox.com` wins over the `dropbox.com` domain. `app.hellosign.com` is already
  covered by `hellosign.com`.
- `dropboxusercontent.com` is kept but unverified by this lane.
- Not in batch A: `dash.ai`. The source lists the domain without saying what it serves, so its category
  is unknown.
- Third-party domains (`evidon`, `arkoselabs`, `zendesk`) get no entry.
- `docsend` metadata (risk 3, `transfers-files`) is this lane's proposal; the Engine lane may adjust it.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and round 4 of 2026-11-21 where it has the name (`research/live-results-2026-11-21-r4.tsv`, partial relay; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `dropbox.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.app.dropbox.com`, subject organisation **Dropbox, Inc** (issuer DigiCert, Inc.) |
| `dropboxapi.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `dropboxapi.com`, no subject organisation (domain-validated) (issuer Let's Encrypt) |
| `dropboxusercontent.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `dropboxstatic.com` | resolves; TLS handshake failed (OSError) in both rounds where checked: not a removal reason |
| `getdropbox.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.getdropbox.com`, subject organisation **Dropbox, Inc** (issuer DigiCert Inc) |
| `db.tt` | **L** resolves; TLSv1.3, ALPN `h2`, cert `db.tt`, subject organisation **Dropbox, Inc** (issuer DigiCert Inc) |
| `dropboxbusiness.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.dropboxbusiness.com`, no subject organisation (domain-validated) (issuer Let's Encrypt) |
| `addtodropbox.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `dropboxcaptcha.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `dropboxcaptcha.com`, no subject organisation (domain-validated) (issuer Amazon) |
| `dropboxexperiment.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `dropbox-dns.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source) |
| `docsend.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.docsend.com`, subject organisation **Dropbox, Inc** (issuer DigiCert Inc) |
| `hellosign.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.hellosign.com`, subject organisation **Dropbox, Inc** (issuer DigiCert Inc) |
| `hellofax.com` | **L** resolves; TLSv1.3, ALPN `h2`, cert `*.hellofax.com`, subject organisation **Dropbox, Inc** (issuer DigiCert Inc) |

## 10. Observed web-client hosts (dependency mapping)

- `https://www.dropbox.com/login`, pass 2 (Hermes server, direct, 2026-11-20), loaded without signing in: HTTP 200, final host `www.dropbox.com`.

Pass 2 (Hermes server, direct connection) replaces pass 1 for every URL it covers; it records hosts seen ("seen"), not request counts. Pages that stopped at a bot or JavaScript challenge from a datacenter address are a lower bound. Pass 1 rows give requests (refused by the research proxy).

| Host | Requests | Class | Attribution today | Live flags | Note |
|---|---|---|---|---|---|
| `077-zjt-858.mktoresp.com` | seen | third party (unclassified) | no application | not checked |  |
| `10906599.fls.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `15932550.fls.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `accounts.google.com` | seen (some failed) | shared vendor infra | `google-accounts` |  |  |
| `ad.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `adservice.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `alb.reddit.com` | seen | shared vendor infra | `reddit-base` | not checked |  |
| `analytics.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `analytics.twitter.com` | seen | shared vendor infra | `x-base` | not checked |  |
| `assets.adobedtm.com` | seen | third party (unclassified) | no application | not checked |  |
| `bttrack.com` | seen (some failed) | third party (unclassified) | no application | not checked |  |
| `cdn.bttrack.com` | seen | third party (unclassified) | no application | not checked |  |
| `cfl.dropboxstatic.com` | seen | app-owned | `dropbox` | not checked |  |
| `cj.dotomi.com` | seen | third party (unclassified) | no application | not checked |  |
| `configs.knotch.com` | seen | third party (unclassified) | no application | not checked |  |
| `connect.facebook.net` | seen | shared vendor infra | `meta-base` | not checked |  |
| `dropboxcaptcha.com` | seen | app-owned | `dropbox` |  |  |
| `fonts.gstatic.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `fp.dropbox.com` | seen | app-owned | `dropbox` | not checked |  |
| `google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `googleads.g.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `js.qualified.com` | seen (some failed) | third party (unclassified) | no application | not checked |  |
| `js.zi-scripts.com` | seen | third party (unclassified) | no application | not checked |  |
| `marketing.dropbox.com` | seen | app-owned | `dropbox` | not checked |  |
| `munchkin.marketo.net` | seen | third party (unclassified) | no application | not checked |  |
| `pixel-config.reddit.com` | seen | shared vendor infra | `reddit-base` | not checked |  |
| `play.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `px.ads.linkedin.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `px4.ads.linkedin.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `s.yimg.jp` | seen | third party (unclassified) | no application | not checked |  |
| `siteintercept.qualtrics.com` | seen | third party (unclassified) | no application | not checked |  |
| `snap.licdn.com` | seen | shared vendor infra | `linkedin-base` | not checked |  |
| `static.ads-twitter.com` | seen | third party | no application | not checked | X advertising tag |
| `static.cloud.coveo.com` | seen | third party (unclassified) | no application | not checked |  |
| `static.xingcdn.com` | seen | third party (unclassified) | no application | not checked |  |
| `stats.g.doubleclick.net` | seen | third party | `google-ads` | not checked |  |
| `t.co` | seen | shared vendor infra | `x-base` | not checked |  |
| `tags.srv.stackadapt.com` | seen (some failed) | third party (unclassified) | no application | not checked |  |
| `ws.zoominfo.com` | seen | third party (unclassified) | no application | not checked |  |
| `www.dropbox.com` | seen | app-owned | `dropbox` | not checked |  |
| `www.emjcd.com` | seen | third party (unclassified) | no application | not checked |  |
| `www.google.co.il` | seen | third party (unclassified) | no application | not checked |  |
| `www.google.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `www.googleadservices.com` | seen | third party | `google-ads` | not checked |  |
| `www.googletagmanager.com` | seen | third party | `google-analytics` | not checked |  |
| `www.gstatic.com` | seen | shared vendor infra | `google-base` | not checked |  |
| `www.knotch-cdn.com` | seen | third party (unclassified) | no application | not checked |  |
| `www.linkedin.com` | seen | third party | `linkedin` | not checked |  |
| `www.redditstatic.com` | seen | shared vendor infra | `reddit-base` | not checked |  |
| `zn9zbcpytdp6xzcnx-dropbox.siteintercept.qualtrics.com` | seen | third party (unclassified) | no application | not checked |  |

## 11. Attributes (App-ID model) and re-verify date

- `dropbox`: general-internet / file-sharing, client-server; characteristics `widely-used`, `transfers-files`; **risk 3**: widely used by enterprises; moves files out of the organisation.
- `docsend`: general-internet / file-sharing, browser-based; characteristics `transfers-files`; **risk 3**: moves files out of the organisation.
- `dropbox-sign`: business-systems / office-programs, browser-based; characteristics `transfers-files`; **risk 2**: moves files out of the organisation.
- Functions separated by name: `dropbox` (Dropbox file sync and sharing), `docsend` (DocSend document sharing (Dropbox)), `dropbox-sign` (Dropbox Sign (HelloSign) e-signature).
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): `077-zjt-858.mktoresp.com`, `assets.adobedtm.com`, `bttrack.com`, `cdn.bttrack.com`, `cj.dotomi.com`, `configs.knotch.com`, `google-accounts`, `google-ads`, `google-analytics`, `google-base`, `js.qualified.com`, `js.zi-scripts.com`, `linkedin`, `linkedin-base`, `meta-base`, `munchkin.marketo.net`, `reddit-base`, `s.yimg.jp`, `siteintercept.qualtrics.com`, `static.ads-twitter.com`, `static.cloud.coveo.com`, `static.xingcdn.com`, `tags.srv.stackadapt.com`, `ws.zoominfo.com`, `www.emjcd.com`, `www.google.co.il`, `www.knotch-cdn.com`, `x-base`, `zn9zbcpytdp6xzcnx-dropbox.siteintercept.qualtrics.com`.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
