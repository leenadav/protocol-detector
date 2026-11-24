# Datto RMM, N-able (N-central, N-sight, Take Control) and Fortinet FortiClient

- Content-pack id today: none for any of the three
- Status: **READY**, NAME, batch O (`research/patches/batch-o-name-based.patch`): new ids `datto-rmm`, `n-able`, `forticlient`. FortiSASE: PARTIAL (ports only)
- Sources: read by Research Lab from the Hermes server (PRO-95), relayed by Hermes (PRO-106), 2026-11-22; no page dates relayed. Datto: only the Syrah platform rows were read; N-sight: only the first territories

## 1. What it is

Two remote monitoring and management (RMM) platforms for managed service providers, Datto RMM (Kaseya) and N-able (N-central, N-sight RMM, Take Control remote access, Cove backup), and Fortinet's endpoint agent FortiClient with its cloud management service (EMS Cloud).

## 2. Transport and ports

Datto RMM [D]: 443/TCP for the web service, updates, web interface and control channel; Web Remote tunnel on 3478 and 49152 to 65535, TCP and UDP, outbound; agent discovery on 13300/UDP inbound. N-central [NC]: `sis.n-able.com` on 80, 443 and 8443/TCP, the rest on 443; the Modern Agent's AWS IoT channel on 8088/TCP; Take Control without wildcard support on 3377/TCP to any IP. N-sight [NS]: 80 and 443. FortiClient [F]: 443/TCP to EMS Cloud and FortiGuard; the Cloud Sandbox returns its server and port at run time ("usually 514"). FortiSASE [FS]: 443/TCP SSL portal, DTLS, 500 and 4500 (IKE, NAT-T), 5246 (CAPWAP), 7831/TCP (SAML), 8008 to 8020 (web filter), 9443 (proxy), ICMP; no names.

## 3. Observable evidence

[D]: wildcards `*.centrastage.net` and `*.rmm.datto.com`; per platform (Syrah shown, "other platforms use their own prefix") `agent-gateway.syrah.rmm.datto.com`, `syrahws`, `syrah-agent`, `syrah-audit`, `syrah-monitoring`, `syrah-agent-notifications`, `syrah-agent-comms`, `update-syrah`, `syrah`, `syrah-realtime`, `syrahrmm`, `syrah-frontend-api`, `syrahcc`, `01syrahcc`, `cpt-syrah` (`.centrastage.net`), `features.syrah.rmm.datto.com`, `syrah.rmm.datto.com`, `storage.rmm.datto.com`, `webrtc.rmm.datto.com`, `update.centrastage.net`; tunnel `tunnel-ips` and `ts.centrastage.net`; IP-list names `<platform>-ips.centrastage.net`; sign-in `auth.datto.com`, `saml.datto.com`; also `download.visualstudio.microsoft.com` and DigiCert status. [NC]: `sis.n-able.com`, `update.n-able.com` (`releases.n-able.com`), `feeds`, `servermetrics`, `licensing`, `push`, `scep`, `keybox`, `secure` (`.n-able.com`), `keybox.solarwindsmsp.com`, `*.sentinelone.net` (EDR); Modern Agent `*.prd.cdo.system-monitor.com`, `eb.<region>.prd.davinci.system-monitor.com`, relays `us`, `eu-w`, `eu-c`, `ap` `.prd.relay.system-monitor.com`, AWS IoT `a33d8yamkwy4nx-ats.iot.<region>.amazonaws.com`; Take Control `swi-rc.cdn-sw.net`, `*.n-able.com`, `*.mspa.n-able.com`; MSP Anywhere `*.beanywhere.com`, `mspa.n-able.com`, `*.pubnub.com`; backup `*.cloudbackup.management`; third parties `*.launchdarkly.com`, `api.openai.com`, `updatewarranty.com`, `sso.navigatorlogin.com`. [NS]: `upload1` to `upload4` `.am.remote.management`, `rm-downloads-us.logicnow.com`, `checks-api.us.system-monitor.com`, `cannonball-us-west-2-push.logicnow.us`; other territories `upload1-4asia.system-monitor.com`, `upload1-4europe1.systemmonitor.eu.com`, `rm-downloads-apac` and `rm-downloads` `.logicnow.com`, `cannonball-<region>-push.logicnow.us`; `dg5bj97jvb67q.cloudfront.net` (antivirus update check). [F]: `forticlient-emsproxy.forticloud.com`, `forticlient.forticloud.com` (EMS Cloud); `fctguard`, `fctusguard`, `fcteuguard` (URL rating, Anycast), `forticlient`, `myforticlient`, `usforticlient` (legacy URL rating; `myforticlient` also the mobile public-IP lookup), `fctupdate`, `fctusupdate`, `fcteuupdate` (signature updates) `.fortinet.net`; `aptctrl1.fortinet.com` (Cloud Sandbox lookup).

## 4. Encrypted-traffic caveats

**Datto RMM**: `centrastage.net` (the platform's original name) and the `rmm.datto.com` subtree are dedicated. `datto.com` itself and the `auth`/`saml` sign-in names serve all Datto products, so they are not mapped; the IP-list names are DNS-only. **N-able**: the dedicated domains are `n-able.com` (also the marketing site: apex and `www` are web fronts), `system-monitor.com`, `systemmonitor.eu.com`, `logicnow.com`, `logicnow.us` (LogicNow, an N-able predecessor) and `remote.management` (registrable under `.management`); `beanywhere.com` (MSP Anywhere) and `cloudbackup.management` (Cove backup) are N-able product domains under the same id (**N2**). `keybox.solarwindsmsp.com` and `swi-rc.cdn-sw.net` are exact names on legacy SolarWinds MSP domains (**N2**), never their parents. Not mapped: SentinelOne (its own id), PubNub, LaunchDarkly, OpenAI, the account-specific AWS IoT endpoint and CloudFront distribution, `updatewarranty.com` and `sso.navigatorlogin.com` (owners not shown). **FortiClient**: only the exact names are proposed: `forticloud.com` and `fortinet.net` also serve other Fortinet products (FortiGate's FortiGuard, FortiCloud), and `aptctrl1.fortinet.com` is a sandbox lookup FortiGate uses too. The VPN tunnel goes to the customer's own gateway and has no Fortinet name. **RMM risk**: both RMM ids take the `atera` attributes (risk 4, tunnels other applications, prone to misuse, used by malware). Remote sessions on the tunnel ports (3478, 49152 to 65535, 3377) carry no name. Only Datto's Syrah rows and N-sight's first territories were read: other platforms' names fall under the same suffixes.

## 5. Confidence and false-positive risks

| Observable | Level | Limits |
|---|---|---|
| SNI under `centrastage.net`, `rmm.datto.com` | **N3** | Datto RMM |
| SNI under `n-able.com`, `system-monitor.com`, `logicnow.com` | **N3** | N-able |
| SNI under `systemmonitor.eu.com`, `logicnow.us`, `remote.management`, `beanywhere.com`, `cloudbackup.management` | **N2** | N-able, older or product domains |
| Exact `keybox.solarwindsmsp.com`, `swi-rc.cdn-sw.net` | **N2** (exact) | Legacy SolarWinds MSP |
| Exact 11 FortiClient names | **N3** (exact) | EMS Cloud, FortiGuard for FortiClient |
| `datto.com` sign-in, `fortinet.net`, `forticloud.com`, `aptctrl1.fortinet.com`, SentinelOne, PubNub, LaunchDarkly | not mapped or other ids | Shared |

## 6. Synthetic test vectors

Checked with `attribution_for_host` in scratch (`c08773f` plus D to I, R, L, J, K, M, N and O): all as expected.

| # | Input | Expected |
|---|---|---|
| P1 | SNI `syrah.centrastage.net`, `agent-gateway.syrah.rmm.datto.com` | `datto-rmm` (today unmapped) |
| P2 | SNI `sis.n-able.com`, `checks-api.us.system-monitor.com`, `upload1.am.remote.management`, `rm-downloads.logicnow.com` | `n-able` (today unmapped) |
| P3 | SNI `www.n-able.com` | `n-able` (web front) |
| P4 | SNI `forticlient.forticloud.com`, `fctguard.fortinet.net` | `forticlient` (today unmapped) |
| N1 | SNI `auth.datto.com`, `x.solarwindsmsp.com`, `x.cdn-sw.net`, `aptctrl1.fortinet.com`, `www.forticloud.com`, `xcentrastage.net` | no application |
| N2 | SNI `x.sentinelone.net` | `sentinelone`, not `n-able` |

<!-- method-v2-vectors:start -->

### Method v2 vectors (checked 2026-11-20 against `c08773f` plus batches D to I, R, L, J, K, M, N, O and P as rebuilt 2026-11-22)

O+ = observed app-owned host (positive); D- = observed dependency (must not be this app); L- = look-alike or label-boundary name (must not be this app).

| Kind | Input SNI | Expected | Result today | Check |
|---|---|---|---|---|
| L- | `xcentrastage.net` | not datto-rmm/n-able/forticlient (label boundary) | no application | PASS |
| L- | `centrastage.net.example.invalid` | not datto-rmm/n-able/forticlient (suffix look-alike) | no application | PASS |
| L- | `xdatto.com` | not datto-rmm/n-able/forticlient (label boundary) | no application | PASS |
| L- | `rmm.datto.com.example.invalid` | not datto-rmm/n-able/forticlient (suffix look-alike) | no application | PASS |
| L- | `xn-able.com` | not datto-rmm/n-able/forticlient (label boundary) | no application | PASS |
| L- | `n-able.com.example.invalid` | not datto-rmm/n-able/forticlient (suffix look-alike) | no application | PASS |

<!-- method-v2-vectors:end -->

## 7. Sources

- [D] Datto RMM Help, allow-list requirements, `https://rmm.datto.com/help/en/Content/1INTRODUCTION/Requirements/AllowListRequirements.htm`, read by Research Lab from the Hermes server (PRO-95), relayed by Hermes (PRO-106), 2026-11-22; no page dates relayed.
- [NC] N-able N-central User Guide, firewall requirements, `https://documentation.n-able.com/N-central/userguide/Content/ReleaseDocs/Install_Config/FirewallRequirements.htm`, read by Research Lab from the Hermes server (PRO-95), relayed by Hermes (PRO-106), 2026-11-22; no page dates relayed.
- [NS] N-able N-sight RMM, agent upload URLs, `https://documentation.n-able.com/remote-management/userguide/Content/agent_upload_urls.htm`, read by Research Lab from the Hermes server (PRO-95), relayed by Hermes (PRO-106), 2026-11-22; no page dates relayed.
- [F] Fortinet, FortiClient 7.2.4 Administration Guide, required services and ports, `https://docs.fortinet.com/document/forticlient/7.2.4/administration-guide/539869/required-services-and-ports`, read by Research Lab from the Hermes server (PRO-95), relayed by Hermes (PRO-106), 2026-11-22; no page dates relayed.
- [FS] Fortinet, FortiSASE Administration Guide, ports, `https://docs.fortinet.com/document/fortisase/latest/administration-guide/539869`, read by Research Lab from the Hermes server (PRO-95), relayed by Hermes (PRO-106), 2026-11-22; no page dates relayed.

## 8. Catalog delta and recommendation

```python
("datto-rmm", "networking", "remote-access", "client-server", 4, "Datto RMM remote monitoring and management",
 ("tunnels-other-applications", "prone-to-misuse", "used-by-malware"), ("centrastage.net", "rmm.datto.com")),
("n-able", "networking", "remote-access", "client-server", 4, "N-able RMM (N-central, N-sight) and Take Control remote access",
 ("tunnels-other-applications", "prone-to-misuse", "used-by-malware"),
 ("n-able.com", "system-monitor.com", "systemmonitor.eu.com", "logicnow.com", "logicnow.us", "remote.management", "beanywhere.com",
  "keybox.solarwindsmsp.com", "swi-rc.cdn-sw.net", "cloudbackup.management"), ("n-able.com", "www.n-able.com")),
("forticlient", "business-systems", "management", "client-server", 2,
 "Fortinet FortiClient endpoint agent and FortiClient Cloud (EMS)", (),
 ("forticlient.forticloud.com", "forticlient-emsproxy.forticloud.com", "fctguard.fortinet.net", "fctusguard.fortinet.net",
  "fcteuguard.fortinet.net", "forticlient.fortinet.net", "myforticlient.fortinet.net", "usforticlient.fortinet.net",
  "fctupdate.fortinet.net", "fctusupdate.fortinet.net", "fcteuupdate.fortinet.net")),
```

`forticlient` takes the `sophos` attributes (endpoint security agent, risk 2). FortiSASE has no names to add.

<!-- method-v2:start -->

## 9. Live verification (L)

Source: live-verified by Hermes from an unproxied vantage, 2026-11-20, rounds 1 and 2 (`research/live-results-2026-11-20.tsv`, `research/live-results-2026-11-20-r2.tsv`), and rounds 3 to 7 of 2026-11-21 and 2026-11-22 where they have the name (`research/live-results-2026-11-21-r3.tsv`, `-r4.tsv`, `-r5.tsv`, `research/live-results-2026-11-22-r6.tsv`, `-r7.tsv`; tool `research/tools/live_verify.py`, DoH DNS and direct TLS; round 2 adds certificate organisation and probes). `L` never raises a name above its primary-source level; a CDN-fronted name is usable as a name but its IPs are never evidence.

| Catalog name | Live result (2026-11-20) |
|---|---|
| `centrastage.net` | apex has no address (normal for a suffix entry); suffix **verified** through documented `syrah.centrastage.net` (round 6); verdict (PRO-146): **supports**, moderately (live; Amazon domain-validated certificate) |
| `rmm.datto.com` | round 6 (2026-11-22); **L** resolves; TLSv1.3, ALPN `h2`, TLS via documented probe `syrah.rmm.datto.com`, probe cert `syrah.rmm.datto.com`, no subject organisation (domain-validated) (issuer Amazon); verdict (PRO-146): **supports**, moderately (live; Amazon domain-validated certificate) |
| `n-able.com` | round 6 (2026-11-22); **L** resolves; TLSv1.3, ALPN `http/1.1`, TLS via documented probe `sis.n-able.com`, probe cert `sis.n-able.com`, no subject organisation (domain-validated) (issuer Let's Encrypt) |
| `system-monitor.com` | round 6 (2026-11-22); **L** resolves; TLSv1.3, ALPN `h2`, TLS via documented probe `checks-api.us.system-monitor.com`, probe cert `*.us.system-monitor.com`, no subject organisation (domain-validated) (issuer Let's Encrypt) |
| `systemmonitor.eu.com` | apex has no address (normal for a suffix entry); suffix **verified** through documented `upload1europe1.systemmonitor.eu.com` (round 6, cdn); verdict (PRO-146): stays **N2**: domain-validated certificate, no organisation; promotion needs a vendor page or a WHOIS-class source, not a handshake |
| `logicnow.com` | apex has no address (normal for a suffix entry); suffix **verified** through documented `rm-downloads.logicnow.com` (round 6) |
| `logicnow.us` | apex has no address (normal for a suffix entry); suffix **verified** through documented `cannonball-us-west-2-push.logicnow.us` (round 6, cdn); verdict (PRO-146): stays **N2**: domain-validated certificate, no organisation; promotion needs a vendor page or a WHOIS-class source, not a handshake |
| `remote.management` | apex has no address (normal for a suffix entry); suffix **verified** through documented `upload1.am.remote.management` (round 6, cdn); verdict (PRO-146): stays **N2**: domain-validated certificate, no organisation; promotion needs a vendor page or a WHOIS-class source, not a handshake |
| `beanywhere.com` | apex has no address (normal for a suffix entry); no documented subdomain to probe (wildcard-only source); verdict (PRO-146): stays **N2**: domain-validated certificate, no organisation; promotion needs a vendor page or a WHOIS-class source, not a handshake |
| `keybox.solarwindsmsp.com` | round 6 (2026-11-22); **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `keybox-ncentral.us-west-2.prd.sharedsvcs.system-monitor.com`, no subject organisation (domain-validated) (issuer Let's Encrypt) |
| `swi-rc.cdn-sw.net` | round 6 (2026-11-22); **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `swi-rc.cdn-sw.net`, no subject organisation (domain-validated) (issuer DigiCert Inc) |
| `cloudbackup.management` | round 6 (2026-11-22); **L** resolves; TLSv1.3, ALPN `http/1.1`, TLS via documented probe `integrated.cloudbackup.management`, probe cert `cloudbackup.management`, no subject organisation (domain-validated) (issuer Google Trust Services); verdict (PRO-146): stays **N2**: domain-validated certificate, no organisation; promotion needs a vendor page or a WHOIS-class source, not a handshake |
| `forticlient.forticloud.com` | round 6 (2026-11-22); **L** resolves; TLSv1.3, ALPN `http/1.1`, cert `forticlient.forticloud.com`, subject organisation **Fortinet, Inc.** (issuer DigiCert Inc); CNAME into shared front end `a8003824a2c314586a0a6226b8e83253-0a9dee96d89470ea.elb.us-west-2.amazonaws.com`: name usable, IPs never; verdict (PRO-146): **supports** (certificate organisation Fortinet, Inc.) |
| `forticlient-emsproxy.forticloud.com` | round 6 (2026-11-22); resolves; TLS handshake failed (SSLEOFError, round 6): not a removal reason |
| `fctguard.fortinet.net` | round 6 (2026-11-22); resolves; TLS handshake failed (SSLCertVerificationError, round 6): not a removal reason; verdict (PRO-146): **neutral**: alive in Fortinet's zone; certificate verification failed, which is not removal |
| `fctusguard.fortinet.net` | round 6 (2026-11-22); resolves; TLS handshake failed (SSLCertVerificationError, round 6): not a removal reason; verdict (PRO-146): **neutral**: alive in Fortinet's zone; certificate verification failed, which is not removal |
| `fcteuguard.fortinet.net` | round 6 (2026-11-22); resolves; TLS handshake failed (SSLCertVerificationError, round 6): not a removal reason; verdict (PRO-146): **neutral**: alive in Fortinet's zone; certificate verification failed, which is not removal |
| `forticlient.fortinet.net` | round 6 (2026-11-22); resolves; TLS handshake failed (SSLCertVerificationError, round 6): not a removal reason; verdict (PRO-146): **neutral**: alive in Fortinet's zone; certificate verification failed, which is not removal |
| `myforticlient.fortinet.net` | round 6 (2026-11-22); resolves; TLS handshake failed (SSLCertVerificationError, round 6): not a removal reason; verdict (PRO-146): **neutral**: alive in Fortinet's zone; certificate verification failed, which is not removal |
| `usforticlient.fortinet.net` | round 6 (2026-11-22); resolves; TLS handshake failed (SSLCertVerificationError, round 6): not a removal reason; verdict (PRO-146): **neutral**: alive in Fortinet's zone; certificate verification failed, which is not removal |
| `fctupdate.fortinet.net` | round 6 (2026-11-22); resolves; TLS handshake failed (SSLCertVerificationError, round 6): not a removal reason; verdict (PRO-146): **neutral**: alive in Fortinet's zone; certificate verification failed, which is not removal |
| `fctusupdate.fortinet.net` | round 6 (2026-11-22); resolves; TLS handshake failed (SSLCertVerificationError, round 6): not a removal reason; verdict (PRO-146): **neutral**: alive in Fortinet's zone; certificate verification failed, which is not removal |
| `fcteuupdate.fortinet.net` | round 6 (2026-11-22); resolves; TLS handshake failed (SSLCertVerificationError, round 6): not a removal reason; verdict (PRO-146): **neutral**: alive in Fortinet's zone; certificate verification failed, which is not removal |

## 10. Observed web-client hosts (dependency mapping)

No public web client or login page for this application (desktop agent, tenant-specific console or API only).

## 11. Attributes (App-ID model) and re-verify date

- `datto-rmm`: networking / remote-access, client-server; characteristics `tunnels-other-applications`, `prone-to-misuse`, `used-by-malware`; **risk 4**: carries other traffic or remote control; commonly misused (unsanctioned remote access, data exfiltration); seen in malware campaigns.
- `n-able`: networking / remote-access, client-server; characteristics `tunnels-other-applications`, `prone-to-misuse`, `used-by-malware`; **risk 4**: carries other traffic or remote control; commonly misused (unsanctioned remote access, data exfiltration); seen in malware campaigns.
- `forticlient`: business-systems / management, client-server; characteristics none; **risk 2**: no risk-raising characteristic recorded; rating from its category.
- Functions separated by name: `datto-rmm` (Datto RMM remote monitoring and management), `n-able` (N-able RMM (N-central, N-sight) and Take Control remote access), `forticlient` (Fortinet FortiClient endpoint agent and FortiClient Cloud (EMS)).
- Variant: not separated by name.
- Dependencies (observed, never attributed to this app): none observed.
- Evasive (ECH, DoH, proxy modes): no ECH parameter in any verified name's HTTPS record (2026-11-20); other modes as stated in sections 2 to 4.
- QUIC path (`h3` in the HTTPS record): none advertised.
- Re-verify by: **2027-02-18** (`research/tools/recheck_sources.py` tracks the cited pages).

<!-- method-v2:end -->
