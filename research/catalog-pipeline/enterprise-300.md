# Enterprise priority list: wave 1 (PRO-491 part B)

Research only; nothing changes in the pack (release 2026.11.9, 544 apps). Wave 1 = 65 services **not in the pack** (PRO-495 covers the 30 already in it). Waves 2+ (to ~300) follow; the other classes (SaaS collaboration, social media at scale) are not in wave 1.

Method: 7 research passes over public vendor pages only (WebSearch/WebFetch, no sign-in, no traffic). A domain is listed under `domains` only if an official vendor page names it (URL + short quote in `enterprise-300/wave1/*.json`); everything else is `unsourced`. Pack overlap = the domain already appears in the pack host catalog (805 domains), checked by grep. Order: class by enterprise block priority (remote access, VPN, anonymizers, file sharing, GenAI, webmail, messaging, social, code/paste, crypto, P2P), then name; a numeric rank comes with wave 2.

Separability legend (Culvert = proxy seeing SNI and, with TLS inspection, HTTP): **sni** distinct hostname in the handshake; **http** needs host/path/method after inspection; **pattern** only traffic-pattern detection; **no** not separable.

## Headline

| | n |
|---|---|
| services | 65 |
| confidence high / medium / low | 9 / 21 / 35 |
| sub-functions: sni / http / pattern / no | 101 / 42 / 27 / 11 |

Many low-confidence rows come from vendors that publish no network-requirements page or block fetches (403): their domains sit in `domains_unsourced` and must not enter the pack without a capture.

## Services

| # | service | class | status | pack overlap | sourced domains | conf |
|---|---|---|---|---|---|---|
| 1 | Amazon WorkSpaces (`amazon-workspaces`) | remote-access | active | none (amazonaws.com S3 entries in pack are specific unrelated buckets; no amazonworkspaces.com or awsapps.com) | *.<region>.rdn.amazonaws.com, <dirid>.awsapps.com, clients.amazonworkspaces.com, connectivity.amazonworkspaces.com, drp-<airport>.amazonworkspaces.com, skylight-cm.<region>.amazonaws.com | high |
| 2 | Citrix Workspace / Virtual Apps and Desktops (Citrix DaaS) (`citrix-workspace-daas`) | remote-access | active | partial: windows.net/servicebus-type Azure hosts and digicert.com are generic; no Citrix domain (citrix.com, cloud.com, citrixworkspacesapi.net, nssvc.net) in pack | *.citrixworkspacesapi.net, *.cloud.com, *.netscalergateway.net, *.nssvc.net, *.wsp.cloud.com, [customerid].xendesktop.net | high |
| 3 | HopToDesk (`hoptodesk`) | remote-access | active | none (no hoptodesk domains in pack) | api.hoptodesk.com, dashboard.hoptodesk.com, dl.hoptodesk.com, signal.hoptodesk.com, turn-eu.hoptodesk.com, turn.hoptodesk.com | high |
| 4 | Omnissa Horizon (ex VMware Horizon) (`omnissa-horizon`) | remote-access | rebranded:Omnissa Horizon (from VMware Horizon, 2024) | none (no omnissa.com, vmware.com or horizon domains found in pack) | (none sourced) | low |
| 5 | Radmin (`radmin`) | remote-access | active | none (no radmin or famatech domains in pack) | helpdesk.radmin.com | medium |
| 6 | Sunlogin (Oray AweSun) (`sunlogin-awesun`) | remote-access | active | none (no oray domains in pack) | *.oray.com, client.oray.net | low |
| 7 | ToDesk (`todesk`) | remote-access | active | none (no todesk domains in pack) | (none sourced) | low |
| 8 | Twingate (`twingate`) | remote-access | active | none | api.twingate.com, binaries.twingate.com, pubnub.com, relays.twingate.com, saml.twingate.com, twingate.com | high |
| 9 | Windows 365 / Azure Virtual Desktop (`windows-365-avd`) | remote-access | active | partial: microsoft.com, microsoftonline.com, office.com, office.net, events.data.microsoft.com, digicert.com, windowsupdate.com already in pack (app unknown); AVD-specific hosts not present | *.cdn.office.net, *.service.windows.cloud.microsoft, *.windows.cloud.microsoft, *.windows.static.microsoft, *.wvd.microsoft.com, login.microsoftonline.com | high |
| 10 | Astrill VPN (`astrill-vpn`) | vpn | active | none | (none sourced) | low |
| 11 | Browsec (`browsec`) | vpn | active | none | browsec.com, browsec.cx, browsec.zendesk.com, bs-dl.s3.eu-central-1.amazonaws.com | low |
| 12 | Cisco Secure Client (AnyConnect) (`cisco-secure-client`) | vpn | active | none | ocsp.digicert.com, software.cisco.com | low |
| 13 | Fortinet FortiClient VPN (`fortinet-forticlient-vpn`) | vpn | active | none | aptctrl1.fortinet.com, fctguard.fortinet.net, fctupdate.fortinet.net, forticlient.forticloud.com, forticlient.fortinet.net, myforticlient.fortinet.net | medium |
| 14 | Hola VPN (`hola-vpn`) | vpn | active | none | cdn4.hola.org, hola.org, support.hola.org | low |
| 15 | Ivanti Connect Secure (`ivanti-connect-secure`) | vpn | active | none | download.pulsesecure.net, forums.ivanti.com, help.ivanti.com, pcls.pulseone.net, service.pulsesecure.net | low |
| 16 | Opera VPN (`opera-vpn`) | vpn | active | none | (none sourced) | low |
| 17 | Palo Alto GlobalProtect (`paloalto-globalprotect`) | vpn | active | partial: googleapis.com already under (unknown app) - storage.googleapis.com is a shared bypass host | apps.paloaltonetworks.com, docs.paloaltonetworks.com, epm.gpcloudservice.com, filter.paloaltonetworks.com, storage.googleapis.com | low |
| 18 | PureVPN (`purevpn`) | vpn | active | none | (none sourced) | low |
| 19 | TorGuard (`torguard`) | vpn | active | none | torguard.net, www.torguard.net | low |
| 20 | Urban VPN (`urban-vpn`) | vpn | active | none | premium.urban-vpn.com, www.urban-vpn.com | low |
| 21 | VyprVPN (`vyprvpn`) | vpn | active | none | (none sourced) | low |
| 22 | X-VPN (`x-vpn`) | vpn | active | none | xvpn.io | low |
| 23 | Bright Data (`bright-data`) | proxy-anonymizer | active | none | api.brightdata.com, brd.superproxy.io, brdtest.com, brightdata.com, docs.brightdata.com, geo.brdtest.com | high |
| 24 | CroxyProxy (`croxyproxy`) | proxy-anonymizer | active | none | (none sourced) | low |
| 25 | Baidu Netdisk (`baidu-netdisk`) | file-sharing | active | partial: baidu.com already under an app (domain only) | (none sourced) | low |
| 26 | Citrix ShareFile (`citrix-sharefile`) | file-sharing | active | none | securevdr.com, sf-api.com, sf-api.eu, sf-cdn.net, sharefile.com, sharefile.eu | high |
| 27 | Filemail (`filemail`) | file-sharing | active | none | api-public.filemail.com, docs.filemail.com, filemail.com | medium |
| 28 | Pixeldrain (`pixeldrain`) | file-sharing | active | none | docs.pixeldrain.com, pixeldrain.com | high |
| 29 | Smash (fromsmash.com) (`smash`) | file-sharing | active | none | api.fromsmash.com, developer.fromsmash.com, fromsmash.com | low |
| 30 | SwissTransfer (Infomaniak) (`swisstransfer`) | file-sharing | active | none | infomaniakusercontent.com, ksharelink.com, swisstransfer.com | low |
| 31 | Terabox (`terabox`) | file-sharing | active | none | (none sourced) | low |
| 32 | Tresorit (`tresorit`) | file-sharing | active | none | (none sourced) | low |
| 33 | Yandex Disk (`yandex-disk`) | file-sharing | active | partial: yandex.net, yandex.ru, yandex.com already under an app (domain only) | cloud-api.yandex.net, dst.yandex.net | medium |
| 34 | Bolt.new (`bolt-new`) | genai | active | none | bolt.new, support.bolt.new | low |
| 35 | DeepL (`deepl`) | genai | active | none | api-free.deepl.com, api.deepl.com, developers.deepl.com | medium |
| 36 | Gamma (`gamma`) | genai | active | none | mcp.gamma.app, public-api.gamma.app | medium |
| 37 | Kimi (Moonshot AI) (`kimi-moonshot`) | genai | active | none | api.moonshot.ai, platform.kimi.ai | medium |
| 38 | Lovable (`lovable`) | genai | active | none | docs.lovable.dev, lovable.app, lovable.dev | medium |
| 39 | Manus (`manus`) | genai | active | none | api.manus.ai, open.manus.ai | low |
| 40 | Otter.ai (`otter-ai`) | genai | active | none | (none sourced) | low |
| 41 | Hey.com (`hey-com`) | webmail | active | none | app.hey.com, help.hey.com, hey.com | medium |
| 42 | Mail.ru webmail (`mail-ru`) | webmail | active | none | imap.mail.ru, pop.mail.ru, smtp.mail.ru | medium |
| 43 | Temp-Mail (temp-mail.io disposable email) (`temp-mail`) | webmail | active | none | api.temp-mail.io, docs.temp-mail.io | medium |
| 44 | DingTalk (`dingtalk`) | messaging | active | none | oapi.dingtalk.io | low |
| 45 | Feishu/Lark (`feishu-lark`) | messaging | active | none | open.feishu.cn, open.larksuite.com | medium |
| 46 | Mattermost (`mattermost`) | messaging | active | none | (none sourced) | low |
| 47 | WeCom (WeChat Work) (`wecom`) | messaging | active | partial: weixin.qq.com already under unknown app (WeCom hosts qyapi/work/developer.work.weixin.qq.com are subdomains) | qyapi.weixin.qq.com, work.weixin.qq.com, wwcdn.weixin.qq.com | medium |
| 48 | Wire (`wire`) | messaging | active | none | prod-nginz-ssl.wire.com, sft.calling-prod-v01.wire.com, turn.calling-prod-v01.wire.com | medium |
| 49 | Mastodon (mastodon.social) (`mastodon`) | social | active | none | (none sourced) | low |
| 50 | Truth Social (`truth-social`) | social | active | none | help.truthsocial.com | low |
| 51 | Azure DevOps (`azure-devops`) | code-paste | active | partial: visualstudio.com and vsassets.io already in pack (app unknown); dev.azure.com not present | dev.azure.com, download.agent.dev.azure.com, login.microsoftonline.com, ssh.dev.azure.com, vsassets.io, vsrm.dev.azure.com | high |
| 52 | Bitbucket Cloud (`bitbucket`) | code-paste | active | partial: bitbucket.org and atlassian.com already in pack (app unknown) | altssh.bitbucket.org, api.bitbucket.org, bitbucket.org, ssh.bitbucket.org | medium |
| 53 | Codeberg (`codeberg`) | code-paste | active | none | codeberg.org, codeberg.page, design.codeberg.org, docs.codeberg.org | medium |
| 54 | Rentry (`rentry`) | code-paste | active | none | rentry.co | medium |
| 55 | Bitget (`bitget`) | crypto | active | none | api.bitget.com, capi.bitget.com | low |
| 56 | Bybit (`bybit`) | crypto | active | none | api-testnet.bybit.com, api.bybit.com, api.bybit.eu, api.bytick.com, stream-testnet.bybit.com, stream.bybit.com | medium |
| 57 | KuCoin (`kucoin`) | crypto | active | none | api-broker.kucoin.com, api-futures.kucoin.com, api.kucoin.com, ws-api-futures.kucoin.com, ws-api-spot.kucoin.com, wsapi-push.kucoin.com | medium |
| 58 | Ledger Live (`ledger-live`) | crypto | active | none | (none sourced) | low |
| 59 | OKX (`okx`) | crypto | active | none | eea.okx.com, openapi.okx.com, us.okx.com, ws.okx.com, wspap.okx.com, www.okx.com | medium |
| 60 | Trust Wallet (`trust-wallet`) | crypto | active | none | mcp.trustwallet.com, portal.trustwallet.com, tws.trustwallet.com | low |
| 61 | Uniswap (`uniswap`) | crypto | active | none | developers.uniswap.org, gateway.thegraph.com | low |
| 62 | Resilio Sync (`resilio-sync`) | p2p | active | none | config.resilio.com, connect-license.resilio.com, feedback.resilio.com, upload.resilio.com | low |
| 63 | Soulseek (`soulseek`) | p2p | active | none | (none sourced) | low |
| 64 | qBittorrent (`qbittorrent`) | p2p | active | none | (none sourced) | medium |
| 65 | uTorrent (`utorrent`) | p2p | active | none | (none sourced) | low |

## Sub-functions and separability

### Amazon WorkSpaces

- **client-registration-update** [sni] `clients.amazonworkspaces.com`: Distinct vendor hostname ([doc](https://docs.aws.amazon.com/workspaces/latest/adminguide/workspaces-port-requirements.html))
- **broker-api** [sni] `ws-broker-service.<region>.amazonaws.com`: Regional AWS hostnames; shared parent amazonaws.com ([doc](https://docs.aws.amazon.com/workspaces/latest/adminguide/workspaces-port-requirements.html))
- **login** [sni] `<region>.signin.aws, <dirid>.awsapps.com`: Shared with other AWS sign-in ([doc](https://docs.aws.amazon.com/workspaces/latest/adminguide/workspaces-port-requirements.html))
- **streaming-pcoip-wsp-dcv** [pattern] `TCP/UDP 4172, 4195 to AWS IP ranges`: Streaming goes to IPs, no hostname ([doc](https://docs.aws.amazon.com/workspaces/latest/adminguide/workspaces-port-requirements.html))
- **web-access-turn** [sni] `*.rdn.amazonaws.com`:  ([doc](https://docs.aws.amazon.com/workspaces/latest/adminguide/workspaces-port-requirements.html))

_Note: Client-facing hostnames are clear; streaming runs on ports to AWS IP ranges. DCV proxy not recommended, TLS inspection unsupported._

### Citrix Workspace / Virtual Apps and Desktops (Citrix DaaS)

- **base-login** [sni] `accounts.cloud.com / login.cloud.com / saml.cloud.com`: Distinct auth hostnames ([doc](https://docs.citrix.com/en-us/citrix-cloud/overview/requirements/internet-connectivity-requirements))
- **gateway-service-session** [sni] `*.nssvc.net (ICA proxy via Gateway Service)`: Official page says no SSL interception; SNI only ([doc](https://docs.citrix.com/en-us/citrix-cloud/overview/requirements/internet-connectivity-requirements))
- **cloud-connector-control** [sni] `*.citrixworkspacesapi.net, *.servicebus.windows.net`: Admin/connector plane; servicebus shared with other Azure apps ([doc](https://docs.citrix.com/en-us/citrix-cloud/overview/requirements/internet-connectivity-requirements))
- **workspace-app-config** [sni] `*.wsp.cloud.com`: Store and personalization for Workspace app ([doc](https://docs.citrix.com/en-us/citrix-cloud/overview/requirements/internet-connectivity-requirements))
- **on-prem-storefront-gateway** [no] `customer-hosted Gateway/StoreFront FQDN`: Self-hosted; no vendor domain ([doc](https://docs.citrix.com/en-us/citrix-daas/overview/technical-security-overview))

_Note: Cloud-side domains well documented; on-prem Virtual Apps and Desktops uses customer-owned hostnames, not catalog-matchable. Allowlist API provides per-customer FQDNs._

### HopToDesk

- **signal** [sni] `signal.hoptodesk.com TCP 80/443`: Distinct hostname ([doc](https://help.hoptodesk.com/))
- **relay** [sni] `turn*.hoptodesk.com, ports 1001-65535 or 443`: Port-443 fallback on relays ([doc](https://help.hoptodesk.com/))
- **api-dashboard** [sni] `api.hoptodesk.com, dashboard.hoptodesk.com`:  ([doc](https://help.hoptodesk.com/))
- **update** [sni] `dl.hoptodesk.com`:  ([doc](https://help.hoptodesk.com/))
- **direct-p2p** [pattern] `random TCP/UDP; inbound 21118`: No hostname ([doc](https://help.hoptodesk.com/))

_Note: Help center lists allowlist domains and ports explicitly. Direct connections use IP only. Relay is also sourced from the page, other turn-* regions omitted._

### Omnissa Horizon (ex VMware Horizon)

- **client-to-gateway** [pattern] `tcp 443, 8443 client-facing; 8444 agent-facing`: Ports only; hostnames are customer-owned UAG/Connection Server ([doc](https://learn.microsoft.com/en-us/windows-365/enterprise/requirements-omnissa-horizon))

_Note: Horizon is mostly customer-hosted (UAG, Connection Server); only the cloud control plane has vendor domains, which I could not verify from official docs._

### Radmin

- **viewer-server-session** [pattern] `TCP 4899 direct to Radmin Server (default)`: Direct IP:port, no hostname; port is configurable 1-65535 ([doc](https://helpdesk.radmin.com/kb/faq.php?id=328))
- **radmin-vpn** [no] `radmin-vpn.com (unverified)`: Separate product; endpoints not confirmed ([doc](https://www.radmin-vpn.com/help/))

_Note: Radmin is mainly direct viewer to server on TCP 4899 with no vendor-hosted relay, so there is little domain-level signal. Detect by port or protocol only._

### Sunlogin (Oray AweSun)

- **base-control** [sni] `*.oray.com TCP 443`: Wildcard oray.com also covers Oray's other products ([doc](https://service.oray.com/question/1082.html))
- **p2p-udp** [pattern] `UDP 3008`: Port-based only ([doc](https://service.oray.com/question/1082.html))
- **login** [sni] `passport.oray.com`: Oray shared account host ([doc](https://service.oray.com/question/1082.html))

_Note: Official Oray FAQ is dated Dec 2021; ports/domains came via search summary, and a direct fetch did not confirm them. The ports article is a separate page._

### ToDesk

- **base** [no] `todesk.com (not verified)`: No official endpoint documentation found ([doc](https://www.todesk.com/))

_Note: Searches in English and Chinese returned no official ToDesk network-requirements page. Chinese vendor; service domains unverified._

### Twingate

- **tenant-login** [sni] `<network>.twingate.com / <network>.<region>.twingate.com`: Per-tenant hostname ([doc](https://help.twingate.com/hc/en-us/articles/14142225907485))
- **relay** [sni] `relays*.twingate.com TCP 443, 30000-31000`: Relay fallback ([doc](https://help.twingate.com/hc/en-us/articles/14142225907485))
- **p2p-stun** [pattern] `stun.<region>.twingate.com UDP`: Peer-to-peer UDP ([doc](https://help.twingate.com/hc/en-us/articles/14142225907485))
- **api** [sni] `api.twingate.com`: Control API ([doc](https://help.twingate.com/hc/en-us/articles/14142225907485))

_Note: Official allowlist article lists FQDNs, relay and STUN hosts; tenant subdomain identifies customer._

### Windows 365 / Azure Virtual Desktop

- **service-gateway** [sni] `*.wvd.microsoft.com, *.windows.cloud.microsoft`: Distinct hostnames; AVD and Windows 365 share them ([doc](https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint))
- **login** [no] `login.microsoftonline.com`: Shared Entra ID auth ([doc](https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint))
- **rdp-shortpath-relay** [pattern] `UDP 3478 to 51.5.0.0/16`: IP/port only ([doc](https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint))
- **windows-365-web-client** [sni] `windows365.microsoft.com`: Windows 365 specific host ([doc](https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint))
- **session-rdp-gateway** [http] `TCP 443 via *.wvd.microsoft.com`: Cannot distinguish AVD vs W365 at SNI ([doc](https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint))

_Note: AVD and Windows 365 share endpoints, so they can't be split. Microsoft says blocking these is unsupported. Overlaps with shipped Microsoft domains._

### Astrill VPN

- **base** [no] `astrill.com`: No official endpoint documentation found ([doc](https://www.astrill.com))

_Note: No official network-requirements page found. Consumer VPN with obfuscation (StealthVPN); likely traffic-pattern detection only._

### Browsec

- **base** [sni] `browsec.com`: Marketing/FAQ ([doc](https://browsec.com/en/faq))
- **help** [sni] `browsec.zendesk.com`: Support portal ([doc](https://browsec.com/en/faq))
- **proxy-tunnel** [pattern] `HTTP Proxy over TLS, host not named`: FAQ states protocol; no hostname published ([doc](https://browsec.com/en/faq))

_Note: FAQ says extension uses HTTP proxy over TLS but names no proxy/API host. Download mirrors are s3/browsec.cx; mirror domains may rotate._

### Cisco Secure Client (AnyConnect)

- **base-tunnel** [sni] `customer gateway hostname TCP/UDP 443 (TLS/DTLS)`: Per-customer gateway hostnames, no vendor-wide domain ([doc](https://docs.umbrella.com/umbrella-user-guide/docs/prerequisites-5))
- **swg-module** [pattern] `Umbrella SWG CIDRs TCP 80/443`: Doc lists IP CIDRs, not hostnames ([doc](https://docs.umbrella.com/umbrella-user-guide/docs/prerequisites-5))

_Note: Enterprise headend is customer-hosted; only download and CRL/OCSP hosts sourced. Prerequisites page fetch via securitydocs failed; relied on search snippets._

### Fortinet FortiClient VPN

- **vpn-tunnel** [sni] `FortiGate SSL VPN TCP 443; IPsec UDP 500/4500, ESP`: Customer FortiGate hostname; IPsec not SNI-visible ([doc](https://docs.fortinet.com/document/forticlient/7.2.4/administration-guide/539869/required-services-and-ports))
- **ems-cloud** [sni] `forticlient.forticloud.com:443`: Management channel ([doc](https://docs.fortinet.com/document/forticlient/7.2.4/administration-guide/539869/required-services-and-ports))
- **updates** [sni] `fctupdate.fortinet.net:443`: Signature updates ([doc](https://docs.fortinet.com/document/forticlient/7.2.4/administration-guide/539869/required-services-and-ports))

_Note: VPN endpoint is customer-hosted FortiGate; vendor domains are for management, updates, web filter._

### Hola VPN

- **base** [sni] `hola.org`: Web/account distinct host ([doc](https://hola.org/faq))
- **download** [http] `hola.org/download/android`: Path on main host; needs HTTP visibility ([doc](https://hola.org/faq))
- **proxy-tunnel** [pattern] `HTTPS proxy / IKEv2, no hostname published`: Official FAQ names protocol but no hosts ([doc](https://hola.org/faq))

_Note: Official docs publish no network-requirements list; proxy agent hostnames not officially documented. Hola FAQ also references Bright Data as commercial arm._

### Ivanti Connect Secure

- **vpn-tunnel** [sni] `customer ICS gateway TCP 443 (ESP/SSL)`: Customer-hosted gateway ([doc](https://help.ivanti.com/ps/help/en_US/ICS/22.x/22.7R2.8/spg/client_env_contents.htm))
- **hostchecker-updates** [sni] `download.pulsesecure.net`: Signature download ([doc](https://help.ivanti.com/ps/help/en_US/IPS/22.x/ag/ips_enforcement_modes.htm))

_Note: Allow-list page is Ivanti Policy Secure docs (same client family); applicability to Connect Secure inferred._

### Opera VPN

- **api-bootstrap** [sni] `api.sec-tunnel.com (community-reported)`: Unofficial evidence; credentials/server list fetch ([doc](https://forums.opera.com/post/329740))
- **proxy-tunnel** [pattern] `opera-proxy.net / surfeasy hosts (community-reported)`: Reports say blocking domains alone insufficient; traffic shifts to IPs ([doc](https://forums.opera.com/post/329740))

_Note: No official Opera network doc; domains only from third-party/community. Built-in browser VPN (SurfEasy backend); operacdn pattern unconfirmed._

### Palo Alto GlobalProtect

- **portal-prelogin** [http] `<portal-fqdn>/global-protect/prelogin.esp`: Same host as portal; path needs TLS inspection ([doc](https://docs.paloaltonetworks.com/prisma-agent/administration/prerequisites/prisma-agent-fqdns-and-ports))
- **portal-getconfig** [http] `<portal-fqdn>/global-protect/getconfig.esp`: Path-level ([doc](https://docs.paloaltonetworks.com/prisma-agent/administration/prerequisites/prisma-agent-fqdns-and-ports))
- **gateway-tunnel** [sni] `<gateway-fqdn> TCP 443 SSL / ESP UDP`: Customer-hosted gateway hostname ([doc](https://docs.paloaltonetworks.com/prisma-agent/administration/prerequisites/prisma-agent-fqdns-and-ports))

_Note: Sourced page is Prisma Agent, not classic GlobalProtect app; portal/gateway are customer or Prisma Access hosted._

### PureVPN

- **tunnel** [pattern] `OpenVPN UDP 53, TCP 80; SSTP 443; IKEv2/IPsec`: Port based; server hostnames not documented ([doc](https://purevpn2.helpjuice.com/en_US/general-articles/on-what-ports-purevpn-work-and-should-i-allow-them-on-my-anti-virus-programfirewall))

_Note: Official support lists protocol ports; no official domain list found._

### TorGuard

- **base** [sni] `torguard.net`: Web/support/account ([doc](https://torguard.net/support/))
- **vpn-tunnel** [pattern] `per-server hostnames, not enumerated in fetched docs`: OpenVPN/WireGuard on varied ports; IP/port based ([doc](https://torguard.net/support/articles/TorGuard-Software-Features/getting-started-port-forwarding.php))

_Note: Official fetch blocked (403) for some pages; no network-requirements doc found. Server hostnames not verified._

### Urban VPN

- **base** [sni] `www.urban-vpn.com`: Marketing/support site ([doc](https://www.urban-vpn.com/support/))
- **login** [sni] `premium.urban-vpn.com`: Account portal ([doc](https://www.urban-vpn.com/support/))
- **proxy-tunnel** [pattern] `not published`: Extension/app proxy hosts not in official docs ([doc](https://www.urban-vpn.com/support/))

_Note: No official allowlist or network doc found; tunnel endpoints undocumented. Distributed via browser extensions and apps._

### VyprVPN

- **tunnel** [pattern] `app auto-selects open port (Chameleon)`: Chameleon obfuscation; no hostname doc ([doc](https://support.vyprvpn.com/hc/en-us/articles/360038096291))

_Note: Support pages cover NAT firewall and port selection only; no official domain allowlist found._

### X-VPN

- **base** [sni] `xvpn.io/help-center`: Web/help site ([doc](https://xvpn.io/help-center))
- **vpn-tunnel** [pattern] `not published`: No endpoint hosts in official docs ([doc](https://xvpn.io/help-center))

_Note: Help center has no network-requirements or allowlist; tunnel endpoints undocumented._

### Bright Data

- **proxy-gateway** [sni] `brd.superproxy.io:33335/44445 (HTTP/S), 22228 (SOCKS5)`: Distinct hostname and nonstandard ports; CONNECT target hidden ([doc](https://docs.brightdata.com/proxy-networks/faqs))
- **api** [sni] `api.brightdata.com POST /zone/domain_perm`: Management API on its own host ([doc](https://docs.brightdata.com/api-reference/account-management-api/allowlist-or-denylist-domains))
- **control-panel** [http] `brightdata.com/cp/zones`: Path on main host ([doc](https://docs.brightdata.com/proxy-networks/faqs))

_Note: Well documented. Gateway ports 33335 per search summary and 44445 per FAQ. Proxy exit IPs are residential and not enumerable._

### CroxyProxy

- **web-proxy** [http] `croxyproxy.com (browser-based web proxy)`: Rotating server subdomains likely; target URL carried in requests; not verified officially ([doc](https://chromewebstore.google.com/detail/croxyproxy-free-web-proxy/lmmpgfjnchldhcieiiegcpdmaidkaanb))

_Note: No official vendor docs fetched; only third-party descriptions. Lookalike phishing domains reported. Rotating hostnames possible but unverified._

### Baidu Netdisk

- **upload** [http] `precreate / chunk upload / create (/rest/2.0/xpan/file method=precreate|create)`: Official nav lists precreate, chunked upload, create, get upload domain; paths from third-party SDK ([doc](https://pan.baidu.com/union/doc/3ksg0s9ye))
- **base** [sni] `pan.baidu.com`: Under baidu.com, already shipped in pack ([doc](https://pan.baidu.com/union/doc/3ksg0s9ye))

_Note: Official doc page lists upload steps but no hosts. baidu.com subdomains already in pack, so overlap likely covers it._

### Citrix ShareFile

- **base** [sni] `*.sharefile.com`: Web app tenants are subdomains of sharefile.com ([doc](https://docs.sharefile.com/en-us/sharefile/configure/firewall-ip.html))
- **api** [sni] `*.sf-api.com`: Distinct API/storage hostnames ([doc](https://docs.sharefile.com/en-us/sharefile/configure/firewall-ip.html))
- **ftp** [sni] `ftp-*.sharefileftp.com`: Separate FTP endpoints, regional ([doc](https://docs.sharefile.com/en-us/sharefile/configure/firewall-ip.html))
- **upload** [http] `unspecified path on sharefile/sf-api hosts`: Upload vs download needs method/path; not documented in firewall page ([doc](https://docs.sharefile.com/en-us/sharefile/configure/firewall-ip.html))

_Note: Vendor firewall page lists wildcard domains; tenant subdomains vary. Wildcards give clean SNI-level blocking of the whole service._

### Filemail

- **initialize** [sni] `POST api-public.filemail.com/transfer/initialize`: Distinct API host ([doc](https://docs.filemail.com/api/sending-files/initialize))
- **upload** [sni] `POST <n>.filemail.com/savefile.ashx`: Upload server hostname is numbered subdomain of filemail.com; path savefile.ashx needs http ([doc](https://docs.filemail.com/api/sending-files/upload-files))
- **complete** [http] `PUT /transfer/complete`: Same API host as initialize ([doc](https://docs.filemail.com/api/sending-files/complete))

_Note: API host and numbered upload server subdomains documented. Download hosts not covered._

### Pixeldrain

- **upload** [http] `POST /api/file; PUT /api/file/{name}`: Same host as web; needs method/path ([doc](https://pixeldrain.com/api))
- **download** [http] `GET /api/file/{id}`: Same host ([doc](https://pixeldrain.com/api))
- **login** [http] `POST /api/user/login`: Same host ([doc](https://pixeldrain.com/api))
- **base** [sni] `pixeldrain.com`: Single host for web and API ([doc](https://pixeldrain.com/api))

_Note: Single hostname serves web and API; subfunctions separable only via HTTP inspection._

### Smash (fromsmash.com)

- **base** [sni] `fromsmash.com`: Consumer site ([doc](https://api.fromsmash.com/docs/api-reference))
- **api** [sni] `api.fromsmash.com (docs) / regional API hosts unverified`: API reference marked incomplete ([doc](https://api.fromsmash.com/docs/api-reference))
- **upload** [http] `signed upload URL, third-party description only`: Unconfirmed ([doc](https://api.fromsmash.com/docs/api-reference))

_Note: Official API reference is incomplete ('docs will be available soon'). Upload/storage hosts not confirmed from official sources._

### SwissTransfer (Infomaniak)

- **base** [sni] `swisstransfer.com`: Web app and upload entry ([doc](https://www.infomaniak.com/en/support/faq/1751/discover-the-official-domains-used-by-infomaniak))
- **storage** [sni] `infomaniakusercontent.com`: Shared with kDrive, so blocking affects other Infomaniak products ([doc](https://www.infomaniak.com/en/support/faq/1751/discover-the-official-domains-used-by-infomaniak))
- **upload** [http] `swisstransfer.com upload`: API path not documented officially ([doc](https://www.infomaniak.com/en/swisstransfer))

_Note: Infomaniak domain FAQ names swisstransfer.com; no official SwissTransfer API/upload host list found. Storage domain shared with kDrive._

### Terabox

- **upload** [http] `xpan/file precreate, superfile2 (unofficial)`: Unofficial community docs; three-phase precreate/upload/create ([doc](https://herobenhero.github.io/1024TeraBox-REST-API/api/upload.html))
- **base** [sni] `terabox.com family`: Many mirror domains; unofficial ([doc](https://herobenhero.github.io/1024TeraBox-REST-API/api/upload.html))

_Note: No official vendor domain/network doc found; all domains from third-party sources. Multiple mirror domains complicate matching._

### Tresorit

- **base** [sni] `tresorit hostnames per vendor CSV (not retrieved)`: Vendor publishes hostname and IP lists; 443 for all app traffic ([doc](https://support.tresorit.com/hc/en-us/articles/216114237-Network-troubleshooter-guide))
- **tls-inspection** [no] `n/a`: Vendor states not compatible with TLS interception, so http-level separation unlikely ([doc](https://support.tresorit.com/hc/en-us/articles/216114237-Network-troubleshooter-guide))

_Note: Official guide fetch returned 403; hostname list unverified. Search summary: Azure-hosted, 443 plus port 80 for CRLs, no TLS interception support._

### Yandex Disk

- **api** [sni] `GET cloud-api.yandex.net/v1/disk/resources/upload`: Distinct API hostname, yandex.net already in pack ([doc](https://yandex.ru/dev/yandex-360/disk/rest/en/reference/upload))
- **upload** [sni] `PUT uploader*.dst.yandex.net/upload-target/`: Upload hostname returned in href; no OAuth token needed ([doc](https://yandex.ru/dev/yandex-360/disk/rest/en/reference/upload))
- **web** [http] `disk.yandex.*`: Shares parent domain with Yandex mail/search ([doc](https://yandex.com/dev/disk-api/doc/en/index.md))

_Note: API and upload hosts documented; parent domains already in pack under other Yandex apps, so product-level separation needs hostname rules._

### Bolt.new

- **base** [sni] `bolt.new`: Main app ([doc](https://support.bolt.new/))
- **generated-app-hosting** [pattern] `unverified`: Hosting domains not confirmed ([doc](https://support.bolt.new/))

_Note: Support page has no allowlist guidance; WebContainer troubleshooting page returned 404. Runtime domains unverified._

### DeepL

- **api-text** [sni] `POST api.deepl.com/v2/translate`: Pro vs Free hosts separable by SNI ([doc](https://developers.deepl.com/docs/api-reference/translate))
- **document-upload** [http] `POST /v2/document`: Same host as text API; needs HTTP path ([doc](https://developers.deepl.com/docs/api-reference/document))
- **voice** [pattern] `REST then WebSocket streaming URL`: Streaming URL path not documented on page ([doc](https://developers.deepl.com/docs/api-reference/translate))

_Note: API hosts well documented; consumer web translator host not sourced._

### Gamma

- **api-generate** [sni] `POST public-api.gamma.app/v1.0/generations`: Distinct API host ([doc](https://developers.gamma.app/docs/getting-started))
- **upload** [http] `POST /v1.0/uploads`: Same host as API; path needs HTTP ([doc](https://developers.gamma.app/docs/getting-started))
- **export** [http] `POST /v1.0/gammas/{id}/export`: Needs HTTP path ([doc](https://developers.gamma.app/docs/getting-started))
- **mcp** [sni] `mcp.gamma.app/mcp`: Separate MCP host ([doc](https://developers.gamma.app/docs/getting-started))

_Note: API and MCP hosts documented; web app host gamma.app unsourced by network doc._

### Kimi (Moonshot AI)

- **api** [sni] `POST api.moonshot.ai/v1/chat/completions`: Distinct API host separates from consumer chat ([doc](https://platform.kimi.ai/docs/api/chat.md))
- **platform-console** [sni] `platform.kimi.ai`: Developer console/docs ([doc](https://platform.kimi.ai/docs/introduction))

_Note: Platform moved moonshot.ai to kimi.ai; consumer web chat host not confirmed from official docs._

### Lovable

- **base** [sni] `lovable.dev`: Editor/app ([doc](https://docs.lovable.dev/features/custom-domain))
- **published-apps** [sni] `*.lovable.app`: User-published sites; wildcard subdomains, not an upload channel ([doc](https://docs.lovable.dev/features/custom-domain))

_Note: Builder app plus user-hosted sites on lovable.app. No official network requirements page found._

### Manus

- **api** [sni] `api.manus.ai (Tasks, Files sections)`: Distinct API host; paths not listed on fetched page ([doc](https://open.manus.im/docs))
- **file-upload** [http] `api.manus.ai Files API`: Paths not confirmed; needs HTTP inspection ([doc](https://open.manus.im/docs))

_Note: Docs list API host only; no network-requirements page found. Consumer app domains unverified._

### Otter.ai

- **base** [sni] `otter.ai`: Web app and notetaker; unverified ([doc](https://otter.ai))
- **meeting-bot** [pattern] `cloud-joined bot`: Bot joins from vendor cloud; not visible on client network ([doc](https://otter.ai))

_Note: help.otter.ai blocked fetch (403); no official domain list located. All domains unsourced._

### Hey.com

- **webmail** [sni] `app.hey.com`: Web and native apps use same host ([doc](https://www.hey.com/faqs/))
- **imap-smtp** [no] `none`: HEY doesn't support IMAP or POP ([doc](https://www.hey.com/faqs/))

_Note: No IMAP/POP/SMTP; hosts derived from FAQ page, not a network-requirements page. Firewall guidance absent._

### Mail.ru webmail

- **imap** [sni] `imap.mail.ru:993`: Mail client access ([doc](https://help.mail.ru/mail/mailer/popsmtp))
- **smtp-send** [sni] `smtp.mail.ru:465`: Outbound send via client ([doc](https://help.mail.ru/mail/mailer/popsmtp))
- **webmail** [sni] `e.mail.ru`: Unsourced host; web UI ([doc](https://help.mail.ru/))

_Note: Mail protocol hosts sourced from official help; webmail UI and CDN hosts not sourced._

### Temp-Mail (temp-mail.io disposable email)

- **create-address** [http] `POST /v1/emails`: Paid API; same host as other calls ([doc](https://docs.temp-mail.io/docs/getting-started))
- **read-messages** [http] `GET /v1/emails/{email}/messages`: Needs HTTP path ([doc](https://docs.temp-mail.io/docs/getting-started))
- **api-host** [sni] `api.temp-mail.io`: Distinct API host ([doc](https://docs.temp-mail.io/docs/getting-started))

_Note: Disposable-email category has many unrelated look-alike domains; only temp-mail.io API sourced. Disposable inbox domains are not enumerable._

### DingTalk

- **file-upload** [http] `POST oapi.dingtalk.io/media/upload`: Same host as other API calls; needs path visibility ([doc](https://help.dingtalk.io/open/development/upload-media-files.md))
- **api** [sni] `oapi.dingtalk.io`: Open-platform API host distinct from client hosts ([doc](https://help.dingtalk.io/open/development/upload-media-files.md))

_Note: Official domain evidence limited to international docs mirror dingtalk.io; open.dingtalk.com pages did not render. China domains dingtalk.com unsourced._

### Feishu/Lark

- **im-image-upload** [http] `POST /open-apis/im/v1/images`: Same API host as everything else ([doc](https://open.larksuite.com/document/server-docs/im-v1/image/create.md))
- **drive-upload** [http] `POST /open-apis/drive/v1/files/upload_all`: Files up to 20M; chunked flow above ([doc](https://open.larksuite.com/document/uAjLw4CM/ukTMukTMukTM/reference/drive-v1/media/upload_all.md))
- **api** [sni] `open.feishu.cn / open.larksuite.com`: Feishu (CN) and Lark (intl) split by hostname ([doc](https://open.feishu.cn/document/server-docs/api-call-guide/calling-process/get-access-token))

_Note: Client/web hosts (feishu.cn, larksuite.com, larkoffice.com) not confirmed from official network docs; only API hosts sourced._

### Mattermost

- **api** [no] `/api/v4 on customer-chosen host`: Mostly self-hosted at arbitrary customer domains; no vendor fixed host ([doc](https://docs.mattermost.com/api))
- **push-notifications** [sni] `EmailSettings.PushNotificationServer TCP 443`: Only if default hosted push proxy is used ([doc](https://docs.mattermost.com/deployment-guide/server/prepare-network))

_Note: Self-hosted product; official docs name no real hostnames. Cloud tenants use *.cloud.mattermost.com (not verified from docs)._

### WeCom (WeChat Work)

- **api** [sni] `qyapi.weixin.qq.com`: Distinct from consumer WeChat hosts by hostname ([doc](https://developer.work.weixin.qq.com/document/path/90664))
- **media-upload** [http] `POST /cgi-bin/media/upload`: Path named in doc index; path confirmed only via third-party text ([doc](https://developer.work.weixin.qq.com/document/path/90664))
- **group-robot-upload** [http] `POST /cgi-bin/webhook/upload_media`: Third-party sourced ([doc](https://developer.work.weixin.qq.com/document/path/90664))

_Note: Domains are subdomains of weixin.qq.com which is already in pack; SNI-level separation is possible on subdomain only if pack does not wildcard it._

### Wire

- **api-messaging** [sni] `prod-nginz-ssl.wire.com:443`: Single API gateway; messages and assets share it ([doc](https://support.wire.com/hc/en-us/articles/115005341805-What-domain-names-and-ports-does-Wire-connect-to))
- **voice-video-relay** [sni] `turn.calling-prod-v01.wire.com 3478/5349`: UDP/TCP 3478, TLS 5349 ([doc](https://support.wire.com/hc/en-us/articles/115005341805-What-domain-names-and-ports-does-Wire-connect-to))
- **conference-sft** [sni] `sft.calling-prod-v01.wire.com`: Group calls ([doc](https://support.wire.com/hc/en-us/articles/115005341805-What-domain-names-and-ports-does-Wire-connect-to))

_Note: Support page returned 403 to fetch; details taken from search-result summary of the official page. Other hosts (assets, web app) not verified._

### Mastodon (mastodon.social)

- **media-upload** [http] `POST /api/v2/media`: Requires write:media scope ([doc](https://docs.joinmastodon.org/methods/media/))
- **streaming** [sni] `wss://streaming.example/api/v1/streaming`: May be a separate hostname per instance ([doc](https://docs.joinmastodon.org/methods/streaming/))
- **post-status** [http] `POST /api/v1/statuses`: Path-level only ([doc](https://docs.joinmastodon.org/methods/statuses/))
- **oauth** [http] `/oauth/authorize, /oauth/token`: Per-instance ([doc](https://docs.joinmastodon.org/methods/oauth/))

_Note: Federated: thousands of independent instance domains; only mastodon.social is one host. Domain-level blocking cannot cover the fediverse. Official docs give placeholders only._

### Truth Social

- **base** [sni] `truthsocial.com`: Web/app host ([doc](https://help.truthsocial.com/faq))
- **api** [http] `/api/v1/* (Mastodon-derived, undocumented)`: No official developer API docs found ([doc](https://help.truthsocial.com/faq))

_Note: No official developer API or allowlist documentation found; third-party scrapers only. Software is Mastodon-derived (unconfirmed officially)._

### Azure DevOps

- **web-api** [sni] `dev.azure.com/{org}`: Shared host; org in path ([doc](https://learn.microsoft.com/en-us/azure/devops/organizations/security/allow-list-ip-url))
- **git-ssh** [sni] `ssh.dev.azure.com:22`: Git over SSH ([doc](https://learn.microsoft.com/en-us/azure/devops/organizations/security/allow-list-ip-url))
- **agent-download** [sni] `download.agent.dev.azure.com`: Pipeline agent software ([doc](https://learn.microsoft.com/en-us/azure/devops/organizations/security/allow-list-ip-url))
- **artifacts** [sni] `*.pkgs.visualstudio.com, *.blob.core.windows.net`: Package feeds; blob host is shared Azure storage ([doc](https://learn.microsoft.com/en-us/azure/devops/organizations/security/allow-list-ip-url))

_Note: login.microsoftonline.com is shared Microsoft auth, do not block per-service. Legacy {org}.visualstudio.com already in pack._

### Bitbucket Cloud

- **web** [sni] `bitbucket.org`: Already in pack ([doc](https://support.atlassian.com/bitbucket-cloud/docs/what-are-the-bitbucket-cloud-ip-addresses-i-should-use-to-configure-my-corporate-firewall/))
- **api** [sni] `api.bitbucket.org`: Separate hostname ([doc](https://support.atlassian.com/bitbucket-cloud/docs/what-are-the-bitbucket-cloud-ip-addresses-i-should-use-to-configure-my-corporate-firewall/))
- **git-ssh** [sni] `ssh.bitbucket.org / altssh.bitbucket.org`: Git push over SSH ([doc](https://support.atlassian.com/bitbucket-cloud/docs/what-are-the-bitbucket-cloud-ip-addresses-i-should-use-to-configure-my-corporate-firewall/))
- **git-https-push** [http] `POST bitbucket.org/<ws>/<repo>.git/git-receive-pack`: Path visible only with TLS inspection; path from general git protocol knowledge ([doc](https://support.atlassian.com/bitbucket-cloud/docs/what-are-the-bitbucket-cloud-ip-addresses-i-should-use-to-configure-my-corporate-firewall/))

_Note: Core domain already shipped in pack; incremental value is sub-function split (api, ssh)._

### Codeberg

- **base-git** [sni] `codeberg.org`: Web, API and git over HTTPS share host ([doc](https://docs.codeberg.org/))
- **pages-hosting** [sni] `*.codeberg.page`: User-published static sites; wildcard subdomains ([doc](https://docs.codeberg.org/codeberg-pages/))
- **api** [http] `POST codeberg.org/api/v1/... (Forgejo API)`: Same host as web; path from Forgejo knowledge, not fetched ([doc](https://docs.codeberg.org/))

_Note: Forgejo-based; API path not verified on fetched pages. Pages uses git-pages with custom domains (not enumerable)._

### Rentry

- **create** [http] `POST /api/new`: Same host as web ([doc](https://github.com/radude/rentry))
- **edit** [http] `POST /api/edit/{url}`: Edit code required ([doc](https://github.com/radude/rentry))
- **raw-read** [http] `GET /api/raw/{url}`: Also /raw/ read path ([doc](https://github.com/radude/rentry))
- **base** [sni] `rentry.co`: Whole-site block only ([doc](https://github.com/radude/rentry))

_Note: Only unofficial-adjacent author CLI repo documents API; rentry.co/api page returned empty. Read vs write separable only via HTTP inspection._

### Bitget

- **api-rest** [sni] `api.bitget.com`: Distinct hostname ([doc](https://bitgetlimited.github.io/apidoc/en/spot/))
- **api-websocket** [sni] `WS host (unconfirmed)`: Hostname not verified from official page ([doc](https://bitgetlimited.github.io/apidoc/en/spot/))
- **trade-orders** [http] `POST /api/v2/spot/trade/place-order`: Path unverified here; needs HTTP visibility ([doc](https://bitgetlimited.github.io/apidoc/en/spot/))

_Note: New UTA docs list no hostnames; legacy docs give api.bitget.com. WS and web hosts unconfirmed._

### Bybit

- **api-rest** [sni] `api.bybit.com /v5/*`: Distinct hostname ([doc](https://bybit-exchange.github.io/docs/v5/guide))
- **api-websocket** [sni] `stream.bybit.com`: Distinct hostname ([doc](https://bybit-exchange.github.io/docs/v5/ws/connect))
- **order-create** [http] `POST /v5/order/create`: Needs TLS inspection to separate from market data ([doc](https://bybit-exchange.github.io/docs/v5/guide))
- **regional-variants** [sni] `api.bybit.{tr,kz,eu,id,ae}, api.manepa.jp`: Many regional TLDs; list requires maintenance ([doc](https://bybit-exchange.github.io/docs/v5/guide))

_Note: Official docs list many regional API/stream hosts; consumer web domains not verified from official docs._

### KuCoin

- **api-spot-rest** [sni] `api.kucoin.com`: Distinct hostname ([doc](https://www.kucoin.com/docs/basic-info/connection-method/request/api-domain))
- **api-futures-rest** [sni] `api-futures.kucoin.com`: Futures separable by host (classic accounts) ([doc](https://www.kucoin.com/docs/basic-info/connection-method/request/api-domain))
- **ws-order-entry** [sni] `wsapi.kucoin.com`: Order add/cancel host separate from push feeds ([doc](https://www.kucoin.com/docs/basic-info/connection-method/request/api-domain))
- **broker-api** [sni] `api-broker.kucoin.com`: Broker/partner API ([doc](https://www.kucoin.com/docs/basic-info/connection-method/request/api-domain))

_Note: API hosts clearly sourced; web UI and CDN hosts not verified. Classic vs unified account use different WS hosts._

### Ledger Live

- **base** [no] `unknown`: No official host list found; third-party says TLS1.2+ and cert pinning (unverified) ([doc](n/a))

_Note: No official allowlist located; searches returned only third-party pages. Needs dedicated follow-up._

### OKX

- **base-web** [sni] `www.okx.com`: Web trading UI host ([doc](https://www.okx.com/docs-v5/en/))
- **api-rest** [sni] `openapi.okx.com /api/v5/*`: Distinct API hostname; regional variants us/eea ([doc](https://www.okx.com/docs-v5/en/))
- **api-websocket** [sni] `ws.okx.com /ws/v5/{public,private,business}`: Distinct WS host; channel split only by path (http) ([doc](https://www.okx.com/docs-v5/en/))
- **trading-orders** [http] `POST /api/v5/trade/order`: Order placement vs market data needs path visibility ([doc](https://www.okx.com/docs-v5/en/))

_Note: API hosts well documented; consumer web/app hosts and wallet/DEX hosts not listed in official docs fetched._

### Trust Wallet

- **swap-quote** [sni] `get_swap_quote via mcp.trustwallet.com/tws`: Developer API host, not wallet-app traffic ([doc](https://developer.trustwallet.com/developer/mcp/api-gateway))
- **asset-metadata** [http] `GET /v1/assets (tws host)`: Secondary-source path ([doc](https://developer.trustwallet.com/llms.txt))
- **wallet-app-rpc** [no] `chain RPC / backend hosts`: Consumer app backends not documented ([doc](n/a))

_Note: Only developer-platform hosts documented; mobile wallet app/extension backend hosts not found in official docs._

### Uniswap

- **web-app** [sni] `app.uniswap.org`: Frontend; wallet signing happens locally, chain RPC is separate ([doc]((unverified)))
- **subgraph-query** [http] `gateway.thegraph.com/api/<key>/subgraphs/id/<id>`: Shared The Graph host, not Uniswap-specific; id in path ([doc](https://developers.uniswap.org/llms.mdx/docs/ecosystem/subgraphs/overview))
- **onchain-swap** [no] `JSON-RPC to third-party node providers`: Swap tx goes to arbitrary RPC hosts; not Uniswap-separable ([doc](n/a))

_Note: Decentralized protocol; official docs name only The Graph gateway. Web app hosts not confirmed on docs pages._

### Resilio Sync

- **config-fetch** [sni] `config.resilio.com/sync.conf`: Distinct hostname, Sync client bootstrap ([doc](https://help.resilio.com/hc/en-us/articles/204754759))
- **tracker** [pattern] `port 3000 TCP/UDP (Connect agent); Sync tracker 4000 per community`: Tracker host dynamic ([doc](https://docs.resilio.com/content/getting-started/ports-protocols-port-forwarding/))
- **relay** [pattern] `TCP relay fallback, dynamic hosts`: Used when direct connect fails ([doc](https://help.resilio.com/hc/en-us/articles/204754759))
- **p2p-transfer** [pattern] `3839 TCP/UDP between Agents (Connect)`: Sync desktop port is user-configurable ([doc](https://docs.resilio.com/content/getting-started/ports-protocols-port-forwarding/))

_Note: Docs fetched were for Connect/Agent; Sync consumer hosts (tracker/relay) dynamic. help.resilio.com 403'd on direct fetch._

### Soulseek

- **server-login** [sni] `server.slsknet.org:2242`: Hostname/port from community docs; protocol is custom non-TLS so SNI absent; DNS/port match ([doc](https://nicotine-plus.org/doc/SLSKPROTOCOL.html))
- **peer-transfer** [pattern] `client listen port default 2234`: Direct peer connections ([doc](https://nicotine-plus.org/doc/SLSKPROTOCOL.html))

_Note: Proprietary, undocumented by vendor; only community reverse-engineered docs. Not TLS, so SNI inapplicable._

### qBittorrent

- **bittorrent-peer** [pattern] `single configurable incoming TCP/UDP port`: Peer-to-peer; no fixed hostnames ([doc](https://github.com/qbittorrent/qBittorrent/wiki/Explanation-of-Options-in-qBittorrent))
- **dht** [pattern] `UDP on listen port`: DHT tracker-independent peer discovery ([doc](https://github.com/qbittorrent/qBittorrent/wiki/Explanation-of-Options-in-qBittorrent))
- **tracker-announce** [http] `HTTP GET /announce to arbitrary trackers`: Needs HTTP visibility; hosts vary per torrent ([doc](https://www.github.com/qbittorrent/qBittorrent/wiki/How-to-use-qBittorrent-as-a-tracker))

_Note: Protocol-level detection; no vendor-fixed domains. Embedded tracker default port 9000 (disabled by default)._

### uTorrent

- **bittorrent-peer** [pattern] `incoming TCP/UDP port (default 6881-range per community)`: Port default only from community sources ([doc](https://blog.utorrent.com/?p=237))
- **dht** [pattern] `UDP on main port`: Community forum, not official doc ([doc](https://forum.utorrent.com/topic/85487-what-incoming-outgoing-tcp-udp-ports-must-be-opened/))

_Note: No official domain list found; detection via BitTorrent protocol. Ad/update hosts unverified._
