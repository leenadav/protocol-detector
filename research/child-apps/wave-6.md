# Child apps, wave 6: 30 more services already in the pack (PRO-588)

Continues wave 0 (`wave-0.md`, PRO-495) and waves 1 to 5 (PRO-524 PR #176, PRO-550 PR #180, PRO-569 PR #183, PRO-575
PR #185, PRO-579 PR #189) for Engine PRO-492. Data: `wave-6.json` (schema `child-apps/v1`, `wave: 6`, validator
`../tools/check_child_apps.py`). Parent ids are those of `go/internal/content/pack.json` (release `2026.11.9`, last changed
in `59fb9fc`, unchanged on `origin/main` at `cc1566d`); every parent was checked against the pack. Sources accessed
2026-11-27. This branch is cut from `origin/main`, not stacked on the wave 1 to 5 branches; their files were read with
`git show` only to exclude their parents.

## Scope and overlap

- **Not covered before**: waves 0 to 5 (wave 0 on `main`; waves 1 to 5 on `origin/claude/app-research-PRO-524-child-apps-wave1`,
  `...-PRO-550-child-apps-wave2`, `...-PRO-569-child-apps-wave3`, `...-PRO-575-child-apps-wave4` and
  `...-PRO-579-child-apps-wave5-v2`) hold 178 parents. None of the 30 below is among them.
- **PR #166**: as wave 5 found, none of its service ids is a pack application, so parents come from the task's SWG categories.
- **30 services** by category: HR, payroll, scheduling and surveys (BambooHR, Gusto, Workday, Calendly, SurveyMonkey); code analysis (spare for ADP) (SonarCloud); video conferencing and telephony (GoTo Meeting, 8x8, Dialpad); email security (Microsoft Exchange Online Protection); file transfer and sharing (DocSend, 4shared); CRM, marketing and product analytics (Braze, Twilio Segment, Amplitude, Mixpanel, Hotjar, OneSignal); ITSM, RMM and remote support (Atera, NinjaOne, Kaseya, ConnectWise ScreenConnect, Zoho Assist); endpoint and email security console (Sophos Central); domain, hosting and certificate consoles (GoDaddy, Namecheap, DigiCert); endpoint and cloud-proxy security (SentinelOne, Netskope, Zscaler).
- **Dropped or spare**: `adp` (no vendor-owned source could be confirmed: the former `adplabs` organisation is gone and every
  copy found is a personal fork; replaced by the spare `sonarcloud`); `splashtop` (no readable vendor-owned source, dropped to
  keep 30); `sendspace` and `canvas-lms` (spares, not needed).

## Method

Same as wave 5. Official vendor sources only, one citation per verified child (more in `citation_also`). Nothing is taken
from nDPI, Wireshark, Suricata, Snort or OpenAppID. No traffic was captured and no vendor API was called; only
documentation, specification and source files were fetched. **Unverified children keep every signal field `null`.**
Almost every vendor documentation site was refused by this session's network policy (curl 000 or 403), so most verified rows
cite the vendor's own OpenAPI spec, SDK, CLI, sample or documentation repository on `raw.githubusercontent.com`, pinned to a
full commit SHA, in the vendor's own GitHub organisation (52 repositories, named per row in `citation_page_date`). Three
other vendor-owned sources were reachable and used: Microsoft Learn (`learn.microsoft.com`, Exchange Online Protection),
the Dropbox Help Center (`help.dropbox.com`, DocSend is a Dropbox product) and NinjaOne's own docs (`www.ninjaone.com/docs`).

Checks before submission:
- **Quote check.** The first single-quoted string in each verified child's note was fetched again from its `citation_url`
  and found verbatim: 146 of 146.
- **Host check.** Every literal `host_sni` name of a verified row was searched in its cited files (`citation_url` and
  `citation_also`): 174 names, 165 found verbatim. Patterns (`*.` or `{...}`) are not literal and were not searched; the other 9 are Mixpanel regional names
  built from the spec's servers template and enum, explained in each row.
- **Secret scan.** gitleaks 8.30.1 with the repository `.gitleaks.toml` over the branch commits: no leaks.
- **Freshness.** Some sources are old and say so in the row: SurveyMonkey `public_api_docs` (last change 2021), DigiCert
  `digicert_express` (2016), OneSignal `api` spec (2023, current SDK uses `api.onesignal.com`), Calendly v1 demo (2021).

## Result

30 services, 190 proposed children, **146 verified with an official citation** (159 distinct pages); 44 unverified.

Counts asked for by PRO-588: **30 services**; **190 children**; **146 cited** (113 primary pages); **44 unverified**;
**159 distinct pages**. Web-UI evidence: none for all 30 (see each `web_ui_note`).

| # | Service | Parent | Verified children | Unverified children | Verified | Separability |
|---|---|---|---|---|---|---|
| 1 | BambooHR | `bamboohr` | `bamboohr-api-signing-in`, `bamboohr-api-uploading`, `bamboohr-api-downloading`, `bamboohr-api-report-exporting`, `bamboohr-api-webhook-managing`, `bamboohr-api-employee-syncing` | - | 6/6 | partial |
| 2 | Gusto | `gusto` | `gusto-api-signing-in`, `gusto-client-signing-in`, `gusto-api-provisioning`, `gusto-api-report-exporting`, `gusto-api-webhook-managing`, `gusto-client-mcp-calling`, `gusto-client-downloading` | - | 7/7 | partial |
| 3 | Workday | `workday` | `workday-api-signing-in`, `workday-api-report-exporting`, `workday-api-uploading`, `workday-api-dataset-managing`, `workday-api-agent-registering`, `workday-api-extend-app-calling` | - | 6/6 | partial |
| 4 | Calendly | `calendly` | `calendly-api-signing-in`, `calendly-api-event-reading`, `calendly-api-availability-reading`, `calendly-api-event-cancelling`, `calendly-web-embedding`, `calendly-api-legacy-reading` | `calendly-api-webhook-managing` | 6/7 | partial |
| 5 | SurveyMonkey | `surveymonkey` | `surveymonkey-api-signing-in`, `surveymonkey-api-response-exporting`, `surveymonkey-api-webhook-managing`, `surveymonkey-api-invite-sending`, `surveymonkey-api-contact-importing`, `surveymonkey-web-survey-responding` | `surveymonkey-client-sdk-feedback-collecting` | 6/7 | partial |
| 6 | SonarCloud | `sonarcloud` | `sonarcloud-client-bootstrapping`, `sonarcloud-client-build-wrapper-downloading`, `sonarcloud-client-downloading`, `sonarcloud-client-key-fetching`, `sonarcloud-api-badge-fetching` | `sonarcloud-client-report-uploading` | 5/6 | partial |
| 7 | GoTo Meeting | `goto-meeting` | `goto-meeting-api-signing-in` | `goto-meeting-api-meeting-scheduling`, `goto-meeting-web-meeting-joining`, `goto-meeting-client-media-connecting`, `goto-meeting-api-recording-downloading`, `goto-meeting-client-downloading` | 1/6 | host-only |
| 8 | 8x8 | `8x8` | `8x8-api-provisioning`, `8x8-api-auditing`, `8x8-api-recording-downloading`, `8x8-api-messaging`, `8x8-api-webhook-registering`, `8x8-web-meeting-embedding` | `8x8-client-media-connecting` | 6/7 | partial |
| 9 | Dialpad | `dialpad` | `dialpad-api-signing-in`, `dialpad-api-provisioning`, `dialpad-api-exporting`, `dialpad-api-webhook-registering`, `dialpad-api-transcript-downloading`, `dialpad-api-messaging` | `dialpad-client-media-connecting` | 6/7 | partial |
| 10 | Microsoft Exchange Online Protection | `ms-exchange-online-protection` | `ms-exchange-online-protection-client-mail-receiving`, `ms-exchange-online-protection-web-quarantine-reviewing`, `ms-exchange-online-protection-web-message-tracing`, `ms-exchange-online-protection-api-quarantine-releasing`, `ms-exchange-online-protection-api-message-trace-exporting` | `ms-exchange-online-protection-web-message-reporting` | 5/6 | partial |
| 11 | DocSend | `docsend` | `docsend-api-mcp-connecting`, `docsend-web-signing-in`, `docsend-web-document-viewing`, `docsend-web-file-requesting` | `docsend-web-uploading`, `docsend-web-audit-exporting` | 4/6 | partial |
| 12 | 4shared | `4shared` | - | `4shared-web-signing-in`, `4shared-web-uploading`, `4shared-web-downloading`, `4shared-api-file-managing`, `4shared-client-webdav-syncing` | 0/5 | blocked |
| 13 | Braze | `braze` | `braze-api-tracking`, `braze-api-managing`, `braze-api-exporting`, `braze-client-syncing`, `braze-client-downloading`, `braze-web-signing-in` | `braze-api-messaging` | 6/7 | partial |
| 14 | Twilio Segment | `segment` | `segment-client-tracking`, `segment-api-tracking`, `segment-client-configuring`, `segment-client-downloading`, `segment-api-signing-in`, `segment-api-auditing`, `segment-api-provisioning` | - | 7/7 | partial |
| 15 | Amplitude | `amplitude` | `amplitude-client-tracking`, `amplitude-api-importing`, `amplitude-client-recording`, `amplitude-client-configuring`, `amplitude-client-reporting`, `amplitude-client-downloading` | `amplitude-api-exporting` | 6/7 | partial |
| 16 | Mixpanel | `mixpanel` | `mixpanel-client-tracking`, `mixpanel-client-recording`, `mixpanel-client-downloading`, `mixpanel-api-importing`, `mixpanel-api-exporting`, `mixpanel-api-deleting`, `mixpanel-api-provisioning` | - | 7/7 | partial |
| 17 | Hotjar | `hotjar` | `hotjar-client-downloading`, `hotjar-web-signing-in` | `hotjar-client-recording`, `hotjar-client-surveying`, `hotjar-api-exporting` | 2/5 | host-only |
| 18 | OneSignal | `onesignal` | `onesignal-api-sending`, `onesignal-api-exporting`, `onesignal-api-administering`, `onesignal-client-subscribing`, `onesignal-client-configuring`, `onesignal-client-downloading`, `onesignal-client-measuring` | - | 7/7 | partial |
| 19 | Atera | `atera` | - | `atera-api-managing`, `atera-api-ticket-managing`, `atera-client-agent-checking-in`, `atera-client-agent-downloading`, `atera-web-signing-in` | 0/5 | blocked |
| 20 | NinjaOne | `ninjaone` | `ninjaone-api-authorizing`, `ninjaone-api-token-issuing`, `ninjaone-api-querying`, `ninjaone-web-saml-signing-in` | `ninjaone-api-scim-provisioning`, `ninjaone-client-agent-checking-in`, `ninjaone-client-remote-connecting` | 4/7 | partial |
| 21 | Kaseya | `kaseya` | `kaseya-api-autotask-mcp-querying`, `kaseya-api-itglue-mcp-querying`, `kaseya-api-autotask-rest-zone-reaching` | `kaseya-api-datto-rmm-querying`, `kaseya-api-vsa-managing`, `kaseya-client-agent-checking-in` | 3/6 | partial |
| 22 | ConnectWise ScreenConnect | `connectwise-control` | - | `connectwise-control-web-signing-in`, `connectwise-control-client-relaying`, `connectwise-control-client-downloading`, `connectwise-control-api-session-managing` | 0/4 | blocked |
| 23 | Zoho Assist | `zoho-assist` | `zoho-assist-client-session-joining`, `zoho-assist-client-cobrowsing`, `zoho-assist-client-sdk-downloading` | `zoho-assist-api-session-creating`, `zoho-assist-client-agent-downloading` | 3/5 | host-only |
| 24 | Sophos | `sophos` | `sophos-api-signing-in`, `sophos-api-tenant-discovering`, `sophos-api-auditing`, `sophos-api-provisioning`, `sophos-api-endpoint-managing`, `sophos-api-installer-downloading` | - | 6/6 | partial |
| 25 | GoDaddy | `godaddy` | `godaddy-api-signing-in`, `godaddy-api-domain-registering`, `godaddy-api-dns-editing`, `godaddy-api-source-uploading`, `godaddy-api-mailbox-provisioning`, `godaddy-api-order-managing` | - | 6/6 | partial |
| 26 | Namecheap | `namecheap` | `namecheap-api-dns-editing`, `namecheap-api-domain-registering`, `namecheap-api-domain-transferring`, `namecheap-api-certificate-ordering`, `namecheap-api-privacy-managing`, `namecheap-api-account-billing` | - | 6/6 | host-only |
| 27 | DigiCert | `digicert` | `digicert-api-certificate-ordering`, `digicert-api-certificate-downloading`, `digicert-api-certificate-enrolling`, `digicert-api-certificate-pickup`, `digicert-api-certificate-revoking`, `digicert-client-tools-downloading` | `digicert-api-code-signing` | 6/7 | partial |
| 28 | SentinelOne | `sentinelone` | `sentinelone-api-agent-package-downloading`, `sentinelone-api-agent-upgrading`, `sentinelone-api-alert-querying`, `sentinelone-api-purple-ai-querying`, `sentinelone-api-vulnerability-querying`, `sentinelone-api-asset-inventorying`, `sentinelone-api-log-querying` | `sentinelone-client-agent-checking-in` | 7/8 | partial |
| 29 | Netskope | `netskope` | `netskope-api-event-exporting`, `netskope-api-alert-searching`, `netskope-api-file-scanning`, `netskope-api-publisher-listing`, `netskope-api-steering-configuring`, `netskope-web-signing-in` | `netskope-client-steering` | 6/7 | partial |
| 30 | Zscaler | `zscaler` | `zscaler-api-signing-in`, `zscaler-api-zia-configuring`, `zscaler-api-sandbox-uploading`, `zscaler-api-zpa-configuring`, `zscaler-api-device-exporting`, `zscaler-api-legacy-session-signing-in` | `zscaler-client-connector-tunneling` | 6/7 | partial |

## Where a function cannot be separated

Each service's `not_separable` field gives the detail. In short:
- **Blocked (no readable vendor source)**: Atera, ConnectWise ScreenConnect and 4shared; every row is unverified.
- **Host-only**: Namecheap (every function is a POST to `xml.response`, named only by the `Command` body field) and GoTo
  Meeting (only the shared GoTo sign-in host is verified).
- **Tenant hosts**: BambooHR `{companyDomain}.bamboohr.com`, Workday tenant URLs, SentinelOne `*.sentinelone.net`, Netskope
  `*.goskope.com`, Zscaler `{vanity_domain}.zslogin.net`, NinjaOne branded hosts and DigiCert ONE customer hosts: split by path
  only, and the tenant label is a customer identifier, not application identity.
- **API and web app share a host**: Dialpad (`dialpad.com`), Mixpanel `/api/app`, OneSignal `/api/v1`: a host-only policy sees
  the parent, not the function.
- **Non-HTTP**: Exchange Online Protection mail flow is SMTP on TCP 25 (`transport` set); an HTTP rule cannot see it.
- **Binary or bundled clients**: Zoho Assist SDK paths sit in binary frameworks; Kaseya's Datto RMM server ships as a bundle;
  the SonarCloud analysis upload is done by a downloaded engine; agent check-in traffic (SentinelOne, NinjaOne, Netskope
  Client, Zscaler Client Connector) is not described by any readable vendor file.

## Findings for Engine (ENGINE-FIELD, Go only)

- BambooHR: every API host is the tenant template {companyDomain}.bamboohr.com; a classifier must match *.bamboohr.com and split by path. api.bamboohr.com appears only in response examples (_links) of the newer /api/v1/employees listing, not as a servers entry.
- Gusto: sandbox hosts api.gusto-demo.com, mcp.api.gusto-demo.com, app.gusto-demo.com and flows.gusto-demo.com are outside the pack domains (gusto.com). The CLI release download is on github.com (/Gusto/gusto-cli/releases/...), outside the pack.
- Gusto: example document URLs in the spec point at s3.amazonaws.com/static.gusto.com/..., a path-style S3 bucket outside the pack; recorded as an example only, not as a signal.
- Workday: tenant API, RaaS, Prism and OAuth endpoints sit on a customer-specific tenant base URL that no vendor file names; host_sni is null for those rows. ASOR and Extend apps use api.workday.com (in the pack). The ASOR spec names a placeholder authorize host on workdaysuv.com, outside the pack.
- Calendly: auth.calendly.com and api.calendly.com come from the sample app's .env.example environment values, not from code constants. assets.calendly.com (embed widget) is fetched by any site that embeds Calendly.
- SonarCloud: binaries.sonarsource.com (scanner CLI and signing key), sonarqube.us / api.sonarqube.us and sonarqube.au / api.sonarqube.au (regional SonarQube Cloud) are outside the pack domains (sonarcloud.io). api.sonarcloud.io is inside it.
- SonarCloud: /api/project_badges/measure on sonarcloud.io is fetched by third-party page views (README badges), so it should not count as SonarQube Cloud use.
- GoTo Meeting sign-in host authentication.logmeininc.com is outside the pack domains (gotomeeting.com, gotomeet.at, gotomeet.me, joingotomeeting.com, openvoice.com) and is shared by every GoTo product; it should not map to goto-meeting alone.
- 8x8 SMS regional hosts sms.8x8.uk and sms.8x8.id are outside the pack domains (8x8.com, 8x8.vc).
- Dialpad API shares the apex host dialpad.com with the web app; only /api/v2/ and /oauth2/ paths separate it (decrypting proxy needed).
- Microsoft EOP: admin hosts security.microsoft.com, admin.exchange.microsoft.com and outlook.office365.com are outside the pack domains (protection.outlook.com, mx.microsoft) and are shared with Defender for Office 365, Purview and Exchange Online; ps.compliance.protection.outlook.com is under protection.outlook.com but serves all Security and Compliance PowerShell.
- Microsoft EOP mail flow is SMTP on TCP 25 to {domain}.mail.protection.outlook.com / *.mx.microsoft: a non-HTTP signal, invisible to an HTTP/SNI rule.
- Tenant-templated host: {YourCustomDomain}-com.mail.protection.outlook.com (EOP MX endpoint per accepted domain).
- 8x8 Cloud Storage host template api.8x8.com/storage/{region}/{apiversion}/ carries region and version in the path, not the host.
- 4shared: no verified child (all sources refused); separability blocked.
- braze: rest.fra-01/02.braze.eu, dashboard-01/02.braze.eu are outside the pack domains (braze.com); add braze.eu
- braze: js.appboycdn.com (Web SDK CDN, former Appboy name) is outside the pack domains; add appboycdn.com
- segment: api.segmentapis.com (Public API), oauth2.eu1.segmentapis.com and events.eu1.segmentapis.com (EU) are outside the pack domains (segment.com, segment.io); add segmentapis.com
- segment, amplitude, mixpanel: SDK API hosts are customer-overridable (first-party proxy domains), so traffic through such proxies will not match
- mixpanel: cdn.mxpnl.com (JS SDK CDN) is outside the pack domains (mixpanel.com); add mxpnl.com
- mixpanel: GDPR and service-account APIs share the mixpanel.com host with the web app; separate by /api/app/ path only
- onesignal: REST API on onesignal.com/api/v1 shares the host with the dashboard; the newer api.onesignal.com host is used by the Web SDK
- segment-client-configuring and segment-client-downloading paths carry the customer write key and Mixpanel/Hotjar/OneSignal paths carry project or site IDs: tenant identifiers, not application identity
- Kaseya: every verified host is outside the pack domains kaseya.com/kaseya.net: Autotask MCP mcp{zone}.autotask.net (mcp1..mcp31, mcpprde, mcppres, mcpprca01), Autotask REST webservices{zone}.autotask.net, IT Glue MCP mcp.itglue.com / mcp.eu.itglue.com / mcp.au.itglue.com. Adding autotask.net and itglue.com (or separate Autotask / IT Glue / Datto RMM parents) would be needed to match them.
- NinjaOne: oc.ninjarmm.com is under the pack domain ninjarmm.com; other regional instances exist (the docs say to change the host to your region) but are not named in readable sources. Branded (customer custom-domain) NinjaOne hosts serve /ws/account/saml-login and are tenant hosts outside the pack.
- Zoho Assist: regional hosts assist.zoho.eu and assist.zoho.in are named in the zoho Assist SDK READMEs but are outside the pack domain assist.zoho.com; maven.zohodl.com (SDK distribution) is also outside.
- Sophos: api-{dataRegion}.central.sophos.com, api.central.sophos.com and id.sophos.com are under sophos.com.
- Atera and ConnectWise ScreenConnect have no readable vendor-owned source; their rows are all unverified and their pack entries stay host-only.
- Zscaler OneAPI gateway api.zsapi.net (and api.{cloud}.zsapi.net) is not under any zscaler pack domain; add zsapi.net or OneAPI traffic is unattributed.
- Zscaler FedRAMP OneAPI hosts api.zscalergov.net / api.zscalergov.us: zscalergov.us is not in the pack domains.
- Zscaler token host is tenant-templated {vanity_domain}.zslogin.net (pack has zslogin.net).
- Namecheap: api.sandbox.namecheap.com is under namecheap.com; all functions share POST /xml.response and differ only in the form-body Command.
- DigiCert: pki-downloads.digicert.com (tool downloads) is under digicert.com; DigiCert ONE hosts (README example stage.one.digicert.com) are customer-configured.
- SentinelOne and Netskope API hosts are tenant hosts (*.sentinelone.net, *.goskope.com); rows carry patterns, not literals.
- GoDaddy commerce fulfillments use fulfillment.api.commerce.godaddy.com and the CLI uses api.developer.commerce.godaddy.com; OTE test hosts are under ote-godaddy.com, outside the pack domains.

## Unknowns

Every unverified child (44) is unknown; its `notes` say what was searched and why it was not enough. Within verified rows, a
`null` field means the cited source does not state it.

## Rejected sources

- ADP dropped (no vendor-owned source reachable), replaced by the spare SonarCloud: the former adplabs GitHub organisation no longer exists, and every adp-connection-* repository found is a personal fork or copy
- registry.npmjs.org adp-connection: maintained by a personal gmail account, not an ADP scope or account
- pypi.org adp_connection 1.0.1: author email is an adp.com contractor address but the PyPI account owner could not be confirmed (maintainer page not readable), so ownership is unclear
- Third-party ADP Workforce Now SDKs and API profiles on GitHub (several organisations and personal accounts): not ADP
- github.com/adp: an unrelated personal account, not ADP
- Workday/WorkdayBlackberryWrapper: repository description names m.myworkday.com but the repository was not read; not used
- Workday/everywhere: its Sana plugin .mcp.json has an empty MCP url, so no host can be taken from it
- Workday/WorkdayDeveloperAgentForClaude: links to developer.workday.com only, no network endpoints
- Gusto/gusto.github.io (API docs site source) and Gusto/embedded-react-sdk: cloned or listed but not needed; the OpenAPI document in Gusto/gusto-python-client was used instead
- citrixonline/GoToMeeting-Ruby: README says 'It isn't an official repository yet', and it uses the retired api.citrixonline.com host; ownership/official status unclear
- goto-developers send-sms-demo, screen-pop-demo, central-public-api-demo: vendor-owned but about GoTo Connect / LogMeIn Central APIs, not GoTo Meeting; not used for GoTo Meeting children
- goto-opensource/*: LogMeIn host, Kubernetes and library projects; nothing on GoTo Meeting
- PyPI docsend: third-party package (individual author), converts DocSend links to PDF
- GitHub docsend org (slack-avalon-bot, jquery-ui-dist, omniauth-joinme): no DocSend product content; ownership not confirmed
- npm 4shared: third-party (individual maintainer, Bitbucket repo)
- GitHub user 4shared (M722HC tablet repo, 2014): ownership not established, unrelated
- Community 4shared downloaders and clients on GitHub: third-party
- Dialpad websocket event URL example in dialpad_api_spec.json: embeds a signed token-like value; not quoted (secret-scan safety)
- Sendspace (spare): not used; its site was also refused and no vendor-owned GitHub, npm or PyPI source was found (only third-party clients), so swapping it for 4shared would not add a verified row
- braze-inc/braze-docs: git ls-remote asks for credentials (not public); not used
- segmentio/segment-docs: git ls-remote asks for credentials (not public); not used
- hotjar/hotjar-api: does not exist (git ls-remote asks for credentials)
- braze-inc/braze-android-sdk droidboy BrazeLogEntryClassifier.kt: /api/v3/data and elsa.braze.com appear only in a sample-app comment; not used as a signal
- braze-inc/braze-examples, braze-inc/braze-growth-shares-gists: no Braze REST paths for messaging; nothing cited
- analytics-next playground tracking-plan.js: demo code, not used
- OneSignal/onesignal-node-api: not needed (OneSignal/api holds the spec it is generated from)
- Kaseya-Automation-Team/VSAModule and Kaseya-Automation-Team/Kaseya-Automation-Team: module manifest names Kaseya Professional Services, but the organisation's ownership could not be confirmed against a vendor page (help.kaseya.com refused)
- screenconnect/FreeRDP: a fork of FreeRDP with no ScreenConnect endpoints
- LabTechSoftware/ConnectWisePSA-SDK: ConnectWise PSA, not ScreenConnect; ownership not confirmed
- Third-party MCP servers for ScreenConnect, Atera, NinjaOne and Autotask (WYRE-AI): not vendor-owned
- Community PowerShell, PHP and Python clients for Atera, NinjaOne and ScreenConnect (personal accounts and consultancies): third-party
- api-evangelist/atera, api-evangelist/splashtop: third-party API profiles
- NinjaRMM screening/recruiting repositories (ninjarmm_screening, ninjaone_automation_screening, ...): vendor-owned but hiring exercises, not product sources
- kaseya/mcp-servers RMM/datto-rmm-0.1.0.mcpb and plugin zips: compressed bundles, no verbatim quote possible
- godaddy/gdapi-python and godaddy/gdapi-php: old generic REST clients, not used; godaddy/cli is current
- digicert/digicert_client: last commit 2015, host is caller-supplied; digicert_express used instead for CertCentral v2
- digicert/domain-control-validation: library a CA uses to validate customer domains, not DigiCert service traffic
- Sentinel-One/ai-siem: community-driven content library, not a vendor API description
- netskopeoss/netskope_transaction_logs: 2023 sample code, superseded by netskope-py-sdk
- netskope enrollment tokenset endpoint: left out to keep secret-scan-prone identifiers out of quotes
- godaddy/cli self-update (github.com releases): GitHub host, outside the pack domains

## Blocked sources

Vendor documentation pages or repositories refused by this session's network policy (curl 000, 403 or a script-only shell) or
needing credentials. They are recorded here, not in `../blocked-urls.md`, to keep this pull request to the wave files
(PRO-588). None was paraphrased.

| Service | URL | Why |
|---|---|---|
| ADP | https://developers.adp.com/ | curl 000 |
| BambooHR | https://documentation.bamboohr.com/docs | curl 000 |
| Gusto | https://docs.gusto.com/ | curl 000 |
| Workday | https://doc.workday.com/ | curl 000 |
| Calendly | https://developer.calendly.com/api-docs | curl 000 |
| SurveyMonkey | https://api.surveymonkey.com/v3/docs | curl 000 |
| SurveyMonkey | https://developer.surveymonkey.com/api/v3/ | curl 000 |
| GoTo Meeting | https://developer.goto.com/ | curl 000 |
| 8x8 | https://developer.8x8.com/ | curl 000 |
| Dialpad | https://developers.dialpad.com/ | curl 000 |
| DocSend | https://www.docsend.com/ | curl 000 |
| DocSend | https://help.docsend.com/ | curl 000 |
| 4shared | https://www.4shared.com/developer/ | curl 000 |
| 4shared | https://help.4shared.com/ | curl 000 |
| 4shared | https://webdav.4shared.com/ | curl 000 |
| Sendspace (spare) | https://www.sendspace.com/dev.html | curl 000 |
| Microsoft Exchange Online Protection | https://github.com/MicrosoftDocs/defender-office-365-docs | needs credentials (git ls-remote asked for a username; repo private or absent), so learn.microsoft.com pages were cited instead |
| Braze | https://www.braze.com/docs/api/basics/ | curl 000 |
| Twilio Segment | https://segment.com/docs/connections/sources/catalog/libraries/server/http-api/ | curl 000 |
| Amplitude | https://amplitude.com/docs/apis/analytics/http-v2 | curl 000 |
| Mixpanel | https://docs.mixpanel.com/docs/tracking-methods/sdks/javascript | curl 000 |
| Hotjar | https://help.hotjar.com/ | curl 000 |
| OneSignal | https://documentation.onesignal.com/reference/create-notification | curl 000 |
| Atera | https://app.atera.com/apidocs/ | curl 000 |
| Atera | https://support.atera.com/hc/en-us | 403 |
| Atera | https://www.atera.com/ | curl 000 |
| NinjaOne | https://app.ninjarmm.com/apidocs/ | curl 000 |
| NinjaOne | https://oc.ninjarmm.com/apidocs-beta/authorization/overview | curl 000 |
| Kaseya | https://help.kaseya.com/ | curl 000 |
| Kaseya | https://developer.kaseya.com/ | curl 000 |
| ConnectWise ScreenConnect | https://docs.connectwise.com/ScreenConnect_Documentation | 403 |
| ConnectWise ScreenConnect | https://developer.connectwise.com/ | curl 000 |
| ConnectWise ScreenConnect | https://www.screenconnect.com/ | curl 000 |
| Zoho Assist | https://www.zoho.com/assist/api/ | curl 000 |
| GoDaddy | https://developer.godaddy.com/doc | curl 000 |
| Namecheap | https://www.namecheap.com/support/api/methods/ | curl 000 |
| DigiCert | https://dev.digicert.com/en/certcentral-apis.html | curl 000 |
| SentinelOne | https://www.sentinelone.com/ | curl 000 |
| Netskope | https://docs.netskope.com/ | curl 307 redirect, not followed |
| Zscaler | https://help.zscaler.com/ | curl 200 but script-only shell, no content |
