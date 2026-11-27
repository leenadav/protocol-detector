# Child apps, wave 5: 30 more services already in the pack (PRO-579)

Continues wave 0 (`wave-0.md`, PRO-495), wave 1 (PRO-524, PR #176), wave 2 (PRO-550, PR #180), wave 3 (PRO-569,
PR #183) and wave 4 (PRO-575, PR #185) for Engine PRO-492. Data: `wave-5.json` (schema `child-apps/v1`, `wave: 5`,
validator `../tools/check_child_apps.py`). Parent ids are those of `go/internal/content/pack.json` at `2f6ad4d` (release
`2026.11.9`, unchanged on `origin/main` at `cc1566d`); every parent was checked against the pack. Sources accessed
2026-11-27. This branch is cut from `origin/main`, not stacked on the wave 1 to 4 branches; their files were read with
`git show` only to exclude their parents.

## Scope and overlap

- **Not covered before**: waves 0 to 4 (wave 0 on `main`; waves 1 to 4 on `origin/claude/app-research-PRO-524-child-apps-wave1`,
  `...-PRO-550-child-apps-wave2`, `...-PRO-569-child-apps-wave3`, `...-PRO-575-child-apps-wave4`) hold 148 parents. None of
  the 30 below is among them; 396 pack applications remain outside waves 0 to 4.
- **PR #166** (`research/catalog-pipeline/enterprise-300.md` at its head `861bd0a`, PRO-491): rechecked, none of its 65
  service ids is an application id in the pack (the list is by design services not in the pack), so none can be a parent.
  Parents were taken from the task's SWG policy categories instead.
- **30 services** in category order: password and secret managers (1Password, Keeper, Dashlane, LastPass); MFA and endpoint
  security (Duo Security, CrowdStrike Falcon); identity and device management (Microsoft Entra ID, JumpCloud, OneLogin, Ping
  Identity, Let's Encrypt, Microsoft Intune); AI assistants and generative-AI APIs (Anthropic API, OpenAI Platform, Mistral AI,
  xAI, Perplexity, Runway); finance, ERP, expense and BI SaaS (Intuit QuickBooks, SAP Concur, Oracle NetSuite, Tableau, Oracle
  Cloud Infrastructure) and code security (Snyk); communications, design and developer tools (Vonage, Whereby, Lucid, Kaggle,
  Visual Studio / VS Code, Homebrew).
- **Spares, not needed**: `google-colab`, `sonarcloud`, `calendly`, `8x8`, `dialpad`, `ms-exchange-online-protection`.

## Method

Same as wave 4. Official vendor sources only, one citation per verified child (more in `citation_also`). Nothing is taken
from nDPI, Wireshark, Suricata, Snort or OpenAppID. No traffic was captured and no vendor API was called; only
documentation, specification and source files were fetched. **Unverified children keep every signal field `null`.**
Most vendor documentation sites were refused by this session's network policy (curl 000 or 403), so most verified rows cite the
vendor's own OpenAPI spec, SDK, CLI or documentation repository on `raw.githubusercontent.com`, pinned to a full commit SHA,
in the vendor's own GitHub organisation (49 repositories, named per row in `citation_page_date`). Three other vendor-owned
sources were reachable and used: Microsoft Learn (`learn.microsoft.com`, Intune endpoints page), `docs.x.ai` (xAI REST
reference pages) and the `@dashlane/apiconnect-worker` 3.1.9 package on `registry.npmjs.org` (the Dashlane scope, a
dependency in Dashlane's own `dashlane-cli/package.json`).

Checks before submission:
- **Quote check.** The first single-quoted string in each verified child's note was fetched again from its
  `citation_url` and found verbatim: 174 of 174.
- **Host check.** Every literal `host_sni` name of a verified row was searched in its cited files: 226 names. 28 were found only
  in another file of the same service, which was added to that row's `citation_also`. 13 are stated as built from the source:
  PingOne `auth.` + rootDomain (`oauth2/endpoints/endpoints.go`) and the spec server `https://api.pingone.{tld}/{basePath}`
  with default `com` (`pingone/api/openapi.yaml`); Snyk `//deeproxy.` replacing the API origin's `//api.`
  (`src/lib/code-config.ts`); Dashlane `'api.dashlane.com'` in `dist/postRequestAPI.js` of the npm tarball, unpacked and
  read again.
- **Ownership.** LastPass's `lastpass/lastpass-cli` README reads "(c) 2014-2019 LastPass." and its sources "Copyright (C)
  2014-2025 LastPass."; SAP Concur's `concur/developer.concur.com` says it is deprecated in favour of
  `SAP-docs/preview.developer.concur.com`, the one cited.

Rejected or unreadable sources: `concur/developer.concur.com` (deprecated); `whereby/browser-sdk` (archived, moved to
`whereby/sdk`); `xai-org/xai-cookbook` (example code only, not cited); a NetSuite skill appendix with no base URL (not
enough for REST records); `MicrosoftDocs/memdocs`, `mistralai/platform-docs-public`, `xai-org/grok-cli`,
`lucidsoftware/lucid-extension-sdk` and two other Lucid repositories (git asked for credentials). No third-party SDK or package was used.

## Result

30 services, 178 proposed children, **174 verified with an official citation** (223 distinct pages); 4 unverified.

All 30 separate partly by method, path or host; none is blocked. Microsoft Intune is `host-only`: Microsoft says TLS
inspection is not supported for `*.manage.microsoft.com` and `*.dm.microsoft.com`, so only SNI is available there.

Counts asked for by PRO-579: **30 services**; **178 children**; **174 cited** (127 primary pages, 129 rows with
`citation_also`); **4 unverified**; web-UI evidence: none for all 30 (no single official file shows a web client using
the documented API; see each `web_ui_note`).

| # | Service | Parent | Verified children | Unverified children | Verified | Separability | Web UI |
|---|---|---|---|---|---|---|---|
| 1 | 1Password | `1password` | `1password-api-auditing`, `1password-api-retrieving`, `1password-api-downloading`, `1password-client-downloading`, `1password-client-updating` | `1password-api-provisioning` | 5/6 | partial | none |
| 2 | Keeper | `keeper` | `keeper-api-authenticating`, `keeper-api-syncing`, `keeper-api-administering`, `keeper-api-attaching`, `keeper-api-retrieving` | - | 5/5 | partial | none |
| 3 | Dashlane | `dashlane` | `dashlane-api-authenticating`, `dashlane-api-syncing`, `dashlane-api-administering`, `dashlane-api-auditing`, `dashlane-api-device-managing`, `dashlane-api-key-managing` | - | 6/6 | partial | none |
| 4 | LastPass | `lastpass` | `lastpass-client-authenticating`, `lastpass-client-syncing`, `lastpass-client-editing`, `lastpass-client-sharing`, `lastpass-client-downloading` | - | 5/5 | partial | none |
| 5 | Duo Security | `duo-security` | `duo-security-api-authenticating`, `duo-security-api-authorizing`, `duo-security-api-provisioning`, `duo-security-api-auditing`, `duo-security-api-account-managing` | - | 5/5 | partial | none |
| 6 | CrowdStrike Falcon | `crowdstrike` | `crowdstrike-api-authenticating`, `crowdstrike-api-uploading`, `crowdstrike-api-downloading`, `crowdstrike-api-responding`, `crowdstrike-api-provisioning`, `crowdstrike-api-ingesting` | - | 6/6 | partial | none |
| 7 | Microsoft Entra ID (Azure AD) | `azure-ad` | `azure-ad-api-authorizing`, `azure-ad-api-token-issuing`, `azure-ad-api-device-code-signing-in`, `azure-ad-api-discovering`, `azure-ad-api-signing-out`, `azure-ad-api-admin-consenting` | - | 6/6 | partial | none |
| 8 | JumpCloud | `jumpcloud` | `jumpcloud-api-provisioning`, `jumpcloud-api-device-managing`, `jumpcloud-api-commanding`, `jumpcloud-api-assigning`, `jumpcloud-api-bulk-importing`, `jumpcloud-api-inventory-reading` | `jumpcloud-client-agent-checking-in` | 6/7 | partial | none |
| 9 | OneLogin | `onelogin` | `onelogin-api-token-issuing`, `onelogin-api-provisioning`, `onelogin-api-assigning`, `onelogin-api-auditing`, `onelogin-api-mfa-verifying`, `onelogin-api-saml-asserting` | - | 6/6 | partial | none |
| 10 | Ping Identity (PingOne) | `ping-identity` | `ping-identity-api-authorizing`, `ping-identity-api-token-issuing`, `ping-identity-api-device-authorizing`, `ping-identity-api-session-managing`, `ping-identity-api-environment-managing`, `ping-identity-api-flow-managing` | - | 6/6 | partial | none |
| 11 | Let's Encrypt | `lets-encrypt` | `lets-encrypt-api-account-registering`, `lets-encrypt-api-ordering`, `lets-encrypt-api-finalizing`, `lets-encrypt-api-certificate-downloading`, `lets-encrypt-api-revoking`, `lets-encrypt-crl-fetching` | - | 6/6 | partial | none |
| 12 | Microsoft Intune | `ms-intune` | `ms-intune-client-enrolling`, `ms-intune-client-checking-in`, `ms-intune-client-win32-app-downloading`, `ms-intune-client-ime-downloading`, `ms-intune-client-macos-script-downloading`, `ms-intune-client-aosp-managing` | - | 6/6 | host-only | none |
| 13 | Anthropic API | `anthropic-api` | `anthropic-api-api-inferencing`, `anthropic-api-api-batching`, `anthropic-api-api-uploading`, `anthropic-api-api-downloading`, `anthropic-api-api-administering`, `anthropic-api-api-federating` | - | 6/6 | partial | none |
| 14 | OpenAI Platform (API) | `openai-platform` | `openai-platform-api-inferencing`, `openai-platform-api-uploading`, `openai-platform-api-voicing`, `openai-platform-api-imaging`, `openai-platform-api-fine-tuning`, `openai-platform-api-realtime-streaming` | - | 6/6 | partial | none |
| 15 | Mistral AI API (La Plateforme) | `mistral-api` | `mistral-api-api-chatting`, `mistral-api-api-code-completing`, `mistral-api-api-uploading`, `mistral-api-api-downloading`, `mistral-api-api-ocr-processing`, `mistral-api-api-transcribing` | - | 6/6 | partial | none |
| 16 | xAI API (Grok) | `xai-api` | `xai-api-api-chatting`, `xai-api-grpc-inferencing`, `xai-api-api-uploading`, `xai-api-api-downloading`, `xai-api-api-media-generating`, `xai-api-api-voice-streaming` | - | 6/6 | partial | none |
| 17 | Perplexity API (Sonar and Agent API) | `perplexity-api` | `perplexity-api-api-chatting`, `perplexity-api-api-agent-responding`, `perplexity-api-api-searching`, `perplexity-api-api-async-researching`, `perplexity-api-api-uploading`, `perplexity-api-api-downloading` | - | 6/6 | partial | none |
| 18 | Runway | `runway` | `runway-api-video-generating`, `runway-api-image-generating`, `runway-api-audio-generating`, `runway-api-task-polling`, `runway-api-uploading`, `runway-api-administering` | - | 6/6 | partial | none |
| 19 | Intuit (QuickBooks Online) | `intuit` | `intuit-api-authorizing`, `intuit-api-querying`, `intuit-api-uploading`, `intuit-api-downloading`, `intuit-api-reporting`, `intuit-api-batching` | - | 6/6 | partial | none |
| 20 | SAP Concur | `sap-concur` | `sap-concur-api-authorizing`, `sap-concur-api-receipt-uploading`, `sap-concur-api-receipt-downloading`, `sap-concur-api-expense-reporting`, `sap-concur-api-approving`, `sap-concur-api-provisioning` | - | 6/6 | partial | none |
| 21 | Oracle NetSuite | `netsuite` | `netsuite-api-authorizing`, `netsuite-client-sdf-deploying`, `netsuite-client-file-cabinet-uploading`, `netsuite-api-suiteapp-managing`, `netsuite-web-suitelet-serving` | `netsuite-api-record-querying` | 5/6 | partial | none |
| 22 | Tableau | `tableau` | `tableau-api-signing-in`, `tableau-api-content-publishing`, `tableau-api-file-uploading`, `tableau-api-content-downloading`, `tableau-api-view-exporting`, `tableau-api-metadata-querying` | - | 6/6 | partial | none |
| 23 | Oracle Cloud Infrastructure | `oracle-cloud` | `oracle-cloud-api-object-uploading`, `oracle-cloud-api-object-downloading`, `oracle-cloud-api-object-sharing`, `oracle-cloud-api-instance-launching`, `oracle-cloud-api-identity-administering`, `oracle-cloud-api-auditing` | - | 6/6 | partial | none |
| 24 | Snyk | `snyk` | `snyk-client-authenticating`, `snyk-client-dependency-testing`, `snyk-client-monitoring`, `snyk-client-iac-result-sharing`, `snyk-client-code-analyzing`, `snyk-api-rest-calling` | - | 6/6 | partial | none |
| 25 | Vonage | `vonage` | `vonage-api-sms-sending`, `vonage-api-voice-calling`, `vonage-api-verifying`, `vonage-api-messaging`, `vonage-api-video-session-managing`, `vonage-api-network-authenticating` | - | 6/6 | partial | none |
| 26 | Whereby | `whereby` | `whereby-api-meeting-managing`, `whereby-api-recording-downloading`, `whereby-api-transcription-downloading`, `whereby-client-signaling`, `whereby-web-joining`, `whereby-web-embedding` | - | 6/6 | partial | none |
| 27 | Lucid (Lucidchart, Lucidspark) | `lucid` | `lucid-web-oauth-authorizing`, `lucid-api-token-issuing`, `lucid-api-document-importing`, `lucid-api-audit-log-reading`, `lucid-api-profile-reading` | `lucid-api-document-exporting` | 5/6 | partial | none |
| 28 | Kaggle | `kaggle` | `kaggle-api-dataset-downloading`, `kaggle-api-dataset-uploading`, `kaggle-api-competition-submitting`, `kaggle-api-competition-data-downloading`, `kaggle-api-kernel-pushing`, `kaggle-api-model-publishing` | - | 6/6 | partial | none |
| 29 | Visual Studio / VS Code | `visual-studio` | `visual-studio-api-marketplace-extension-querying`, `visual-studio-client-extension-downloading`, `visual-studio-api-extension-publishing`, `visual-studio-client-updating`, `visual-studio-web-marketplace-browsing`, `visual-studio-web-sign-in-redirecting` | - | 6/6 | partial | none |
| 30 | Homebrew | `homebrew` | `homebrew-client-metadata-syncing`, `homebrew-api-package-info-querying`, `homebrew-api-analytics-reading`, `homebrew-client-analytics-reporting`, `homebrew-client-bottle-downloading`, `homebrew-web-install-script-downloading` | - | 6/6 | partial | none |
## Where a function cannot be separated by path

Each service's `not_separable` field gives the detail. In short:
- **One host, path only**: every AI API (Anthropic, OpenAI, Mistral, xAI, Perplexity, Runway), Dashlane, LastPass, Keeper, Duo,
  CrowdStrike, JumpCloud, OneLogin, PingOne, Let's Encrypt ACME, QuickBooks, SAP Concur, Tableau, Snyk, Kaggle, Vonage and
  Lucid: a host-only (SNI) policy sees the parent, not the function.
- **Command bodies**: LastPass `lastpass/api.php`, Keeper `execute_v2_command` and Kaggle `/v1/{service}/{method}` POSTs carry
  several functions on one path, so some functions split only by body.
- **One encrypted stream**: Whereby in-call chat, screen share and recording (socket.io on `signal.appearin.net`); xAI gRPC
  methods share HTTP/2 on `api.x.ai:443` (the gRPC path is visible only after decryption).
- **Inference vs streaming**: streaming and non-streaming chat use the same POST path on every AI API; only a body flag differs.
- **Run-time transfer targets**: Runway `uploadUrl` and task outputs, Kaggle file bytes, Keeper file bytes and Snyk Code request
  paths go to hosts or paths the server or a separate library returns; the documented call is the rule, the follow-up host is not.
- **No inspection**: Intune hosts (above); the 1Password apps' sign-in and sync go through a WebAssembly core, so no path is stated.

## Findings for Engine (ENGINE-FIELD, Go only)

1. **API hosts outside the parent's pack domains** need adding, or a host-to-parent override, before these children can match:
   - `api.nexmo.com`, `rest.nexmo.com` (Vonage SMS, Voice, Verify);
   - `api.whereby.dev` (Whereby REST) and `signal.appearin.net` (Whereby signalling);
   - `api.lucid.co` (Lucid REST);
   - `vscode.dev` and the VS Code sync and CDN hosts (Visual Studio);
   - regional or government hosts: Keeper (`keepersecurity.eu`, `.com.au`, `.ca`, `.jp`, `govcloud`/`il5.keepersecurity.us`),
     LastPass `lastpass.eu`, CrowdStrike `crowdstrike.mil`, PingOne `pingone.eu`/`.asia`/`.com.au`/`.ca`/`.sg`, OpenAI
     regional `{us,eu,...}.api.openai.com`, Mistral `api.eu.mistral.ai`/`api.us.mistral.ai` and `console.mistral.ai`, xAI
     `management-api.x.ai`/`console.x.ai`, OCI realms other than `oraclecloud.com`, Graph `graph.microsoft.com` (Entra).
2. **Shared hosting must not name the parent**: Homebrew bottles on `ghcr.io` and the installer on `raw.githubusercontent.com`
   are GitHub hosts; the pack rule that shared hosting names no application stands, so those two Homebrew children are leads,
   not rules, until Engine decides.
3. **Tenant and self-hosted hosts**: Duo `api-{xxxxxxxx}.duosecurity.com`, OneLogin `{subdomain}.onelogin.com`, NetSuite
   `{accountId}.*.netsuite.com`, SAP Concur `{datacenter}.api.concursolutions.com`, OCI Object Storage namespaces are
   per-customer subdomains of the pack suffixes; 1Password Connect and SCIM bridge and Tableau Server run on customer hosts and
   are not attributable by name.
4. **Do-not-decrypt hosts**: Microsoft's Intune guidance means a rule needing a path there would require inspection the vendor
   does not support; keep Intune children SNI-only.

## Unknowns

Every unverified child (4) is unknown: `1password-api-provisioning` (SCIM bridge upstream host not stated),
`jumpcloud-client-agent-checking-in` (no agent source), `netsuite-api-record-querying` (SuiteTalk REST base URL not in the
SDK) and `lucid-api-document-exporting` (no readable source). Within verified rows, a `null` field means the cited source
does not state it (for example `host_sni` for NetSuite OAuth and SDF calls, whose host comes from the auth session; the HTTP
method of the OpenAI realtime WebSocket upgrade; Snyk Code paths).

## Blocked sources

Vendor documentation pages or repositories refused by this session's network policy (curl 000 or 403) or needing credentials.
They are recorded here, not in `../blocked-urls.md`, to keep this pull request to the wave files (PRO-579). None was paraphrased.

| Service | URL |
|---|---|
| JumpCloud | https://docs.jumpcloud.com/api/ |
| OneLogin | https://developers.onelogin.com/api-docs/2/getting-started/dev-overview |
| Ping Identity (PingOne) | https://developer.pingidentity.com/pingone-api/ |
| Let's Encrypt | https://letsencrypt.org/docs/ |
| Microsoft Intune | https://raw.githubusercontent.com/MicrosoftDocs/memdocs (repository not reachable from this session: git ls-remote requires authentication) |
| Mistral AI API (La Plateforme) | https://github.com/mistralai/platform-docs-public (git ls-remote asked for credentials: not public or not present) |
| Runway | https://docs.dev.runwayml.com/api/ |
| Intuit (QuickBooks Online) | https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/attachable |
| Intuit (QuickBooks Online) | https://developer.intuit.com/.well-known/openid_configuration/ |
| SAP Concur | https://developer.concur.com/platform/base-uris.html |
| SAP Concur | https://developer.concur.com/api-reference/receipts/endpoints.html |
| Oracle NetSuite | https://docs.oracle.com/en/cloud/saas/netsuite/ns-online-help/article_2085345571.html |
| Oracle NetSuite | https://docs.oracle.com/en/cloud/saas/netsuite/ns-online-help/section_1544787084.html |
| Tableau | https://help.tableau.com/current/api/rest_api/en-us/REST/rest_api_ref.htm |
| Oracle Cloud Infrastructure | https://docs.oracle.com/en-us/iaas/api/ |
| Snyk | https://docs.snyk.io/snyk-api |
| Snyk | https://apidocs.snyk.io/ |
| Vonage | https://developer.vonage.com/en/api/sms |
| Vonage | https://developer.vonage.com/en/api/voice |
| Whereby | https://docs.whereby.com/reference/whereby-rest-api-reference |
| Whereby | https://whereby.com |
| Lucid (Lucidchart, Lucidspark) | https://developer.lucid.co/rest-api/v1/ |
| Lucid (Lucidchart, Lucidspark) | https://github.com/lucidsoftware/lucid-extension-sdk (git ls-remote asked for credentials) |
| Kaggle | https://www.kaggle.com/docs/api |
| Visual Studio / VS Code | https://code.visualstudio.com/docs/setup/network |
| Homebrew | https://docs.brew.sh/Analytics |
| Homebrew | https://formulae.brew.sh/docs/api/ |
