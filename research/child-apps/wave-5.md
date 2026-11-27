# Child apps, wave 5: 30 more services already in the pack (PRO-579)

Continues wave 0 (`wave-0.md`, PRO-495, PR #161), wave 1 (PRO-524, PR #176), wave 2 (PRO-550, PR #180), wave 3
(PRO-569, PR #183) and wave 4 (PRO-575, PR #185) for Engine PRO-492. Data: `wave-5.json` (schema `child-apps/v1`,
`wave: 5`, validator `../tools/check_child_apps.py`). Parent ids are those of `go/internal/content/pack.json` on
`origin/main` at `cc1566d` (release `2026.11.9`); every parent was checked against the pack. Sources accessed
2026-11-27. This branch is cut from `origin/main`, not stacked on the wave 1 to 4 branches; their files were read with
`git show` only to exclude their parents and child ids.

## Scope and overlap

- **Not covered before**: waves 0 to 4 (wave 0 on `main`; waves 1 to 4 on `origin/claude/app-research-PRO-524-child-apps-wave1`,
  `...-PRO-550-child-apps-wave2`, `...-PRO-569-child-apps-wave3`, `...-PRO-575-child-apps-wave4`) hold 148 parents. None
  of the 30 below is among them, and no wave-5 child id repeats an id of waves 0 to 4 (six would have; they are named
  `<parent>-file-uploading` / `-file-downloading`).
- **PR #166** (`research/catalog-pipeline/enterprise-300.md` at its head `861bd0a`, PRO-491): rechecked, none of its 65
  service ids is an application id in the pack, so none can be a parent. Parents were taken from the SWG policy
  categories not yet covered instead.
- **30 services** in category order: password and secret managers (1Password, LastPass, Dashlane, Keeper); identity and
  SSO (Microsoft Entra ID, OneLogin, Ping Identity, JumpCloud, Duo Security); endpoint and cloud security (CrowdStrike,
  Zscaler, Snyk); AI model APIs and data science (OpenAI API Platform, Anthropic API, Mistral AI API, xAI API, Perplexity
  API, Kaggle); CRM, marketing and product analytics (Braze, Twilio Segment, Amplitude, Mixpanel, OneSignal, Tableau);
  Microsoft security, email security and device management (Defender for Endpoint, Exchange Online Protection, Intune);
  developer and cloud platforms (SonarQube Cloud, Oracle Cloud Infrastructure, JetBrains).
- **Left out**: ITSM/ticketing, e-signature, design and backup parents in the pack are already covered by waves 0 to 4
  (ServiceNow, Zendesk, Freshworks, PagerDuty, DocuSign, Dropbox Sign, PandaDoc, Figma, Canva, Backblaze, IDrive, ...).
  `vonage`, `sentinelone`, `whereby`, `netskope` and `lucid` were held as spares and not needed.

## Method

Same as wave 4, with one stricter rule. Official vendor sources only, one citation per verified child (more in
`citation_also`). Nothing is taken from nDPI, Wireshark, Suricata, Snort or OpenAppID. No traffic was captured and no
vendor API was called; only documentation, specification and source files were fetched. **Unverified children keep
every signal field `null`.** Most vendor documentation sites were refused by this session's network policy (listed
below), so 206 of the 248 cited pages are vendor files on `raw.githubusercontent.com` pinned to a full commit SHA in the
vendor's own GitHub organisation (49 repositories, named per row in `citation_page_date`). The other 42 are the vendor's
own documentation pages (learn.microsoft.com, duo.com/docs, docs.x.ai, docs.perplexity.ai, support.1password.com) or
the vendor's own registry documents (Dashlane on registry.npmjs.org, Braze on pypi.org); those are not pinned and were
read as served on 2026-11-27.

Checks before submission (all re-run on the merged file by an independent script):
- **Quote check.** The first single-quoted string in each verified child's note was fetched again from its
  `citation_url` and found verbatim: 164 of 164.
- **Host check.** Every literal `host_sni` name of a verified row was searched in its cited files: 266 names, 263 found
  verbatim; the other three are built from the source as the note states (Zscaler `api.zdxcloud.net` and
  `api.zdxbeta.net` from `https://api.{cloud}.net` in `zscaler/zdx/legacy.py`; Snyk `deeproxy.snyk.io` from the
  `app.`/`api.` to `deeproxy.` rewrite in `src/lib/code-config.ts`).
- **Path check.** Every literal segment of every `path_pattern` alternative was found in the row's cited files.
- **Pinning.** Every `raw.githubusercontent.com` citation names a 40-hex commit (206 of 206).
- **Strictness (new in wave 5).** A `content_type` or `http_method` that the cited files do not spell literally is set
  to `null`, and the note says so: 21 content types (for example `application/json` sent by an SDK helper that names no
  media type) and 5 methods (PingOne authorize and token, Braze export, two JetBrains downloads) were nulled. Every
  verified row still carries at least one signal.

Rejected or unused sources: `1Password/onepassword-sdk-python` (calls made by a bundled native core, no host or path in
the source); `1Password/scim-examples` (only the self-hosted bridge's `/health`); PyPI `braze-client` and `braze-sdk`
(third-party authors, not Braze); `braze-inc/braze-examples` (community samples, no REST endpoints); `OneSignal/api`
(older spec, superseded by `onesignal-python-api`); `snyk/snyk-api-ts`, `snyk/rest-api-docs`, `braze-inc/braze-docs`,
`Dashlane/apiconnect-worker` and the MicrosoftDocs repositories (not readable without credentials; the Microsoft
content was read on learn.microsoft.com and Dashlane's own npm package was used); `sonarcloud.io/web_api` (that would
call the service). The SonarSource `sonarqube` server source is used for `/api/ce/submit` only, with a caveat in the
row, because the SonarQube Cloud server is not public.

## Result

30 services, 173 proposed children, **164 verified with an official citation** (248 distinct pages); 9 unverified.

All 30 separate partly by method, path or host; none is blocked. No service has web-UI evidence (all `none`; see each
`web_ui_note`).

Counts asked for by PRO-579: **30 services**; **173 children**; **164 cited** (127 primary pages, 119 rows with
`citation_also`); **9 unverified**.

| # | Service | Parent | Verified children | Unverified children | Verified | Separability | Web UI |
|---|---|---|---|---|---|---|---|
| 1 | 1Password | `1password` | `1password-api-events-exporting`, `1password-client-file-transferring`, `1password-client-updating`, `1password-api-vault-reading`, `1password-api-vault-writing`, `1password-api-file-downloading` | - | 6/6 | partial | none |
| 2 | LastPass | `lastpass` | `lastpass-client-authenticating`, `lastpass-client-vault-downloading`, `lastpass-client-vault-writing`, `lastpass-client-attachment-downloading`, `lastpass-client-sharing` | `lastpass-api-administering` | 5/6 | partial | none |
| 3 | Dashlane | `dashlane` | `dashlane-api-authenticating`, `dashlane-api-vault-syncing`, `dashlane-api-team-administering`, `dashlane-api-audit-log-exporting`, `dashlane-api-key-managing` | `dashlane-api-vault-writing` | 5/6 | partial | none |
| 4 | Keeper | `keeper` | `keeper-client-authenticating`, `keeper-client-vault-syncing`, `keeper-client-vault-writing`, `keeper-client-attachment-transferring`, `keeper-client-sharing`, `keeper-api-secrets-fetching` | - | 6/6 | partial | none |
| 5 | Microsoft Entra ID (Azure AD) | `azure-ad` | `azure-ad-web-authorizing`, `azure-ad-api-token-issuing`, `azure-ad-api-device-code-requesting`, `azure-ad-web-saml-signing`, `azure-ad-api-discovering` | - | 5/5 | partial | none |
| 6 | OneLogin | `onelogin` | `onelogin-api-token-issuing`, `onelogin-api-user-provisioning`, `onelogin-api-app-administering`, `onelogin-api-events-exporting`, `onelogin-api-saml-asserting`, `onelogin-api-mfa-managing` | - | 6/6 | partial | none |
| 7 | Ping Identity (PingOne) | `ping-identity` | `ping-identity-api-authenticating`, `ping-identity-web-signing`, `ping-identity-api-administering`, `ping-identity-api-audit-exporting`, `ping-identity-api-image-uploading` | - | 5/5 | partial | none |
| 8 | JumpCloud | `jumpcloud` | `jumpcloud-api-user-administering`, `jumpcloud-api-command-running`, `jumpcloud-api-device-querying`, `jumpcloud-api-audit-exporting`, `jumpcloud-api-report-downloading` | `jumpcloud-web-authenticating` | 5/6 | partial | none |
| 9 | Duo Security | `duo-security` | `duo-security-api-authenticating`, `duo-security-web-authenticating`, `duo-security-api-administering`, `duo-security-api-log-exporting`, `duo-security-api-provisioning` | - | 5/5 | partial | none |
| 10 | CrowdStrike Falcon | `crowdstrike` | `crowdstrike-api-authenticating`, `crowdstrike-api-sample-uploading`, `crowdstrike-api-artifact-downloading`, `crowdstrike-api-remote-responding`, `crowdstrike-api-alert-querying`, `crowdstrike-api-event-streaming` | - | 6/6 | partial | none |
| 11 | Zscaler | `zscaler` | `zscaler-api-authenticating`, `zscaler-api-zia-administering`, `zscaler-api-audit-exporting`, `zscaler-api-sample-uploading`, `zscaler-api-zpa-administering`, `zscaler-api-zdx-querying` | - | 6/6 | partial | none |
| 12 | Snyk | `snyk` | `snyk-api-authenticating`, `snyk-client-testing`, `snyk-client-monitoring`, `snyk-client-code-uploading` | `snyk-api-audit-exporting` | 4/5 | partial | none |
| 13 | OpenAI API Platform | `openai-platform` | `openai-platform-api-prompting`, `openai-platform-api-uploading`, `openai-platform-api-batching`, `openai-platform-api-finetuning`, `openai-platform-api-streaming`, `openai-platform-api-administering` | - | 6/6 | partial | none |
| 14 | Anthropic API | `anthropic-api` | `anthropic-api-prompting`, `anthropic-api-file-uploading`, `anthropic-api-file-downloading`, `anthropic-api-batching`, `anthropic-api-administering`, `anthropic-api-agenting` | - | 6/6 | partial | none |
| 15 | Mistral AI API | `mistral-api` | `mistral-api-prompting`, `mistral-api-file-uploading`, `mistral-api-file-downloading`, `mistral-api-batching`, `mistral-api-streaming`, `mistral-api-administering` | - | 6/6 | partial | none |
| 16 | xAI API | `xai-api` | `xai-api-prompting`, `xai-api-uploading`, `xai-api-downloading`, `xai-api-batching`, `xai-api-streaming`, `xai-api-administering` | - | 6/6 | partial | none |
| 17 | Perplexity API | `perplexity-api` | `perplexity-api-prompting`, `perplexity-api-searching`, `perplexity-api-file-uploading`, `perplexity-api-file-downloading`, `perplexity-api-batching`, `perplexity-api-administering` | - | 6/6 | partial | none |
| 18 | Kaggle | `kaggle` | `kaggle-api-downloading`, `kaggle-api-uploading`, `kaggle-api-submitting`, `kaggle-api-pushing`, `kaggle-api-pulling`, `kaggle-api-publishing` | - | 6/6 | partial | none |
| 19 | Braze | `braze` | `braze-client-tracking`, `braze-web-loading`, `braze-api-exporting`, `braze-api-authoring` | `braze-api-ingesting`, `braze-api-messaging` | 4/6 | partial | none |
| 20 | Twilio Segment | `segment` | `segment-client-tracking`, `segment-api-ingesting`, `segment-api-authenticating`, `segment-client-configuring`, `segment-api-administering`, `segment-api-deleting` | - | 6/6 | partial | none |
| 21 | Amplitude | `amplitude` | `amplitude-api-ingesting`, `amplitude-client-recording`, `amplitude-client-configuring`, `amplitude-api-flagging`, `amplitude-api-cohort-downloading` | `amplitude-api-exporting` | 5/6 | partial | none |
| 22 | Mixpanel | `mixpanel` | `mixpanel-client-tracking`, `mixpanel-api-ingesting`, `mixpanel-api-importing`, `mixpanel-client-recording`, `mixpanel-api-flagging` | `mixpanel-api-exporting` | 5/6 | partial | none |
| 23 | OneSignal | `onesignal` | `onesignal-api-sending`, `onesignal-api-exporting`, `onesignal-api-provisioning`, `onesignal-api-administering`, `onesignal-api-authoring`, `onesignal-client-loading` | - | 6/6 | partial | none |
| 24 | Tableau (Cloud/Server) | `tableau` | `tableau-api-authenticating`, `tableau-api-publishing`, `tableau-api-downloading`, `tableau-api-exporting`, `tableau-api-provisioning`, `tableau-api-querying` | - | 6/6 | partial | none |
| 25 | Microsoft Defender for Endpoint | `ms-defender-endpoint` | `ms-defender-endpoint-api-isolating`, `ms-defender-endpoint-api-responding`, `ms-defender-endpoint-api-downloading`, `ms-defender-endpoint-api-indicating`, `ms-defender-endpoint-api-hunting`, `ms-defender-endpoint-client-reporting` | - | 6/6 | partial | none |
| 26 | Exchange Online Protection | `ms-exchange-online-protection` | `ms-exchange-online-protection-client-receiving`, `ms-exchange-online-protection-web-clicking`, `ms-exchange-online-protection-web-quarantining`, `ms-exchange-online-protection-api-releasing` | - | 4/4 | partial | none |
| 27 | Microsoft Intune | `ms-intune` | `ms-intune-client-enrolling`, `ms-intune-client-checking-in`, `ms-intune-client-downloading`, `ms-intune-api-inventorying`, `ms-intune-api-wiping`, `ms-intune-api-uploading` | - | 6/6 | partial | none |
| 28 | SonarQube Cloud (SonarCloud) | `sonarcloud` | `sonarcloud-client-downloading`, `sonarcloud-api-submitting`, `sonarcloud-api-querying`, `sonarcloud-api-triaging`, `sonarcloud-client-notifying` | - | 5/5 | partial | none |
| 29 | Oracle Cloud Infrastructure | `oracle-cloud` | `oracle-cloud-api-uploading`, `oracle-cloud-api-downloading`, `oracle-cloud-api-provisioning`, `oracle-cloud-api-administering`, `oracle-cloud-client-authenticating`, `oracle-cloud-api-retrieving` | - | 6/6 | partial | none |
| 30 | JetBrains | `jetbrains` | `jetbrains-api-uploading`, `jetbrains-client-downloading`, `jetbrains-client-installing`, `jetbrains-client-resolving`, `jetbrains-web-licensing` | `jetbrains-client-assisting` | 5/6 | partial | none |

## Where a function cannot be separated by path

Each service's `not_separable` field gives the detail. In short:
- **One host, path only**: every API-first parent here (OpenAI, Anthropic, Mistral, xAI, Perplexity, CrowdStrike, Duo,
  OneLogin, Keeper, Dashlane, Tableau, OneSignal, Braze REST, SonarQube Cloud, JetBrains Marketplace) puts all functions
  on one host; a host-only (SNI) policy sees only the parent.
- **Same path, method only**: Oracle Object Storage upload vs download (PUT vs GET on `/n/{ns}/b/{bucket}/o/{object}`),
  OneSignal view vs create notification (GET vs POST `/notifications`), Snyk test vs monitor.
- **One path, body selects the function**: LastPass `lastpass/api.php` (a `cmd` form field), Keeper
  `vault/execute_v2_command` (includes audit export), Kaggle `POST /v1/{service}/{method}` JSON calls, Segment
  `/v1/batch` (all event types), Amplitude identify and revenue on `/2/httpapi`.
- **Header selects the feature**: Anthropic beta features (`anthropic-beta` header on the same paths).
- **Not decryptable or not HTTP**: Intune device check-in (Microsoft states SSL inspection is not supported on
  `*.manage.microsoft.com` / `*.dm.microsoft.com`, so host-only); Exchange Online Protection inbound mail and SMTP relay
  (SMTP on tcp/25 to the same tenant host, invisible to an HTTP rule).
- **Run-time transfer targets**: Kaggle blob upload (`create_url`) and download redirect, Defender live-response output
  (a time-limited storage link) and Tableau chunked uploads go to URLs the server returns.

## Findings for Engine (ENGINE-FIELD, Go only)

1. **API hosts outside the parent's pack domains** need adding, or a host-to-parent override, before these children can match:
   - Microsoft Defender for Endpoint: `api.security.microsoft.com` and its regional names (all documented API functions),
     `security.microsoft.com` (portal; also EOP quarantine);
   - Zscaler OneAPI `api.zsapi.net` / `api.{cloud}.zsapi.net`, FedRAMP `api.zscalergov.us` and `{vanity}.zidentitygov.us`;
   - xAI management `management-api.x.ai`; Mistral regional `api.eu.mistral.ai` and `api.us.mistral.ai`;
   - Segment Public API `api.segmentapis.com` / `eu1.api.segmentapis.com`; Braze `js.appboycdn.com`, `sdk.api.braze.eu`;
     Mixpanel `cdn.mxpnl.com`;
   - PingOne regional `auth.pingone.{eu,asia,com.au,ca,sg}` and `api.pingone.{...}`; Keeper regional
     `keepersecurity.{eu,com.au,ca,jp}` and `*.keepersecurity.us`; LastPass EU `lastpass.eu`;
   - SonarQube Cloud US/AU `sonarqube.us`, `sonarqube.au`; CrowdStrike `api.us-gov-2.crowdstrike.mil`; Snyk `snykgov.io`;
   - Microsoft authority hosts `login.microsoft.com`, `login.windows.net`, `sts.windows.net`, `login.microsoftonline.us`.
2. **Shared hosts must not name the parent**: Intune and Entra admin calls go to `graph.microsoft.com` (all of Microsoft
   Graph); Intune enrollment uses `enterpriseregistration.windows.net` and Win32 content also comes from
   `*.blob.core.windows.net`; OCI opt-in realm hosts `*.oci.customer-oci.com`.
3. **Tenant and self-hosted hosts**: Duo `api-XXXXXXXX.duosecurity.com`, OneLogin `{subdomain}.onelogin.com`, Tableau
   `{pod}.online.tableau.com`, Braze `rest.{cluster}.braze.com`; 1Password Connect and SCIM bridge and Tableau Server run
   on customer hosts, so those rows match by path only (`host_sni` null).
4. **Non-HTTP and upgrade transports**: Exchange Online Protection SMTP tcp/25; xAI gRPC over HTTP/2 to `api.x.ai:443`
   (paths like `/xai_api.Chat/GetCompletion`); WebSockets for OpenAI realtime (`wss://api.openai.com/v1/realtime`),
   Mistral realtime speech, xAI realtime and STT, SonarQube Cloud IDE events (`wss://events-api.sonarcloud.io/`);
   OpenAI `/v1/realtime/calls` sets up WebRTC, whose media flows outside HTTP.

## Unknowns

Every unverified child (9) is unknown; the ids are in the table. Within verified rows, a `null` field means the cited
source does not state it (in wave 5 this includes every content type or method the files do not spell literally).
Not described by any source reached: the CrowdStrike sensor channel to `cloudsink.net`, Zscaler Client Connector tunnels,
Duo Mobile push, JetBrains AI.

## Blocked sources

Vendor documentation pages refused by this session's network policy (curl 000 or a 403 from the proxy) or not readable
without credentials. They are recorded here, not in `../blocked-urls.md`, to keep this pull request to the wave files
(PRO-579). None was paraphrased.

| Service | URL |
|---|---|
| 1Password | https://developer.1password.com/docs/connect/ |
| 1Password | https://developer.1password.com/docs/events-api/reference/ |
| LastPass | https://www.lastpass.com/ |
| LastPass | https://support.lastpass.com/ |
| OneLogin | https://developers.onelogin.com/api-docs/2/getting-started/dev-overview |
| Ping Identity (PingOne) | https://developer.pingidentity.com/ |
| JumpCloud | https://docs.jumpcloud.com/api/ |
| CrowdStrike Falcon | https://falcon.crowdstrike.com/documentation |
| Snyk | https://docs.snyk.io/snyk-api |
| Mistral AI API | https://docs.mistral.ai/api/ |
| Kaggle | https://www.kaggle.com/docs/api |
| Braze | https://www.braze.com/docs/api/endpoints/user_data/post_user_track |
| Braze | https://github.com/braze-inc/braze-docs |
| Twilio Segment | https://segment.com/docs/connections/sources/catalog/libraries/server/http-api/ |
| Amplitude | https://amplitude.com/docs/apis/analytics/http-v2 |
| Mixpanel | https://developer.mixpanel.com/reference/track-event |
| OneSignal | https://documentation.onesignal.com/reference/create-notification |
| Tableau (Cloud/Server) | https://help.tableau.com/current/api/rest_api/en-us/REST/rest_api_ref.htm |
| SonarQube Cloud (SonarCloud) | https://sonarcloud.io/documentation |
| SonarQube Cloud (SonarCloud) | https://docs.sonarsource.com/sonarqube-cloud/ |
| SonarQube Cloud (SonarCloud) | https://docs.sonarsource.com/ |
| Oracle Cloud Infrastructure | https://docs.oracle.com/en-us/iaas/api/ |
| JetBrains | https://plugins.jetbrains.com/docs/marketplace/plugin-upload.html |
