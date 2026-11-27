# Child apps, wave 4: 30 more services already in the pack (PRO-575)

Continues wave 0 (`wave-0.md`, PRO-495, PR #161), wave 1 (PRO-524, PR #176), wave 2 (PRO-550, PR #180) and wave 3
(PRO-569, PR #183) for Engine PRO-492. Data: `wave-4.json` (schema `child-apps/v1`, `wave: 4`, validator
`../tools/check_child_apps.py`). Parent ids are those of `go/internal/content/pack.json` at `59fb9fc` (release
`2026.11.9`, identical on `origin/main` at `cc1566d`); every parent was checked against the pack. Sources accessed
2026-11-27. This branch is cut from `origin/main`, not stacked on the wave 1 to 3 branches; their files were read with
`git show` only to exclude their parents.

## Scope and overlap

- **Not covered before**: waves 0 to 3 (wave 0 on `main`; waves 1 to 3 on `origin/claude/app-research-PRO-524-child-apps-wave1`,
  `...-PRO-550-child-apps-wave2`, `...-PRO-569-child-apps-wave3`) hold 118 parents. None of the 30 below is among them.
- **PR #166** (`research/catalog-pipeline/enterprise-300.md` at its head `861bd0a`, PRO-491): rechecked, none of its rows
  is an application id in the pack, so none can be a parent. Parents were taken from the task's categories instead.
- **30 services** in category order: collaboration, chat and video (Signal, Matrix / Element, Jitsi Meet, Twilio,
  RingCentral, Basecamp); dev tools, CI and observability (CircleCI, Heroku, Sentry, Datadog, New Relic); cloud and data
  platforms (DigitalOcean, Linode, Databricks, Snowflake, Splunk Cloud); finance, HR and forms SaaS (Stripe, PayPal, Xero,
  Expensify, Typeform, Shopify); remote access and tunnels (ngrok, Tailscale, RustDesk, ZeroTier); security and identity
  (VirusTotal, Okta, Auth0, Bitwarden).
- **Left out**: `mongodb` (in the pack with no app domains: a wire protocol, no host to split); `crowdstrike` and
  `duo-security` were held as spares and not needed.

## Method

Same as wave 3. Official vendor sources only, one citation per verified child (more in `citation_also`). Nothing is taken
from nDPI, Wireshark, Suricata, Snort or OpenAppID. No traffic was captured and no vendor API was called; only
documentation, specification and source files were fetched. **Unverified children keep every signal field `null`.**
Every vendor documentation site tried was refused by this session's network policy (curl 000) or not needed, so every
verified row cites the vendor's own OpenAPI spec, SDK, client source or documentation repository on
`raw.githubusercontent.com`, pinned to a full commit SHA, in the vendor's own GitHub organisation (50 repositories, listed
per row in `citation_page_date`).

Checks before submission:
- **Quote check.** The first single-quoted string in each verified child's note was fetched again from its
  `citation_url` and found verbatim: 165 of 165; the 4 web-UI quotes likewise.
- **Host check.** Every literal `host_sni` name of a verified row was searched in its cited files: 161 names, 159 found
  verbatim; the other two are stated as built from the source (Datadog EU intake from the spec's `{subdomain}.{site}`
  server with site `datadoghq.eu`; VirusTotal from `_API_HOST = "https://www.virustotal.com"` in `vt/client.py`, read again).
- **Path check.** Every `path_pattern` alternative was matched to its cited files (allowing a documented base prefix such
  as `/api/v2` or `/v4`). One unsupported alternative was removed (CircleCI `/settings/organization`).
- **Downgrades.** Two proposed web-UI ratings were reduced to `none` because the quote did not show it by itself
  (Expensify `different`: a QA edge-case comment; Bitwarden `same`: a development proxy setting). One placeholder host
  (`customer.splunkcloud.com` from a README) is written as the pattern `{stack}.splunkcloud.com`.

Rejected sources: `linode/linode-api-docs` (end of service, replaced by `linode/linode-api-openapi`); `Shopify/shopify-api-js`
(superseded by `shopify-app-js`, not needed); Splunk repositories that name no Splunk Cloud host. No third-party SDK or
package was used.

## Result

30 services, 172 proposed children, **165 verified with an official citation** (192 distinct pages); 7 unverified.

All 30 separate partly by method, path or host; none is blocked. 4 services with web-UI evidence.

Counts asked for by PRO-575: **172 children**; **165 cited** (105 primary pages, 109 rows with `citation_also`);
**7 unverified**; web-UI evidence: Matrix / Element (same), Sentry (partial), Linode (Akamai Cloud) (same), Okta (partial).

| # | Service | Parent | Verified children | Unverified children | Verified | Separability | Web UI |
|---|---|---|---|---|---|---|---|
| 1 | Signal | `signal` | `signal-client-messaging`, `signal-client-sending`, `signal-cdn-downloading`, `signal-cdn-uploading`, `signal-storage-syncing`, `signal-client-calling` | - | 6/6 | partial | none |
| 2 | Matrix / Element | `matrix-element` | `matrix-element-api-sending`, `matrix-element-api-syncing`, `matrix-element-api-uploading`, `matrix-element-api-downloading`, `matrix-element-api-loggingin` | - | 5/5 | partial | same |
| 3 | Jitsi Meet | `jitsi-meet` | `jitsi-meet-web-joining`, `jitsi-meet-client-signaling`, `jitsi-meet-client-boshing`, `jitsi-meet-api-embedding`, `jitsi-meet-api-livestreaming` | `jitsi-meet-client-recording` | 5/6 | partial | none |
| 4 | Twilio | `twilio` | `twilio-api-messaging`, `twilio-api-reading`, `twilio-api-calling`, `twilio-api-downloading`, `twilio-verify-verifying`, `twilio-video-managing` | - | 6/6 | partial | none |
| 5 | RingCentral | `ringcentral` | `ringcentral-api-texting`, `ringcentral-api-faxing`, `ringcentral-api-reporting`, `ringcentral-api-downloading`, `ringcentral-api-posting`, `ringcentral-api-conferencing` | - | 6/6 | partial | none |
| 6 | Basecamp | `basecamp` | `basecamp-api-uploading`, `basecamp-api-downloading`, `basecamp-api-posting`, `basecamp-api-chatting`, `basecamp-api-tasking`, `basecamp-api-authorizing` | - | 6/6 | partial | none |
| 7 | CircleCI | `circleci` | `circleci-api-triggering`, `circleci-api-logreading`, `circleci-api-secretmanaging`, `circleci-api-runneradministering`, `circleci-api-orbpublishing`, `circleci-web-settingsbrowsing` | - | 6/6 | partial | none |
| 8 | Heroku | `heroku` | `heroku-api-deploying`, `heroku-api-configuring`, `heroku-api-logstreaming`, `heroku-api-dynorunning`, `heroku-api-accessadministering`, `heroku-client-gitpushing` | - | 6/6 | partial | none |
| 9 | Sentry | `sentry` | `sentry-api-eventingesting`, `sentry-api-issuereading`, `sentry-api-releasing`, `sentry-api-sourcemapuploading`, `sentry-api-orgadministering` | - | 5/5 | partial | partial |
| 10 | Datadog | `datadog` | `datadog-api-metricsubmitting`, `datadog-api-logsubmitting`, `datadog-api-querying`, `datadog-api-orgadministering`, `datadog-client-agentforwarding` | - | 5/5 | partial | none |
| 11 | New Relic | `new-relic` | `new-relic-api-logingesting`, `new-relic-api-metricingesting`, `new-relic-api-eventingesting`, `new-relic-api-nerdgraphquerying`, `new-relic-api-syntheticsscripting` | - | 5/5 | partial | none |
| 12 | DigitalOcean | `digitalocean` | `digitalocean-api-dropletcreating`, `digitalocean-api-appdeploying`, `digitalocean-api-applogviewing`, `digitalocean-api-kubernetesadministering`, `digitalocean-api-billingreading` | `digitalocean-client-spacestransferring` | 5/6 | partial | none |
| 13 | Linode (Akamai Cloud) | `linode` | `linode-api-provisioning`, `linode-api-paying`, `linode-api-billing-reading`, `linode-api-object-storage-administering`, `linode-client-object-storage-transferring`, `linode-web-consoling` | - | 6/6 | partial | same |
| 14 | Databricks | `databricks` | `databricks-api-uploading`, `databricks-api-downloading`, `databricks-api-querying`, `databricks-api-running`, `databricks-api-exporting`, `databricks-api-account-administering` | - | 6/6 | partial | none |
| 15 | Snowflake | `snowflake` | `snowflake-api-authenticating`, `snowflake-api-querying`, `snowflake-client-stage-uploading`, `snowflake-client-stage-downloading`, `snowflake-api-snowpipe-ingesting` | `snowflake-web-browsing` | 5/6 | partial | none |
| 16 | Splunk Cloud Platform | `splunk-cloud` | `splunk-cloud-api-ingesting`, `splunk-cloud-api-searching`, `splunk-cloud-api-app-installing`, `splunk-cloud-api-app-exporting`, `splunk-cloud-web-searching` | - | 5/5 | partial | none |
| 17 | Stripe | `stripe` | `stripe-api-paying`, `stripe-api-transferring`, `stripe-api-uploading`, `stripe-api-reporting`, `stripe-api-connecting`, `stripe-web-loading` | - | 6/6 | partial | none |
| 18 | PayPal | `paypal` | `paypal-api-paying`, `paypal-api-disbursing`, `paypal-api-invoicing`, `paypal-api-reporting`, `paypal-api-disputing`, `paypal-web-approving` | - | 6/6 | partial | none |
| 19 | Xero | `xero` | `xero-api-invoicing`, `xero-api-uploading`, `xero-api-downloading`, `xero-api-reporting`, `xero-api-payrolling`, `xero-api-authenticating` | - | 6/6 | partial | none |
| 20 | Expensify | `expensify` | `expensify-client-submitting`, `expensify-client-paying`, `expensify-client-chatting`, `expensify-api-integrating` | `expensify-client-syncing` | 4/5 | partial | none |
| 21 | Typeform | `typeform` | `typeform-api-creating`, `typeform-api-reading`, `typeform-api-deleting`, `typeform-api-webhooking`, `typeform-api-uploading`, `typeform-web-responding` | - | 6/6 | partial | none |
| 22 | Shopify | `shopify` | `shopify-api-administering`, `shopify-api-storefronting`, `shopify-api-authenticating`, `shopify-web-administering` | `shopify-api-bulk-exporting`, `shopify-api-uploading` | 4/6 | partial | none |
| 23 | ngrok | `ngrok` | `ngrok-client-tunneling`, `ngrok-api-credential-administering`, `ngrok-api-endpoint-configuring`, `ngrok-api-session-reading` | `ngrok-client-updating` | 4/5 | partial | none |
| 24 | Tailscale | `tailscale` | `tailscale-client-coordinating`, `tailscale-client-relaying`, `tailscale-client-stun-probing`, `tailscale-client-log-uploading`, `tailscale-api-policy-administering`, `tailscale-api-inventory-reading` | - | 6/6 | partial | none |
| 25 | RustDesk | `rustdesk` | `rustdesk-client-rendezvousing`, `rustdesk-client-relaying`, `rustdesk-client-websocketing`, `rustdesk-api-authenticating`, `rustdesk-api-address-booking`, `rustdesk-api-uploading` | - | 6/6 | partial | none |
| 26 | ZeroTier | `zerotier` | `zerotier-client-tunneling`, `zerotier-api-reading`, `zerotier-api-configuring`, `zerotier-api-authorizing`, `zerotier-api-administering` | - | 5/5 | partial | none |
| 27 | VirusTotal | `virustotal` | `virustotal-api-uploading`, `virustotal-api-submitting`, `virustotal-api-reporting`, `virustotal-api-downloading`, `virustotal-api-searching`, `virustotal-api-feeding` | - | 6/6 | partial | none |
| 28 | Okta | `okta` | `okta-api-authenticating`, `okta-api-authorizing`, `okta-api-provisioning`, `okta-api-assigning`, `okta-api-auditing`, `okta-api-self-servicing` | - | 6/6 | partial | partial |
| 29 | Auth0 | `auth0` | `auth0-api-authenticating`, `auth0-api-registering`, `auth0-api-provisioning`, `auth0-api-auditing`, `auth0-api-importing`, `auth0-api-exporting` | - | 6/6 | partial | none |
| 30 | Bitwarden | `bitwarden` | `bitwarden-api-authenticating`, `bitwarden-api-syncing`, `bitwarden-client-notifying`, `bitwarden-api-sharing`, `bitwarden-api-receiving`, `bitwarden-client-icon-fetching` | - | 6/6 | partial | none |

## Web-UI evidence

- **Matrix / Element** (`same`, https://raw.githubusercontent.com/element-hq/element-web/31977dbf946265b35621ad27650c6c6f08ff2e21/apps/web/src/serviceworker/index.ts): "url.href = url.href.replace(/\/media\/v3\/(.*)\//, "/client/v1/media/$1/");"
- **Sentry** (`partial`, https://raw.githubusercontent.com/getsentry/sentry/78bb0a0ab110f4999d5d1e5d49be7740dd556205/static/app/api.tsx): "this.baseUrl = options.baseUrl ?? '/api/0';"
- **Linode (Akamai Cloud)** (`same`, https://raw.githubusercontent.com/linode/manager/6503a875f7a4e82dd8335d4ce16fcbd8ae492e21/packages/manager/.env.example): "REACT_APP_API_ROOT='https://api.linode.com/v4'"
- **Okta** (`partial`, https://raw.githubusercontent.com/okta/okta-signin-widget/9226d6765f5bd4b10b9242860efacdcb314da4ce/src/v1/controllers/RegistrationController.js): "/api/v1/registration/form"
- Every other service: `none`; see each `web_ui_note`.

## Where a function cannot be separated by path

Each service's `not_separable` field gives the detail. In short:
- **Same path, method only**: Twilio, Heroku, CircleCI, Sentry, Basecamp, Databricks Files (PUT vs GET), Typeform
  responses (GET vs DELETE): a host-only (SNI) policy cannot split read from write.
- **One GraphQL endpoint**: New Relic NerdGraph (NRQL reads and admin mutations) and Shopify Admin GraphQL (bulk export
  and staged uploads), so those children stay unverified or are split by body only.
- **One encrypted stream**: Signal send vs receive (one chat websocket), RustDesk file transfer vs screen (same relay
  stream), ZeroTier join vs tunnel data (udp/9993), Jitsi recording (an XMPP command on the signalling connection),
  Matrix E2EE message type, Bitwarden item type (client-side encrypted).
- **Shared with the web site**: VirusTotal API and site share `www.virustotal.com`; only the `/api/v3` prefix separates them.
- **Run-time transfer targets**: Signal attachment upload, VirusTotal `upload_url`, Bitwarden Send file upload (Azure blob),
  Snowflake stage transfer (cloud storage) and Basecamp downloads go to a URL the server returns; the documented call is
  the rule, the follow-up host is not.

## Findings for Engine (ENGINE-FIELD, Go only)

1. **API hosts outside the parent's pack domains** need adding, or a host-to-parent override, before these children can match:
   - `3.basecampapi.com` (all Basecamp API children) and `launchpad.37signals.com` (OAuth; shared by other 37signals products);
   - `{shop}.myshopify.com` (Shopify Admin, Storefront and OAuth);
   - `*.linodeobjects.com` (Linode Object Storage data plane);
   - `admin.splunk.com` (Splunk Cloud Admin Config Service);
   - `form.typeform.eu` (Typeform EU respondents);
   - `vector.im` / `scalar.vector.im` (Element identity and integrations), `8x8.vc` and `alpha.jitsi.net` (Jitsi known
     domains), `bitwarden-gov.com` (Bitwarden Gov region) and `ddog-gov.com` (Datadog Gov site): leads only, not used as
     signals.
2. **Shared cloud storage must not name the parent**: Snowflake stage transfers (`storage.googleapis.com`, S3, Azure blob),
   Bitwarden Send blobs and DigitalOcean Spaces (`digitaloceanspaces.com`) run on storage hosts; the pack rule that shared
   cloud hosting names no application stands.
3. **Tenant hosts**: Okta (`{yourOktaDomain}`), Auth0 (`{TENANT}.auth0.com`), Databricks workspaces, Snowflake accounts and
   Splunk Cloud stacks are per-customer subdomains of the pack suffixes; custom domains are not attributable.
4. **Non-HTTP and upgrade transports**: RustDesk tcp/udp 21116, tcp/21117 and websocket 21118/21119 (no TLS, so no SNI);
   ZeroTier udp/9993; Tailscale control `/ts2021` and DERP `/derp` (HTTP Upgrade, not WebSocket) and STUN udp/3478;
   Signal and Jitsi WebSockets and Bitwarden SignalR `/hub`. A rule must look at the transport or the upgrade request.

## Unknowns

Every unverified child (7) is unknown; the ids are in the table. Within verified rows, a `null` field means
the cited source does not state it (for example `host_sni` for Jitsi WebSocket and BOSH, whose repository config is a
template; `content_type` where the SDK sends a FormData body without naming it; `direction` for OAuth and webhooks).

## Blocked sources

Vendor documentation pages refused by this session's network policy (curl 000) or not followed (a 301 for ngrok, a 403
for GitHub's HTML page of `basecamp/bc3-api`, whose raw files were read). They are recorded here, not in
`../blocked-urls.md`, to keep this pull request to the wave files (PRO-575). None was paraphrased.

| Service | URL |
|---|---|
| Signal | https://signal.org/docs/ |
| Matrix / Element | https://spec.matrix.org/latest/client-server-api/ |
| Jitsi Meet | https://jitsi.github.io/handbook/docs/dev-guide/dev-guide-iframe |
| Twilio | https://www.twilio.com/docs/messaging/api/message-resource |
| RingCentral | https://developers.ringcentral.com/api-reference |
| Basecamp | https://github.com/basecamp/bc3-api |
| CircleCI | https://circleci.com/docs/api/v2/ |
| Heroku | https://devcenter.heroku.com/articles/platform-api-reference |
| Sentry | https://docs.sentry.io/api/ |
| New Relic | https://docs.newrelic.com/docs/apis/nerdgraph/get-started/introduction-new-relic-nerdgraph/ |
| DigitalOcean | https://docs.digitalocean.com/reference/api/ |
| Linode (Akamai Cloud) | https://techdocs.akamai.com/linode-api/reference/api |
| Databricks | https://docs.databricks.com/api/workspace/introduction |
| Snowflake | https://docs.snowflake.com/en/user-guide/data-load-snowpipe-rest-apis |
| Splunk Cloud Platform | https://docs.splunk.com/Documentation/SplunkCloud/latest/Data/UsetheHTTPEventCollector |
| Splunk Cloud Platform | https://help.splunk.com/en/splunk-cloud-platform/get-started/get-data-in/ |
| Stripe | https://docs.stripe.com/api |
| PayPal | https://developer.paypal.com/api/rest/ |
| Xero | https://developer.xero.com/documentation/api/accounting/invoices |
| Expensify | https://integrations.expensify.com/Integration-Server/doc/ |
| Typeform | https://www.typeform.com/developers/create/reference/create-form/ |
| Shopify | https://shopify.dev/docs/api/admin-graphql |
| ngrok | https://ngrok.com/docs/api/ |
| ZeroTier | https://docs.zerotier.com/api/ |
| VirusTotal | https://docs.virustotal.com/reference/overview |
| Okta | https://developer.okta.com/docs/reference/ |
| Auth0 | https://auth0.com/docs/api |
