# Child apps, wave 6: 30 more services already in the pack (PRO-588)

Continues wave 0 (`wave-0.md`, PRO-495), wave 1 (PRO-524, PR #176), wave 2 (PRO-550, PR #180), wave 3 (PRO-569,
PR #183), wave 4 (PRO-575, PR #185) and wave 5 (PRO-579, PR #189) for Engine PRO-492. Data: `wave-6.json` (schema
`child-apps/v1`, `wave: 6`, validator `../tools/check_child_apps.py`). Parent ids are those of
`go/internal/content/pack.json` at `59fb9fc` (release `2026.11.9`, unchanged on `origin/main` at `cc1566d`); every
parent was checked against the pack. Sources accessed 2026-11-27. This branch is cut from `origin/main`, not stacked on
the wave 1 to 5 branches; their files were read with `git show` only to exclude their parents.

## Scope and overlap

- **Not covered before**: waves 0 to 5 (wave 0 on `main`; waves 1 to 5 on `origin/claude/app-research-PRO-524-child-apps-wave1`,
  `...-PRO-550-child-apps-wave2`, `...-PRO-569-child-apps-wave3`, `...-PRO-575-child-apps-wave4` and
  `...-PRO-579-child-apps-wave5-v2`) hold 178 parents. None of the 30 below is among them; 366 of the 544 pack
  applications remained outside waves 0 to 5.
- **PR #166**: wave 5 found none of its enterprise-300 service ids in the pack, so parents come from the task's SWG
  policy categories.
- **Categories asked for and what the pack still had**: the e-signature, ITSM and ticketing, whiteboard, backup and
  hosting-console parents in the pack (for example `docusign`, `servicenow`, `zendesk`, `miro`, `backblaze`,
  `netlify`, `vercel`, `heroku`) were already covered by waves 0 to 5. The HR and payroll parents left (`adp`,
  `bamboohr`, `gusto`, `workday`) and the file-hosting ones (`docsend`, `4shared`, `sendspace`) have no vendor-owned
  source reachable from this session (no public vendor repository found by `git ls-remote`, doc sites curl 000), so
  they are not in this wave.
- **30 services** in category order: CRM, marketing and customer-engagement SaaS (Braze, Twilio Segment, Amplitude,
  Mixpanel, OneSignal, Hotjar, Adjust, Branch, AppsFlyer, Google Analytics); video conferencing and calling (Dialpad,
  8x8 JaaS); email security and mail (Exchange Online Protection, Tuta); endpoint and Microsoft platform services
  (Defender for Endpoint, Windows Update, Windows diagnostic data, Mozilla Firefox services); network security, CDN,
  DNS and hosting consoles (Cloudflare WARP, Cloudflare 1.1.1.1, Zscaler, Sophos Central, WordPress.com, GoDaddy);
  developer and learning tools (JetBrains, SonarCloud, Google Colab, Gradle, Canvas LMS, Tabnine).
- **Spares, not needed**: `google-ads`, `digicert`, `netskope`, `calendly`.

## Method

Same as wave 5. Official vendor sources only, one citation per verified child (more in `citation_also`). Nothing is taken
from nDPI, Wireshark, Suricata, Snort or OpenAppID. No traffic was captured and no vendor API was called; only
documentation, specification and source files were fetched. **Unverified children keep every signal field `null`.**
Vendor documentation sites were refused by this session's network policy (curl 000: braze.com, segment.com,
developer.mixpanel.com, documentation.onesignal.com, help.hotjar.com, dev.adjust.com, help.branch.io, dev.appsflyer.com,
developers.google.com, developers.dialpad.com, developer.8x8.com, developer.sophos.com, developer.wordpress.com,
developer.godaddy.com, plugins.jetbrains.com, docs.sonarsource.com, docs.gradle.org, canvas.instructure.com,
colab.research.google.com, tuta.com), so most verified rows cite the vendor's own OpenAPI spec, SDK, CLI or
documentation repository on `raw.githubusercontent.com`, pinned to a full commit SHA, in the vendor's own GitHub
organisation (58 repositories, named per row in `citation_page_date`). The four Microsoft services cite Microsoft Learn
pages (`learn.microsoft.com`, 36 citations) directly; the Cloudflare rows cite `cloudflare/cloudflare-docs`, the source
of developers.cloudflare.com.

Checks before submission:
- **Quote check.** The first single-quoted string in each verified child's note was fetched again from its
  `citation_url` (cache cleared, fresh download) and found verbatim: 183 of 183. Microsoft Learn pages are compared
  after HTML unescaping.
- **Host check.** Every literal `host_sni` name of a verified row was searched in its cited files: 239 of 239 found.
  38 further entries are patterns or templates (`*.` or `{...}`), each explained in its row: for example Mixpanel
  `{region}.mixpanel.com` from the spec servers entry, Zscaler `{vanity}.zslogin{cloud}.net`, GoDaddy Commerce
  `api.{sub-domain}.com`, Braze `sdk.*.braze.com`.
- **Hosts outside the pack domains** are named in each row's notes (for example `js.appboycdn.com`,
  `api.segmentapis.com`, `cdn.mxpnl.com`, `analyticsdata.googleapis.com`, `app.link`, `api.zsapi.net`,
  `binaries.sonarsource.com`, `scans.gradle.com`, `sso.canvaslms.com`, Cloudflare `cloudflareok.com`): a rule on the
  parent's pack domains does not see them.
- **Ownership.** Dialpad's SDK states copyright Dialpad, Inc.; Tabnine's `codota/TabNine` LICENSE states copyright
  Tabnine and `tabnine-vscode` names Tabnine as author; the two Jitsi repositories were accepted for 8x8 only because
  they state the 8x8.vc JaaS hosts (the jitsi-meet README credits the Jitsi team at 8x8).
- **Secret scan.** gitleaks 8.30.1 (`git --ignore-gitleaks-allow --redact --log-opts=origin/main..HEAD .`) on this
  branch's commits: no leaks. No key, token or credential-shaped text is quoted; such values are described in words.

Rejected or unreadable sources: `godaddy/gdapi-python` (a generic GDAPI-style client whose examples use localhost, not
api.godaddy.com; `godaddy/cli` OpenAPI specs cited instead); `Automattic/wpcom.js` (archived, moved into
`wp-calypso`, cited there); `jitsi/lib-jitsi-meet` (no 8x8 copyright or 8x8.vc host); `AppsFlyerSDK/appsflyer-android-sdk`
(no source, binary releases only); `googleapis/python-analytics-data` (archived, moved to `google-cloud-python`);
`endpoints.office.com` (reachable, but repeats the Learn table without its notes; not cited); `help.zscaler.com` (page
without article content); `braze-inc/braze-docs`, `segmentio/segment-docs`, `amplitude/amplitude-docs` and three
Hotjar repository names (git asked for credentials). No third-party SDK or package was used.

## Result

30 services, 187 proposed children, **183 verified with an official citation** (219 distinct pages); 4 unverified.

Counts asked for by PRO-588: **30 services**; **187 children**; **183 cited** (125 primary pages, 120 rows with
`citation_also`); **4 unverified** (`braze-api-messaging`, `hotjar-client-identifying`, `hotjar-client-tracking`,
`tabnine-client-completing`: no vendor file shows their network path); **219 pages**. Web-UI evidence: two services
(Tuta `same`: `buildSrc/DomainConfigs.js` gives the app.tuta.com web client the apiUrl `https://app.tuta.com`;
WordPress.com `partial`: the wp-calypso `wpcom-proxy-request` Readme puts the browser on public-api.wordpress.com);
none for the other 28.

25 services separate partly by method, path or host; none is blocked. Five are `host-only`: Hotjar (the only vendor
file names the script host and a `*.hotjar.com` pattern, no paths) and the four Microsoft services, because Microsoft
says Defender for Endpoint connections, Windows Update metadata, the Delivery Optimization service and Windows
diagnostic data use certificate pinning, so a decrypting proxy does not see their paths. Exchange Online Protection is
SMTP on TCP 25 to `*.mail.protection.outlook.com` and `*.mx.microsoft`; inbound mail, Direct Send, relay and hybrid
connectors share the MX host. Signals marked `transport` (WARP WireGuard and MASQUE on UDP, 1.1.1.1 DoT on tcp/853,
Delivery Optimization peering on tcp/7680 and udp/3544) are invisible to an HTTP rule.

| # | Service | Parent | Verified children | Unverified children | Verified | Separability | Web UI |
|---|---|---|---|---|---|---|---|
| 1 | Braze | `braze` | `braze-client-downloading`, `braze-client-importing`, `braze-client-tracking`, `braze-client-registering`, `braze-client-unregistering` | `braze-api-messaging` | 5/6 | partial | none |
| 2 | Twilio Segment | `segment` | `segment-api-tracking`, `segment-client-tracking`, `segment-client-configuring`, `segment-client-downloading`, `segment-api-deleting`, `segment-api-managing` | - | 6/6 | partial | none |
| 3 | Amplitude | `amplitude` | `amplitude-api-tracking`, `amplitude-api-importing`, `amplitude-client-configuring`, `amplitude-client-recording`, `amplitude-client-flagging`, `amplitude-client-downloading` | - | 6/6 | partial | none |
| 4 | Mixpanel | `mixpanel` | `mixpanel-api-tracking`, `mixpanel-api-importing`, `mixpanel-api-profiling`, `mixpanel-api-exporting`, `mixpanel-api-deleting`, `mixpanel-client-tracking`, `mixpanel-client-downloading` | - | 7/7 | partial | none |
| 5 | OneSignal | `onesignal` | `onesignal-api-sending`, `onesignal-api-identifying`, `onesignal-api-exporting`, `onesignal-api-administering`, `onesignal-client-registering`, `onesignal-client-configuring`, `onesignal-client-messaging` | - | 7/7 | partial | none |
| 6 | Hotjar | `hotjar` | `hotjar-client-downloading`, `hotjar-client-framing` | `hotjar-client-identifying`, `hotjar-client-tracking` | 2/4 | host-only | none |
| 7 | Adjust | `adjust` | `adjust-client-session-tracking`, `adjust-client-event-tracking`, `adjust-client-attributing`, `adjust-client-consent-reporting`, `adjust-client-forgetting`, `adjust-client-subscription-reporting`, `adjust-client-purchase-verifying` | - | 7/7 | partial | none |
| 8 | Branch | `branch-io` | `branch-io-client-session-opening`, `branch-io-client-event-tracking`, `branch-io-client-link-creating`, `branch-io-client-qr-generating`, `branch-io-client-skiplist-downloading`, `branch-io-client-journey-tracking` | - | 6/6 | partial | none |
| 9 | AppsFlyer | `appsflyer` | `appsflyer-client-first-open-reporting`, `appsflyer-client-session-reporting`, `appsflyer-client-event-reporting`, `appsflyer-client-sandbox-testing`, `appsflyer-client-click-recording`, `appsflyer-client-smart-script-loading` | - | 6/6 | partial | none |
| 10 | Google Analytics | `google-analytics` | `google-analytics-api-event-sending`, `google-analytics-api-event-validating`, `google-analytics-client-tag-loading`, `google-analytics-client-library-loading`, `google-analytics-api-reporting`, `google-analytics-api-audience-exporting` | - | 6/6 | partial | none |
| 11 | Dialpad | `dialpad` | `dialpad-api-call-controlling`, `dialpad-api-sms-sending`, `dialpad-api-transcript-retrieving`, `dialpad-api-stats-exporting`, `dialpad-api-provisioning`, `dialpad-api-event-subscribing`, `dialpad-api-authorizing` | - | 7/7 | partial | none |
| 12 | 8x8 | `8x8` | `8x8-client-api-loading`, `8x8-client-config-loading`, `8x8-client-staging-testing`, `8x8-web-console-managing`, `8x8-client-token-fetching`, `8x8-client-tenant-checking` | - | 6/6 | partial | none |
| 13 | Microsoft Exchange Online Protection | `ms-exchange-online-protection` | `ms-exchange-online-protection-client-mx-receiving`, `ms-exchange-online-protection-client-dnssec-mx-receiving`, `ms-exchange-online-protection-client-direct-sending`, `ms-exchange-online-protection-client-connector-relaying`, `ms-exchange-online-protection-web-safelinks-redirecting`, `ms-exchange-online-protection-client-service-connecting` | - | 6/6 | host-only | none |
| 14 | Microsoft Defender for Endpoint | `ms-defender-endpoint` | `ms-defender-endpoint-client-core-connecting`, `ms-defender-endpoint-client-ipv6-probing`, `ms-defender-endpoint-client-commanding`, `ms-defender-endpoint-client-cyberdata-uploading`, `ms-defender-endpoint-client-sample-uploading`, `ms-defender-endpoint-client-cloud-protection-checking` | - | 6/6 | host-only | none |
| 15 | Windows Update and Microsoft software delivery | `ms-update` | `ms-update-client-metadata-scanning`, `ms-update-client-webservice-scanning`, `ms-update-client-payload-downloading`, `ms-update-client-do-coordinating`, `ms-update-client-do-peering`, `ms-update-client-traffic-shaping`, `ms-update-client-ctl-updating` | - | 7/7 | host-only | none |
| 16 | Microsoft diagnostic data endpoints | `ms-telemetry` | `ms-telemetry-client-diagnostic-uploading`, `ms-telemetry-client-processor-uploading`, `ms-telemetry-client-error-reporting`, `ms-telemetry-client-crash-analyzing`, `ms-telemetry-client-defender-core-uploading`, `ms-telemetry-client-settings-retrieving` | - | 6/6 | host-only | none |
| 17 | Tuta (Tutanota) encrypted mail | `tuta-mail` | `tuta-mail-client-authenticating`, `tuta-mail-client-sending`, `tuta-mail-client-event-streaming`, `tuta-mail-client-blob-transferring`, `tuta-mail-client-importing`, `tuta-mail-client-push-receiving`, `tuta-mail-client-updating` | - | 7/7 | partial | same |
| 18 | Mozilla Firefox services and updates | `mozilla` | `mozilla-client-updating`, `mozilla-client-syncing`, `mozilla-client-account-authenticating`, `mozilla-client-settings-syncing`, `mozilla-client-telemetry-uploading`, `mozilla-client-addons-browsing`, `mozilla-client-push-connecting` | - | 7/7 | partial | none |
| 19 | Cloudflare WARP (Cloudflare One Client) | `cloudflare-warp` | `cloudflare-warp-client-orchestrating`, `cloudflare-warp-client-wireguard-tunneling`, `cloudflare-warp-client-masque-tunneling`, `cloudflare-warp-client-captive-checking`, `cloudflare-warp-client-connectivity-checking`, `cloudflare-warp-client-downloading` | - | 6/6 | partial | none |
| 20 | Cloudflare DNS (1.1.1.1 resolver) | `cloudflare-dns` | `cloudflare-dns-api-json-resolving`, `cloudflare-dns-client-wireformat-resolving`, `cloudflare-dns-client-tls-resolving`, `cloudflare-dns-client-family-filtering`, `cloudflare-dns-client-family-tls-filtering`, `cloudflare-dns-client-oblivious-resolving` | - | 6/6 | partial | none |
| 21 | Zscaler (ZIA, ZPA, ZDX, Client Connector admin APIs) | `zscaler` | `zscaler-api-authenticating`, `zscaler-api-oneapi-calling`, `zscaler-api-zia-configuring`, `zscaler-api-zpa-configuring`, `zscaler-api-zdx-monitoring`, `zscaler-api-zcc-managing`, `zscaler-api-zpa-scim-provisioning` | - | 7/7 | partial | none |
| 22 | Sophos Central | `sophos` | `sophos-api-authenticating`, `sophos-api-identifying`, `sophos-api-tenant-listing`, `sophos-api-siem-exporting`, `sophos-api-endpoint-inventorying`, `sophos-api-alert-retrieving`, `sophos-api-live-discover-querying` | - | 7/7 | partial | none |
| 23 | WordPress.com and Jetpack | `wordpress-com` | `wordpress-com-api-requesting`, `wordpress-com-api-media-uploading`, `wordpress-com-api-stats-reading`, `wordpress-com-api-dns-managing`, `wordpress-com-client-jetpack-connecting`, `wordpress-com-web-stats-tracking` | - | 6/6 | partial | partial |
| 24 | GoDaddy Developer Platform APIs | `godaddy` | `godaddy-api-authenticating`, `godaddy-api-domain-registering`, `godaddy-api-dns-managing`, `godaddy-api-hosting-deploying`, `godaddy-api-email-provisioning`, `godaddy-api-checkout-shopping`, `godaddy-api-commerce-managing` | - | 7/7 | partial | none |
| 25 | JetBrains | `jetbrains` | `jetbrains-api-publishing`, `jetbrains-api-downloading`, `jetbrains-client-browsing`, `jetbrains-client-updating`, `jetbrains-client-patching`, `jetbrains-client-fetching` | - | 6/6 | partial | none |
| 26 | SonarCloud (SonarQube Cloud) | `sonarcloud` | `sonarcloud-api-submitting`, `sonarcloud-client-bootstrapping`, `sonarcloud-api-gating`, `sonarcloud-api-triaging`, `sonarcloud-api-measuring`, `sonarcloud-client-downloading` | - | 6/6 | partial | none |
| 27 | Google Colab | `google-colab` | `google-colab-web-opening`, `google-colab-web-bridging`, `google-colab-client-monitoring`, `google-colab-client-reporting`, `google-colab-api-generating` | - | 5/5 | partial | none |
| 28 | Gradle | `gradle` | `gradle-client-downloading`, `gradle-client-checking`, `gradle-client-validating`, `gradle-client-resolving`, `gradle-client-publishing`, `gradle-api-tokening` | - | 6/6 | partial | none |
| 29 | Instructure Canvas | `canvas-lms` | `canvas-lms-api-querying`, `canvas-lms-api-uploading`, `canvas-lms-api-graphing`, `canvas-lms-api-authorizing`, `canvas-lms-web-launching`, `canvas-lms-api-importing` | - | 6/6 | partial | none |
| 30 | Tabnine | `tabnine` | `tabnine-client-updating`, `tabnine-client-downloading`, `tabnine-api-reviewing`, `tabnine-web-managing`, `tabnine-client-updating-enterprise` | `tabnine-client-completing` | 5/6 | partial | none |
