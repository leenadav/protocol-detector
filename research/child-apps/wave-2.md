# Child apps, wave 2: 30 more services already in the pack, with web-UI evidence (PRO-550)

Continues wave 0 (`wave-0.md`, PRO-495, PR #161) and wave 1 (`wave-1.md`, PRO-524, PR #176) for Engine PRO-492. Data:
`wave-2.json` (schema `child-apps/v1`, `wave: 2`). Parent ids are those of `go/internal/content/pack.json` at `5cb35d2`
(release `2026.11.9`, identical on `origin/main`); every parent was checked against the pack. Sources accessed 2026-11-27.

## Scope and overlap

- **30 new services**, none in wave 0 or 1, chosen in the task's order: its named examples that are in the pack and not yet
  covered (Zoho Mail, Fastmail, Hugging Face, Replit, npm, PyPI, Docker Hub, Zendesk, HubSpot, DocuSign, Adobe Acrobat
  online, Smartsheet, Airtable, ClickUp), then AI assistants (Power BI, xAI Grok, GitHub Copilot, Cursor, Google AI
  Studio, NotebookLM), dev platforms (Netlify, Vercel, Stack Overflow), file sharing and e-signature (Egnyte, MediaFire,
  Sync.com, transfer.sh, Dropbox Sign), mail and notes (Evernote) and messaging (Facebook Messenger).
- **PR #166** (`research/catalog-pipeline/enterprise-300.md`, PRO-491): none of its 65 rows is in the pack, so none can be a
  parent; **Azure DevOps** is row 48 there (`azure-devops`, not in the pack) and is linked, not repeated.
- **Left out**: the task's other examples (Dropbox, Box, WeTransfer, iCloud Drive, MEGA, Claude, Gemini, Copilot, Discord,
  Telegram Web, WhatsApp Web, LinkedIn, X, Facebook, Instagram) are wave 0; `openai-platform` children are in wave 0.

## Method

Same as waves 0 and 1: official vendor pages only, one citation URL per verified child (more in `citation_also`),
nothing from nDPI, Wireshark, Suricata, Snort or OpenAppID, no traffic capture and no calls to the APIs. **Unverified children
keep every signal field `null`.** Where a documentation site was blocked by this session's network policy, rows cite the
vendor's own OpenAPI spec, SDK or sample repository on `raw.githubusercontent.com`, or its official package on
`registry.npmjs.org` / `pypi.org` (PRO-501 rule); packages and repositories not published by the vendor were rejected
(Zoho Mail, ClickUp, Stack Exchange and Airtable had only third-party ones). Each note quotes the file line.

**New: `web_ui_evidence`.** Wave 1 found that vendors document API paths, not web-UI paths. Each service now says whether
the browser web app uses the documented API host/paths, **only where an official source says so**: `same`, `partial`
(web app on the API host, paths not stated), `different`, or `none`. A host overlap that only shows when two pages are put
side by side (DocuSign's sandbox console URL, Docker Hub's web and API host) is described in `web_ui_note` and is not counted.
`../tools/check_child_apps.py` now requires the field from wave 2 and checks its shape and the count below.

## Result

30 services, 150 proposed children, **111 verified with an official citation** (96 distinct pages); 39 unverified.

22 separate partly by method and path, 2 by host only, 6 are blocked (no readable primary source for any function split). 3 services with web-UI evidence.

Counts asked for by PRO-550: **30 services**; **111 children with citations**; **not separable: 2** (Fastmail, Evernote: the function is
only in the request body); **3 services with web-UI evidence** (Microsoft Power BI (partial), GitHub Copilot (partial), Cursor (different)); **6 blocked**: Zoho Mail, Replit, ClickUp, MediaFire, Sync.com, Stack Overflow.

| # | Service | Parent | Verified children | Unverified children | Verified | Separability | Web UI |
|---|---|---|---|---|---|---|---|
| 1 | Zoho Mail | `zoho` | - | `zoho-mail-base`, `zoho-mail-sending`, `zoho-mail-attachment-uploading`, `zoho-mail-attachment-downloading` | 0/4 | blocked | none |
| 2 | Fastmail | `fastmail` | `fastmail-base`, `fastmail-jmap-calling`, `fastmail-sending`, `fastmail-uploading`, `fastmail-downloading` | - | 5/5 | host-only | none |
| 3 | DocuSign | `docusign` | `docusign-esign-base`, `docusign-envelope-sending`, `docusign-draft-sending`, `docusign-document-uploading`, `docusign-document-downloading`, `docusign-signing-view` | - | 6/6 | partial | none |
| 4 | Dropbox Sign | `dropbox-sign` | `dropbox-sign-api-base`, `dropbox-sign-request-sending`, `dropbox-sign-file-downloading`, `dropbox-sign-template-uploading`, `dropbox-sign-fax-sending`, `dropbox-sign-embedded-signing` | - | 6/6 | partial | none |
| 5 | Adobe Acrobat online / Document Cloud | `adobe-cloud` | `adobe-cloud-pdfservices-base`, `adobe-cloud-pdfservices-uploading`, `adobe-cloud-pdfservices-converting`, `adobe-cloud-pdfservices-downloading`, `adobe-cloud-dc-api` | `adobe-cloud-acrobat-web` | 5/6 | partial | none |
| 6 | Evernote | `evernote` | `evernote-userstore`, `evernote-notestore`, `evernote-oauth` | `evernote-base` | 3/4 | host-only | none |
| 7 | Replit | `replit` | - | `replit-base`, `replit-uploading`, `replit-prompting`, `replit-deploying` | 0/4 | blocked | none |
| 8 | npm | `npm` | `npm-registry-base`, `npm-publishing`, `npm-downloading`, `npm-reading`, `npm-unpublishing` | - | 5/5 | partial | none |
| 9 | PyPI | `pypi` | `pypi-uploading`, `pypi-reading`, `pypi-index-browsing`, `pypi-downloading` | - | 4/4 | partial | none |
| 10 | Docker Hub | `docker-hub` | `docker-hub-base`, `docker-hub-pushing`, `docker-hub-pulling`, `docker-hub-registry-auth`, `docker-hub-api-login`, `docker-hub-api-repositories` | - | 6/6 | partial | none |
| 11 | Netlify | `netlify` | `netlify-api-deploying`, `netlify-api-uploading`, `netlify-api-building`, `netlify-api-reading` | `netlify-base` | 4/5 | partial | none |
| 12 | Vercel | `vercel` | `vercel-api-deploying`, `vercel-api-uploading`, `vercel-api-downloading`, `vercel-api-caching` | `vercel-base` | 4/5 | partial | none |
| 13 | Hugging Face | `hugging-face` | `hugging-face-base`, `hugging-face-commit-uploading`, `hugging-face-xet-cas`, `hugging-face-xet-uploading`, `hugging-face-downloading`, `hugging-face-inference-prompting` | - | 6/6 | partial | none |
| 14 | Microsoft Power BI | `power-bi` | `power-bi-base`, `power-bi-api-importing`, `power-bi-api-large-import-location`, `power-bi-api-exporting`, `power-bi-api-pbix-downloading` | - | 5/5 | partial | partial |
| 15 | xAI Grok | `xai-grok` | `xai-grok-base`, `xai-grok-api-prompting`, `xai-grok-api-uploading`, `xai-grok-api-downloading`, `xai-grok-api-realtime-voice`, `xai-grok-build-cli` | - | 6/6 | partial | none |
| 16 | GitHub Copilot | `github-copilot` | `github-copilot-base`, `github-copilot-personal-plan`, `github-copilot-web-chat`, `github-copilot-cloud-sessions`, `github-copilot-chat-attachments` | - | 5/5 | partial | partial |
| 17 | Cursor | `cursor` | `cursor-base`, `cursor-agent`, `cursor-tab`, `cursor-web-agents`, `cursor-api-agent-prompting`, `cursor-api-artifact-downloading` | - | 6/6 | partial | different |
| 18 | Google AI Studio (Gemini API) | `google-ai-studio` | `google-ai-studio-base`, `google-ai-studio-build-mode`, `google-ai-studio-published-apps`, `google-ai-studio-api-generating`, `google-ai-studio-api-interactions`, `google-ai-studio-api-file-search-uploading` | - | 6/6 | partial | none |
| 19 | Zendesk | `zendesk` | `zendesk-base`, `zendesk-api-uploading`, `zendesk-api-ticket-creating` | `zendesk-attachment-downloading` | 3/4 | partial | none |
| 20 | HubSpot | `hubspot` | `hubspot-api-file-uploading`, `hubspot-api-file-importing`, `hubspot-api-file-signed-url`, `hubspot-api-crm-importing`, `hubspot-api-crm-exporting` | `hubspot-webapp` | 5/6 | partial | none |
| 21 | Smartsheet | `smartsheet` | `smartsheet-api-attachment-uploading`, `smartsheet-api-sheet-importing`, `smartsheet-api-sheet-exporting` | `smartsheet-base`, `smartsheet-attachment-downloading` | 3/5 | partial | none |
| 22 | Airtable | `airtable` | `airtable-api-record-creating`, `airtable-api-record-updating`, `airtable-api-record-listing` | `airtable-base`, `airtable-attachment-uploading` | 3/5 | partial | none |
| 23 | ClickUp | `clickup` | - | `clickup-base`, `clickup-api-attachment-uploading`, `clickup-api-task-creating`, `clickup-api-comment-posting` | 0/4 | blocked | none |
| 24 | Google NotebookLM | `google-notebooklm` | `google-notebooklm-base`, `google-notebooklm-api-notebook-creating`, `google-notebooklm-api-source-adding`, `google-notebooklm-api-audio-overview-generating` | `google-notebooklm-source-uploading`, `google-notebooklm-chatting` | 4/6 | partial | none |
| 25 | Egnyte | `egnyte` | `egnyte-api-uploading`, `egnyte-api-uploading-chunked`, `egnyte-api-downloading`, `egnyte-api-sharing`, `egnyte-api-deleting` | `egnyte-base` | 5/6 | partial | none |
| 26 | MediaFire | `mediafire` | - | `mediafire-base`, `mediafire-uploading`, `mediafire-downloading` | 0/3 | blocked | none |
| 27 | Sync.com | `sync-com` | - | `sync-com-base`, `sync-com-uploading`, `sync-com-downloading`, `sync-com-sharing` | 0/4 | blocked | none |
| 28 | transfer.sh | `transfer-sh` | `transfer-sh-uploading`, `transfer-sh-uploading-form`, `transfer-sh-downloading`, `transfer-sh-deleting`, `transfer-sh-scanning` | - | 5/5 | partial | none |
| 29 | Facebook Messenger | `facebook-messenger` | `facebook-messenger-api-sending` | `facebook-messenger-base`, `facebook-messenger-web-sending`, `facebook-messenger-web-uploading` | 1/4 | partial | none |
| 30 | Stack Overflow | `stack-overflow` | - | `stack-overflow-base`, `stack-overflow-api-reading`, `stack-overflow-api-posting`, `stack-overflow-web-posting` | 0/4 | blocked | none |

## Web-UI evidence

- **Microsoft Power BI** (`partial`, https://learn.microsoft.com/en-us/power-bi/admin/power-bi-allow-list-urls): "The Power BI service requires internet connectivity. The endpoints listed in the following tables should be reachable for customers who use the Power BI service. ... Required: Backend APIs | api.powerbi.com | TCP 443 ... Required: Portal | *.powerbi.com | TCP 443"
- **GitHub Copilot** (`partial`, https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-for-enterprise/manage-access/manage-network-access): "Configuring Copilot subscription-based network routing will affect the following Copilot features: [...] Copilot Chat on GitHub [...] Copilot subscription-based network routing is enabled for all users. Requests use a plan-specific endpoint."
- **Cursor** (`different`, https://cursor.com/docs/enterprise/network-configuration): "The web app at `cursor.com` streams agent conversations and code review data as long-lived, compressed binary responses. [...] In the browser's developer tools, the Network tab shows a `StreamConversation` request under `/api/connect-proxy/` with no status code and nothing transferred."
- Every other service: `none` (no official page read here says what its browser app calls); see each `web_ui_note`.

## Where a function cannot be separated

- **Fastmail**: Fastmail's API is JMAP: every mail operation (query, read, create a draft, send via EmailSubmission/set) is a method name inside one JSON body POSTed to the session's apiUrl (RFC 8620 section 3.1), so send vs read is split only by inspecting the JSON body, not by path or method. Blob upload and download have their own session URLs (RFC 8620 sections 6.1 and 6.2), but Fastmail's concrete uploadUrl/downloadUrl paths come from the session object at runtime and were not on any reachable Fastmail page.
- **Evernote**: The Evernote Cloud API is Thrift over HTTP: every NoteStore call (createNote, updateNote, getNote, getResourceData) is a binary Thrift message POSTed with Content-Type application/x-thrift to the one noteStoreUrl of the user's shard, so upload vs read is in the binary body, not the path or method. Only UserStore (/edam/user) and NoteStore (/shard/{shardId}/edam/note) differ by path.
- **Run-time upload targets**: Adobe PDF Services (`POST /assets` returns a pre-signed upload URL), Power BI
  (`createTemporaryUploadLocation` returns an Azure Blob URL), Cursor artifacts and HubSpot signed URLs: the documented call
  is the rule; the follow-up host is not.

## Findings for Engine (ENGINE-FIELD, Go only)

1. **API hosts outside the parent's pack domains**: `api.hubapi.com` (HubSpot; pack has `hubspot.com` only),
   `graph.facebook.com` (Messenger Send API; pack maps it to `facebook`), `discoveryengine.googleapis.com` (NotebookLM
   Enterprise) and `generativelanguage.googleapis.com` (AI Studio; `google-base`), `api.hellosign.com`/`sign.dropbox.com`
   (Dropbox Sign), `smartsheet.eu`, `smartsheet.au`, `smartsheetgov.com`, `*.ai.studio`, `cas-server.xethub.hf.co`: these
   children need the host added or a host-to-parent override before they can match.
2. **Body-level functions**: Fastmail (JMAP) and Evernote (Thrift) put every operation in one POST body; Hugging Face
   commits are NDJSON bodies. A path rule sees only the endpoint.
3. **Cursor web app** uses `cursor.com/api/connect-proxy/` (vendor-stated), not the desktop `api*.cursor.sh` hosts or
   `api.cursor.com`: a rule written from the API rows will not see browser traffic.
4. **transfer.sh** is self-hostable; the `transfer.sh` host is only the README's example, so its path rules hold only there.

## Blocked sources

Rows 72 to 92 of `../blocked-urls.md` (21 vendors); the hosts are batch R4 in `../allowlist-requests.md`.

