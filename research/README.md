# Application research lane: method and format

Owner: application-research lane (branch `claude/app-research`). This directory holds research only:
no product code, tests, fixtures or workflows change here. Anything that should change the engine
or its content pack is written as a **recommendation** (section 8 of each spec) for Hermes to pass to
the Engine lane, which implements it in Python and Go together.

## Product context the research is judged against

- The detector will be embedded in the Culvert secure web gateway. The first product phase is
  **visibility only**: identify and log, never block (working plan on `claude/culvert-integration-prep`,
  `docs/integration/PROTODETECT-CULVERT-WORKING-PLAN.md`, decision 3, 2026-11-17).
- In that phase only **TLS, HTTP/1, SSH and SMTP** are identified with evidence; every other family is
  named without evidence and presented as unvalidated. UDP families (QUIC, DTLS, ...) are **not on the
  observed path** in this phase (same plan, decision 4, 2026-11-18). A UDP observation in a spec is
  therefore recorded for later phases, never counted toward a candidate's current confidence.
- Applications are named by the content pack's server-name catalog (`go/internal/content/pack.json`
  on `claude/go-migration`, release `2026.11.2`: 431 host-named applications, 684 suffixes). The
  contract is PROTOCOLS.md, "Built-in server-name application catalog (v0.65)": label-boundary
  longest-suffix matching on TLS SNI, QUIC SNI or HTTP Host; never on an ECH outer ClientHello;
  shared CDNs and cloud hosting name no application; the name is a client assertion, not
  authenticated identity.
- Each spec therefore asks two questions: **is the current catalog entry supported by a primary
  source**, and **what more could this detector observe** (ports, ALPN, structural bytes) without
  decrypting anything.

## Source policy

1. **Primary sources only**: RFCs and IETF drafts, IANA registries, the vendor's official protocol
   or network documentation, and official published endpoint lists (for example the Microsoft 365
   endpoint web service, Google's `goog.json`, Anthropic's IP address page).
2. **Every claim cites its source**, with the URL as fetched, the access date and, where the page
   shows one, its own "updated" date. Citations point to the section, table row or line content.
3. **No copying from nDPI, Wireshark, Suricata, Snort or OpenAppID.** They may be cited only as a
   pointer to a primary source, and none is cited in this batch.
4. **Anything without a primary source is marked `UNVERIFIED`** and is never used to raise a
   confidence level. Search-engine summaries, community forums, third-party blogs and mirrors are not
   sources; when only such material was found, the spec says so.
5. **A source that could not be read is reported as `SOURCE BLOCKED`**, with the reason (for example a
   bot challenge). Its contents are not paraphrased from memory or from search snippets.
6. **Never guess.** Where a vendor declines to publish something (TeamViewer's port-5938 protocol,
   Microsoft's per-feature Copilot host names), the spec says it is unpublished.

Sources were retrieved over HTTPS through the session's egress proxy. JavaScript-rendered help
pages were rendered in a headless Chromium and read as text. Raw copies stay in the session
scratchpad and are **not committed** (licensing and size); the URLs are the record.

## Shared protocol facts (cited once, used by every spec)

| Fact | Primary source |
|---|---|
| TLS SNI is ClientHello extension `server_name` (type 0); `HostName` is the server's fully qualified DNS name, name type `host_name(0)` | RFC 6066, section 3 |
| ALPN is ClientHello extension `application_layer_protocol_negotiation` (type 16) carrying `ProtocolNameList`; the server's choice comes back in the server's extensions | RFC 7301, section 3.1 |
| ALPN identifiers `http/1.1`, `h2`, `h3` and others are registered in IANA's "TLS Application-Layer Protocol Negotiation (ALPN) Protocol IDs" | IANA registry `tls-extensiontype-values`, ALPN table (accessed 2026-11-18) |
| In TLS 1.3 the server's `EncryptedExtensions` and `Certificate` are protected by handshake traffic keys, so a passive observer sees **no server certificate names** in TLS 1.3 | RFC 8446, section 2 (handshake figure: `{}` = protected with handshake traffic secret) |
| ECH: the ClientHelloOuter carries `encrypted_client_hello` (0xfe0d); the outer SNI SHOULD be the ECHConfig `public_name`, the client-facing server's name, not the real destination | RFC 9849, sections 5 and 6.1 (published from `draft-ietf-tls-esni-25`; datatracker state "RFC Published", accessed 2026-11-18) |
| QUIC Initial packets are protected with keys derived from the client's Destination Connection ID and a published salt, so an observer can read the Initial's ClientHello (SNI, ALPN) | RFC 9001, section 5.2 |
| HTTP/1.1 target host is the `Host` header; HTTP/2 uses `:authority` | RFC 9110, section 7.2; RFC 9113, section 8.3.1 |
| A WebSocket starts as an HTTP/1.1 request with `Upgrade: websocket`; over TLS (`wss`) that request is inside the encrypted tunnel | RFC 6455, sections 1.3 and 4.1 |
| `Alt-Svc` can move a client from TCP/TLS to another protocol (for example h3 over QUIC) for the same origin | RFC 7838, section 3 |
| DNS over HTTPS carries DNS inside HTTPS, so DNS names are not visible as DNS | RFC 8484 |

Consequences applied in every spec:

- On the visibility-phase path (a CONNECT tunnel carrying TLS), the detector's application evidence
  is **SNI plus offered ALPN plus port**. URL paths, WebSocket upgrades, HTTP headers and TLS 1.3
  server certificates are **not visible** without decryption, which Culvert owns and this phase does
  not use. Vendor guidance written as URLs (`https://host/path`) is reduced to its host.
- The proxy knows the CONNECT target (`host:port`) itself. The detector's SNI is a second,
  client-asserted name; a mismatch between the two is a domain-fronting signal Culvert can compare.
  It is not authentication either way.

## Method v2 (Hermes for Lee, 2026-11-19)

Vendor documentation is the starting point, not ground truth. Primary sources still decide what a name
means. Four checks are added, and each spec records their results:

1. **Live verification** (`tools/live_verify.py`, input `L`). It is passive: DNS lookups and one TLS
   handshake per name, with no HTTP request and no account. It must run where DNS and TLS are not
   intercepted. The research cloud environment re-terminates TLS at its egress proxy and does not permit
   direct DNS, so there the tool runs only in DNS mode through an approved DoH resolver, or is run
   elsewhere. Flags: `cdn` (name fine, IPs never), `ech` (SNI may vanish), `h3` (QUIC path), `nxdomain`
   (recommend removal after a second check; RFC 8020), `no-address` (an apex or suffix with no address: normal, not
   dead; verified through a documented subdomain given as the line's PROBE) and `tls-fail` (not a removal reason).
   Runs from the Hermes server (Hermes's decision 1, 2026-11-20); this lane writes the tools and host lists.
2. **Dependency mapping** (`tools/observe_web.js`, input `O`). The app's public web client or login page is
   loaded in headless Chromium with a fresh profile, no sign-in, and only host names kept. Hosts are classed
   as app-owned, shared vendor infrastructure (sign-in, telemetry, CDN) or third party (analytics,
   consent, CAPTCHA, payment). Shared and third-party hosts are never attributed to the app; they are listed
   as its dependencies. The entry hosts must be on the allowlist (`allowlist-requests.md`). Hosts the proxy
   refuses are still recorded as attempted, so one pass is a lower bound.
3. **Attributes** (App-ID model): functions separated by name, dependencies, category, characteristics,
   consumer or business variant, and risk 1 to 5 with a reason. The proposed engine fields are in
   `protocol/app-attributes.md` (ENGINE-FIELD, post-merge, Go only).
4. **Change tracking** (`tools/recheck_sources.py`, state in `source-state.json`). It re-fetches every cited
   page (text hash) and every machine-readable feed (its own version: Microsoft 365 endpoints `latest`,
   Google `syncToken`, others by hash), and reports changes. Every spec carries a re-verify-by date 90 days
   out. Pages whose text changes on every fetch are marked noisy in `source-state.json` notes and compared by
   reading.

**Measured accuracy per app**: section 6 of every spec includes the observed app-owned hosts as positives,
the observed dependency hosts as negatives (the app must not be reported), and label-boundary and suffix
look-alikes as negatives. All are checked against `attribution_for_host` on the proposed catalog. D09
reports per application wherever the dataset's labels name an application (`d09-iscx-vpn2016.md` section 8).

**Prioritisation by real usage**: V (operator value) states its reason: enterprise prevalence, risk, and
how often the app's traffic appears as unknown in D09 or, later, in Culvert field data (placeholder in
`backlog.md`; not available yet). A public popularity ranking is used only if its licence passes LEE-1.
Cloudflare Radar data is CC BY-NC and is excluded. The Tranco list's licence has not been checked by this
lane (its site is not reachable from this environment), so no ranking is used yet.

## Confidence scale

| Level | Meaning |
|---|---|
| **N3 (name, dedicated)** | The vendor publishes the host name as serving this application, and the name serves nothing else. |
| **N2 (name, shared within vendor)** | The name is published but also serves other products of the same vendor (for example `*.cloud.microsoft`), or the vendor states its list is not exhaustive. |
| **N1 (name, weak)** | Only broad wildcards, IP ranges, or names that also serve marketing, sign-in or downloads. |
| **S (structural)** | The protocol bytes are specified in a primary document, so a family profile could validate them. |
| **U** | No primary source: `UNVERIFIED`; not usable for identification. |
| **L (live-verified, date)** | Method v2 input, not a level of its own: the name resolved and answered a TLS handshake with SNI from an unproxied client on that date (`tools/live_verify.py`). It never raises a name above its primary-source level. A name that is dead, or whose CNAME chain or certificate lands in a shared CDN or cloud front end, is **capped at N1** for IP use (the name stays usable, its addresses never are). |
| **O (observed, date)** | Method v2 input: the vendor's own web client contacted the name (`tools/observe_web.js`), or redirected to it. On its own it supports a name only on a vendor-branded domain and only with a Hermes decision; it never establishes identity for a third-party or shared host. |

A spec states one level per observable, not one level per application, and lists the concrete
false-positive risks that cap it.

## Spec format (`research/apps/<name>.md`)

Every spec uses these headings, in this order:

0. Header: application id(s) in the content pack, research status, access date, and readiness:
   `READY` (a recommendation can be implemented from cited sources), `PARTIAL` (some claims ready,
   some `UNVERIFIED`), `BLOCKED` (the primary source could not be read).
1. **What it is**
2. **Transport and ports**
3. **Observable evidence**: handshake bytes, message structure, TLS SNI/ALPN patterns, certificate
   names, DNS names
4. **Encrypted-traffic caveats**: ECH, QUIC, domain fronting, shared CDNs
5. **Confidence and false-positive risks**
6. **Synthetic test vectors** we can generate: positives, negatives, label-boundary and ECH cases,
   using the existing generators `client_hello_with(...)` and `ech_outer(...)` in
   `protocol_adapters/protocol_fixtures.py` (no traffic is captured)
7. **Sources**: exact URLs, access date, page date
8. **Catalog delta and recommendation**: current content-pack entry, each difference from the
   primary source, and the change proposed to the Engine lane
9. **Live verification (L)**: per catalog name, DNS (A/AAAA, CNAME chain, HTTPS/SVCB record) and the
   TLS handshake (version, ALPN accepted, certificate subject and SANs) with date and flags `cdn`, `ech`,
   `h3`, `dead`
10. **Observed web-client hosts**: every host the public web client or login page contacts when loaded
    without signing in, classed as app-owned, shared vendor infrastructure or third party
11. **Attributes (App-ID model) and re-verify date**: functions, dependencies, category, characteristics,
    variant, risk 1 to 5 with its reason, and a re-verify-by date 90 days out

Sections 6 and 9 to 11 are maintained by `tools/retrofit_specs.py` between `method-v2` markers and can be
regenerated; hand-written text stays outside the markers.

## Files

- `LANE-BRIEF.md`: the lane's onboarding brief, read first by every new chat. Each task adds its own
  `migration/notes/PRO-<n>.md` (PRO-347) instead of logging itself in the brief; never edit the brief's generated
  "Recent work" section. Update the hand-written state, open items and pitfalls when they change, then run the gates
  it lists, push, and report the SHA.

- `README.md`: this method.
- `backlog.md`: the ranked backlog, scoring and status of every candidate.
- `apps/*.md`: one spec per candidate.
- `datasets.md`: labelled public traffic datasets for corpus D09 (task 2).
- `apps.json`: spec registry (catalog ids and public web-client URLs per spec).
- `allowlist-requests.md`: network allowlist requests, one batch per approval, with the reason for each host.
- `source-state.json`: recorded hashes and feed versions for change tracking.
- `tools/`: `live_verify.py`, `observe_web.js`, `recheck_sources.py`, `retrofit_specs.py`.
- `protocol/app-attributes.md`: proposed attribute schema (ENGINE-FIELD).
- `observations/`: dependency-mapping outputs (host names, request counts and page status only).
- `child-apps/`: child applications per function for the App-ID model (PRO-492): `wave-N.json` with citations per
  row, and `wave-N.md` rendered from it by `tools/check_child_apps.py --write-md` (which also checks the JSON).
