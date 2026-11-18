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

## Confidence scale

| Level | Meaning |
|---|---|
| **N3 (name, dedicated)** | The vendor publishes the host name as serving this application, and the name serves nothing else. |
| **N2 (name, shared within vendor)** | The name is published but also serves other products of the same vendor (for example `*.cloud.microsoft`), or the vendor states its list is not exhaustive. |
| **N1 (name, weak)** | Only broad wildcards, IP ranges, or names that also serve marketing, sign-in or downloads. |
| **S (structural)** | The protocol bytes are specified in a primary document, so a family profile could validate them. |
| **U** | No primary source: `UNVERIFIED`; not usable for identification. |

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

## Files

- `README.md`: this method.
- `backlog.md`: the ranked backlog, scoring and status of every candidate.
- `apps/*.md`: one spec per candidate.
- `datasets.md`: labelled public traffic datasets for corpus D09 (task 2).
