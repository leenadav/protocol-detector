# Protocol coverage — v0.12

The engine implements 35 families with the profiles below. This is a complete
inventory of this release, not a claim to recognize every protocol or application.
All input must start at the supported message/stream boundary; no port-only match.

| Family | Transport | Selection | Observation scope | Implemented profile |
|---|---|---|---|---|
| radius | udp | Hint required | datagram | Hint required: Access-Request PAP/CHAP/State with supported attributes; no authenticator verification or EAP |
| fastcgi | tcp | Automatic profiles | initial_params | v1 BEGIN_REQUEST plus complete PARAMS stream; one request, zero reserved fields, no response/body semantics |
| rsync | tcp | Automatic profiles | protocol_header | Daemon greeting, final protocols 27..32; version/digest offers, no authentication or transfer |
| mysql | tcp | Hint required | protocol_header | Hint required: modern HandshakeV10, 21-byte challenge and native/caching_sha2/sha256 plugin |
| mongodb | tcp | Hint required | initial_message | Hint required: uncompressed OP_MSG body/sequences, bounded BSON and CRC-32C; no telemetry or command semantics |
| stomp | tcp | Automatic profiles | protocol_header | 1.1/1.2 CONNECT/STOMP/CONNECTED, complete empty-body NUL-terminated frame |
| nats | tcp | Automatic profiles | protocol_header | INFO/CONNECT with required typed JSON fields; bounded extensions, no message bodies |
| imap | tcp | Automatic profiles | protocol_header | Server CAPABILITY or OK/PREAUTH with explicit IMAP4rev1/2 capability; no commands/authentication |
| rdp | tcp | Automatic profiles | negotiation_request | TPKT/X.224 with RDP negotiation, optional cookie/correlation; no routing token or session |
| bgp | tcp | Automatic profiles | negotiation_request | BGPv4 OPEN, standard optional lengths and capability framing |
| smb2 | tcp | Automatic profiles | negotiation_request | Direct TCP SMB2/3 NEGOTIATE including 3.1.1 context framing; offers only |
| snmp | udp | Automatic profiles | datagram | v1/v2c Get/GetNext/GetBulk read requests; no v3, responses or traps |
| tftp | udp | Automatic profiles | datagram | RRQ/WRQ with bounded options; no transfer state |
| ntp | udp | Hint required | datagram | Hint required: v3/v4 base client/server header, no extensions/authentication |
| http | tcp | Automatic profiles | initial_message | HTTP/1.0 and 1.1 start-line/headers |
| http2 | tcp | Automatic profiles | initial_message | Client preface plus initial SETTINGS; no HPACK |
| tls | tcp | Automatic profiles | initial_message | ClientHello only; no decryption or handshake authentication |
| ssh | tcp | Automatic profiles | initial_message | Leading SSH-2.0/1.99 identification |
| socks5 | tcp | Automatic profiles | initial_message | No-auth offer plus client request; server unverified |
| smtp | tcp | Automatic profiles | initial_message | EHLO/HELO only; ambiguous 220 banners unknown |
| mqtt | tcp | Automatic profiles | initial_message | 3.1.1/5.0 CONNECT; MQTT5 CONNECT/Will property validation |
| resp | tcp | Automatic profiles | initial_message | Non-null bulk-string request array; no product inference |
| amqp | tcp | Automatic profiles | protocol_header | Plain 0-9-1/1.0 version header only |
| dns | tcp/udp | Automatic profiles | initial_message/datagram | QUERY opcode, one question; TCP length prefixes >=512 require dns hint |
| stun | tcp/udp | Automatic profiles | initial_message/datagram | Binding method; attributes and optional fingerprint, no HMAC validation |
| dhcp | udp | Automatic profiles | datagram | DHCPv4 types 1..8, no overloaded options |
| coap | udp | Automatic profiles | datagram | CoAP v1 framing, token <=8; tiny messages require coap hint |
| syslog | udp | Automatic profiles | datagram | RFC5424 version 1 header/structured data; no RFC3164 |
| postgresql | tcp | Automatic profiles | initial_message/negotiation_request | v3.0..3.2 startup or SSL/GSS request; no authentication |
| rfb | tcp | Automatic profiles | protocol_header | RFB 3.3/3.7/3.8 banner; no VNC security exchange |
| bittorrent | tcp | Automatic profiles | initial_message | 68-byte peer handshake; encrypted transport unsupported |
| memcached | tcp | Automatic profiles | initial_message | Selected binary request commands 0x00..0x10; no SASL/text/meta |
| ldap | tcp | Automatic profiles | initial_message | LDAPv3 BindRequest, simple/SASL; no controls or searches |
| sip | tcp/udp | Automatic profiles | initial_headers/datagram | SIP/2.0 required header framing; no dialogue/body semantics |
| rtsp | tcp | Automatic profiles | initial_headers | RTSP/1.0 and 2.0 header framing; no RTP/media decoding |

## Profiles and exclusions

- HTTP/1: initial start-line/headers only. Duplicate Host/Content-Length and
  Transfer-Encoding + Content-Length are rejected; transfer coding is limited to
  chunked. No body, later requests or upgrade/tunnel processing.
- HTTP/2: client preface and complete first non-ACK SETTINGS only. No server-only
  detection, HPACK, headers or stream inspection. ALPN h2 is only an offer.
- TLS: ClientHello structural checks, SNI/ALPN extraction and cross-record assembly.
  No ServerHello, certificate authentication, encryption/decryption or ECH recovery.
- SSH: leading SSH-2.0/1.99 line only; no server pre-banner text or key exchange.
- SOCKS5: client no-auth offer plus request; no server selection/reply/authentication.
- SMTP: valid EHLO/HELO only; 220 alone is ambiguous. No DATA/AUTH/STARTTLS.
- MQTT: full initial CONNECT for 3.1.1 and 5.0. Checks lengths, flags, UTF-8,
  ClientId, Will and credentials framing, MQTT5 property types/contexts/duplicates,
  authentication-data dependency and Will payload UTF-8 when declared. Strict
  minimal variable-integer encoding; max 128 properties per block. No 3.1,
  subsequent packets, broker acceptance, authentication or payload inspection.
- RESP: one nonempty array of non-null bulk strings, first string an ASCII command
  token. No server responses, inline/nested requests or command semantics.
- AMQP: exact plain 0-9-1/1.0 eight-byte version header; no frame or handshake validation.
- DNS: QUERY opcode, exactly one question, common IN/ANY class profile, complete
  sections and backward compression pointers to already parsed label boundaries.
  Common A/AAAA/name/MX/SOA/TXT RDATA and EDNS option lengths are checked; unknown
  RDATA is length-checked only. Max 128 total questions/records. No DNSSEC,
  UPDATE/DSO, truncated messages, arbitrary extended labels or mDNS/LLMNR-specific
  semantics. Automatic TCP selection only for declared lengths 12..511; for other
  lengths use a trusted `protocol_hint="dns"` and still validate all bytes.
- STUN: modern magic cookie, Binding method, attribute framing, common address and
  integrity-field lengths, optional FINGERPRINT CRC. No HMAC authentication,
  transaction correlation, legacy RFC3489, TURN methods or media identification.
- DHCP: DHCPv4 BOOTP framing, cookie, type 1..8, TLV bounds and END padding. No
  overloaded options, DHCPv6, lease state or full option semantics.
- CoAP: RFC7252 v1 header, token <=8 bytes, base request codes and response classes,
  delta/length option framing and payload marker. No extended tokens, option
  semantics, block reassembly, observe state, DTLS or OSCORE. Empty/token-only
  messages need an explicit CoAP hint. Ambiguity with DNS remains unknown.
- Syslog: RFC5424 version 1 header, timestamp and structured data including escaping.
  Header-only NILVALUE messages accepted. Log message content is opaque; no RFC3164,
  TCP octet-counting or sender authentication. Invalid escape sequences are handled
  as literal backslashes as required for RFC5424 receivers.
- PostgreSQL: v3.0..3.2 startup name/value framing, required user, conservative
  duplicate-key rejection, SSLRequest and GSSENCRequest. No CancelRequest, server
  authentication, query parsing, or automatic post-negotiation TLS transition.
- RFB: exact 3.3/3.7/3.8 version banners only; not security negotiation or desktop data.
- BitTorrent: complete 68-byte peer handshake; reserved bits accepted, info-hash and
  peer ID treated as opaque. No encrypted transport, tracker/DHT messages or file identity.
- Memcached: binary client opcodes 0x00..0x10, with field-size checks for the included
  GET/store/delete/arithmetic/quit/flush/noop/version/append/prepend/stat shapes.
  No binary responses, SASL, later opcodes, text/meta protocols or value semantics.
  The binary format is recognized for existing traffic, not recommended for new clients.
- LDAP: definite BER lengths (up to four length octets), LDAPv3 BindRequest, simple
  or SASL authentication framing. No controls, search, StartTLS or authentication.
  DN UTF-8 is checked, not full DN grammar. Empty SASL mechanism is accepted as abort syntax.
- SIP: SIP/2.0 start-line, required headers, compact header aliases, CSeq/request-method
  agreement, Max-Forwards and Content-Length syntax. No folded headers, exhaustive
  URI/header semantics, transactions or SDP/media. TCP stops at headers; UDP checks
  available body length. Supported request methods use uppercase letters/underscore.
- RTSP: version 1.0/2.0 start-line and CSeq/header framing; no folded headers, body,
  interleaved RTP, media, session state or upgrade handling. Numeric CSeq is bounded
  to the implemented signed-31-bit inspection profile.

- BGP: v4 OPEN, 16-byte marker, 29..4096 message length, hold time, standard
  optional parameter lengths, capability TLV framing and selected known capability
  lengths. At most 128 capabilities. No UPDATE/routes, extended RFC9072 OPEN
  lengths, session validation, AS/router identity validation or authentication.
- SMB2: direct TCP framing and initial synchronous, unsigned, uncompounded NEGOTIATE
  request. Fixed structure/header fields, bounded dialect array, 3.1.1 context offsets,
  alignment, uniqueness, reserved fields, preauthentication hash/salt lengths and
  encryption capability lengths. Unknown contexts get length checks only. At most
  128 dialects/contexts; SHA-512 preauthentication offer required for 3.1.1 in this
  profile. Offered dialects do not establish a negotiated version or encryption.
  No SMB1, NetBIOS session setup, server negotiation, file operations or encrypted SMB.
- SNMP: v1/v2c Get/GetNext and v2c GetBulk, definite BER, signed 32-bit integer
  fields, request status/bulk counts, OID base-128 framing and NULL read values.
  At most 128 bindings and 128 arcs per OID. Community is never emitted. No v3,
  SET, response/trap/inform messages, MIB semantics or authentication.
- TFTP: initial RRQ/WRQ <=512 bytes, printable ASCII filename/mode profile,
  netascii/octet/mail modes, <=16 unique option/value pairs. Known blksize, timeout,
  tsize and windowsize numerical constraints; unknown options checked for framing
  only. No DATA/ACK/OACK transfer tracking or file identity.
- NTP: **explicit `protocol_hint="ntp"` required**. v3/v4 client/server modes,
  exactly 48 bytes, stratum bound and nonzero server transmit timestamp. This is
  weak structural evidence, not automatic identification or clock correctness.
  No extensions, MAC, NTS, control/private messages or request-response correlation.
  Candidate hints are emitted as caller context, never identity evidence.

## v0.7 handshake profiles and bounds

- STOMP: CONNECT/STOMP with nonempty host and a supported accept-version list,
  or CONNECTED with version 1.1/1.2. LF and CRLF, UTF-8 headers, STOMP escapes,
  first duplicate wins, optional zero content-length and numeric heart-beat pair
  (20-digit maximum per component). All these commands require an empty body and
  terminal NUL. Line/header/byte/update budgets apply. Legacy 1.0-only negotiation,
  leading heartbeats, SEND/MESSAGE/ERROR bodies and connection state are unsupported.
- NATS: CRLF-terminated case-insensitive INFO/CONNECT and one JSON object. INFO
  requires server_id/version/go/host strings, port 1..65535 and positive max_payload
  <=2^63-1. CONNECT requires verbose/pedantic/tls_required booleans and nonempty
  lang/version strings. Known optional scalar/list fields are type-checked. Unknown
  extension values get syntax/resource validation only. Depth <=16, up to
  min(max_headers,128) members per object and four times that many structural
  tokens/decoded values; numbers <=20 integer digits, finite floats. Duplicate
  JSON keys, nonstandard constants and unpaired Unicode surrogates are rejected.
  No empty/minimal CONNECT profile, PUB/SUB/MSG, WebSocket or NATS server-link protocol.
- IMAP: initial untagged CAPABILITY response or OK/PREAUTH greeting containing a
  CAPABILITY response code, with an exact case-insensitive IMAP4rev1 or IMAP4rev2
  atom. At most min(max_headers,128) capability atoms; nonempty UTF-8 greeting text
  without control bytes. Generic OK/PREAUTH, tagged commands, mail bodies, literals
  and authentication are unsupported. Capabilities remain server assertions; they
  do not establish a selected revision or prove authentication.
- RDP: TPKT version 3, reserved zero, length 11..260, X.224 class-zero connection
  request, consistent length indicator and explicit 8-byte RDP negotiation request.
  Optional mstshash cookie and 36-byte correlation structure are checked. Supported
  security flag bits are 0..4; negotiation flag mask 0x0b. No routing tokens,
  legacy request without negotiation, server responses, encryption or session parsing.
  Offered security flags are emitted as offered evidence. No cookies are emitted.

## v0.8 database profiles

Both require explicit TCP candidate hints, validated independently of ports.
Neither automatic routing nor a fallback protocol scan was added.

- MySQL: sequence-zero HandshakeV10; printable nonempty server-version field up to
  128 bytes, protocol-4.1/secure-connection/plugin-auth capabilities, nonzero charset,
  zero filler/reserved fields, 21-byte challenge and terminated plugin name.
  Supported plugins: mysql_native_password, caching_sha2_password, sha256_password.
  Capabilities remain offers. No legacy/alternative challenge layouts, MariaDB
  extension fields, client authentication, SSLRequest, compression or SQL commands.
- MongoDB: uncompressed OP_MSG, exactly one body section, optional kind-1 sequences
  in either order, simple unique identifiers absent from body. Unknown required
  flags/types rejected; unknown optional flags ignored by this observer. Requests
  require command-first structure and a nonempty string $db (database-name and
  command semantics are not fully validated). Reply framing is supported without
  request correlation. CRC-32C is verified when present. No OP_COMPRESSED, legacy
  opcodes, kind-2 security tokens or kind-3 telemetry.
- BSON: all standard element framing, UTF-8, bool values, nested documents/arrays,
  binary lengths, legacy binary inner length and UUID/MD5 widths, regex option
  ordering, code-with-scope boundaries. Binary subtype contents remain opaque.
  Depth <=16, total elements <=min(max_headers,128), documents <=128, cstrings
  <=min(max_line,1024). Duplicate keys are rejected at all levels. No code execution.

CRC-32C has a separate default 4096-byte input budget; exceeding it yields
budget_exhausted from the fixed header, before body accumulation. It is configurable
with Config.max_crc32c_bytes or --crc32c-byte-limit (0..1048576). Zero rejects
checksummed messages. Increasing the budget can add milliseconds in Python.
The overall byte budget remains independent and still applies.

## What is not implemented

These are remaining engineering work, not implicitly identified protocols:

| Area | Required work |
|---|---|
| QUIC / HTTP/3 | Version-aware protected packet parsing, Initial crypto processing, CRYPTO/stream assembly and HTTP/3 validation |
| DTLS | Record/epoch handling and bounded datagram handshake-fragment assembly |
| WebSocket / gRPC | Trusted HTTP upgrade/transaction boundaries or HTTP/2 headers/streams and application framing |
| FTP / POP3 / additional IMAP commands | Additional validators and bidirectional evidence for ambiguous greetings/commands |
| Additional database/RDP phases | MySQL client/auth/query phases, MongoDB compressed/legacy/telemetry sections, RDP later phases and independent traffic corpora |
| RTP / SNMPv3 / NTS and others | Protocol-specific validation and evidence rules, especially for weak short headers |
| DNS-over-HTTPS, general application/product identity | Validated outer transactions plus inner payload inspection and explicit attribution evidence |
| Persistent sessions and upgrades | Host integration for phase/transaction boundaries; no guessing from arbitrary payload substrings |

The new framing/registry/datagram infrastructure enables further parsers; it does
not make unimplemented protocols supported automatically. Production priorities
should be driven by actual SWG traffic and required detection accuracy, not only
by increasing a protocol counter.

## Primary specifications used

- [DNS RFC1035](https://www.rfc-editor.org/rfc/rfc1035.html)
- [STUN RFC8489](https://www.rfc-editor.org/rfc/rfc8489.html), [published test vectors RFC5769](https://www.rfc-editor.org/rfc/rfc5769.html)
- [DHCPv4 RFC2131](https://www.rfc-editor.org/rfc/rfc2131.html)
- [CoAP RFC7252](https://www.rfc-editor.org/rfc/rfc7252.html)
- [Syslog RFC5424](https://www.rfc-editor.org/rfc/rfc5424.html)
- [PostgreSQL message formats](https://www.postgresql.org/docs/18/protocol-message-formats.html)
- [RFB RFC6143](https://www.rfc-editor.org/rfc/rfc6143.html)
- [BitTorrent BEP3](https://www.bittorrent.org/beps/bep_0003.html)
- [Memcached binary protocol](https://docs.memcached.org/protocols/binary/)
- [LDAP RFC4511](https://www.rfc-editor.org/rfc/rfc4511.html)
- [SIP RFC3261](https://www.rfc-editor.org/rfc/rfc3261.html)
- [RTSP RFC2326](https://www.rfc-editor.org/rfc/rfc2326.html), [RTSP2 RFC7826](https://www.rfc-editor.org/rfc/rfc7826.html)
- [MQTT 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/errata01/os/mqtt-v3.1.1-errata01-os-complete.html), [MQTT 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- [RESP](https://redis.io/docs/latest/develop/reference/protocol-spec/)
- [AMQP 1.0](https://docs.oasis-open.org/amqp/core/v1.0/os/amqp-core-transport-v1.0-os.html), [AMQP 0-9-1](https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf)
- [HTTP/1 RFC9112](https://www.rfc-editor.org/rfc/rfc9112.html), [HTTP/2 RFC9113](https://www.rfc-editor.org/rfc/rfc9113.html)
- [TLS RFC8446](https://www.rfc-editor.org/rfc/rfc8446.html), [SSH RFC4253](https://www.rfc-editor.org/rfc/rfc4253.html)
- [SOCKS5 RFC1928](https://www.rfc-editor.org/rfc/rfc1928.html), [SMTP RFC5321](https://www.rfc-editor.org/rfc/rfc5321.html)

Additional v0.6 primary references:

- [BGP RFC4271](https://www.rfc-editor.org/rfc/rfc4271.html), [capabilities RFC5492](https://www.rfc-editor.org/rfc/rfc5492.html).
- [Microsoft SMB2 NEGOTIATE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5), [SMB3 preauthentication context](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a07bd66-4734-4af8-abcf-5a44ff7ee0e5).
- [SNMPv1 RFC1157](https://www.rfc-editor.org/rfc/rfc1157.html), [SNMP operations RFC3416](https://www.rfc-editor.org/rfc/rfc3416.html).
- [TFTP RFC1350](https://www.rfc-editor.org/rfc/rfc1350.html), [options RFC2347](https://www.rfc-editor.org/rfc/rfc2347.html), [block size RFC2348](https://www.rfc-editor.org/rfc/rfc2348.html), [timeout/size RFC2349](https://www.rfc-editor.org/rfc/rfc2349.html), [window RFC7440](https://www.rfc-editor.org/rfc/rfc7440.html).
- [NTP RFC5905](https://www.rfc-editor.org/rfc/rfc5905.html).

Additional v0.7 primary references:

- [STOMP 1.2](https://stomp.github.io/stomp-specification-1.2.html).
- [NATS client protocol](https://docs.nats.io/reference/protocols/client).
- [IMAP4rev2 RFC9051](https://www.rfc-editor.org/rfc/rfc9051.html), [IMAP4rev1 RFC3501](https://www.rfc-editor.org/rfc/rfc3501.html).
- [RDP X.224 connection request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/18a27ef9-6f9a-4501-b000-94b1fe3c2c10), [negotiation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3), [correlation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/f047e45b-fbb8-4014-8f20-ce80149586d7).

Additional v0.8 primary references:

- [MySQL HandshakeV10](https://dev.mysql.com/doc/dev/mysql-server/8.0.46/page_protocol_connection_phase_packets_protocol_handshake_v10.html), [packet framing](https://dev.mysql.com/doc/dev/mysql-server/8.0.46/page_protocol_basic_packets.html), [capabilities](https://dev.mysql.com/doc/dev/mysql-server/8.0.46/group__group__cs__capabilities__flags.html).
- [MongoDB wire format](https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/), [OP_MSG specification](https://github.com/mongodb/specifications/blob/master/source/message/OP_MSG.md).
- [BSON specification](https://bsonspec.org/spec.html), [published BSON test corpus](https://github.com/mongodb/specifications/tree/master/source/bson-corpus/tests).
- [RFC3720 appendix B.4 CRC-32C vectors](https://www.rfc-editor.org/rfc/rfc3720.html#appendix-B.4).

## v0.9 FastCGI and rsync profiles

- FastCGI v1: initial BEGIN_REQUEST, nonzero request ID, content length eight,
  role responder/authorizer/filter, KEEP_CONN flag only, zero reserved header/body
  bytes. Zero reserved bytes are a conservative profile restriction, not a claim
  that the original specification mandates rejecting every other value. Skip
  arbitrary padding (0..255 bytes), but require it to arrive completely.
- Require subsequent PARAMS records for that same request and an explicit empty
  PARAMS terminator. Decode both length encodings, including across record
  boundaries, and validate all name/value boundaries. Binary, empty and duplicate
  strings are framed without interpreting CGI/HTTP semantics. Values and IDs are
  never exported. No STDIN/DATA/STDOUT parsing, management records, multiplexed
  requests, response correlation, execution or later-request validation.
- At most min(max_headers,128) records including BEGIN and PARAMS EOF; independently
  at most min(max_headers,128) name/value pairs. Aggregate advertised wire bytes,
  including headers/padding, cannot exceed max_bytes; reject over-budget headers
  before body growth. Padding is discarded; retained parameters are bounded by
  max_bytes and released at identification. Scope: initial_params.
- Automatic FastCGI dispatch uses the eight-byte BEGIN header. Within the current
  one-question DNS profile it is disjoint: DNS QDCOUNT at those offsets would be
  padding<<8, never one when the reserved byte is zero. A valid 257-byte DNS
  collision fixture and all 256 padding lengths exercise this property.
- Rsync daemon: exact LF-terminated @RSYNCD greeting, final protocol versions
  27..32 (subprotocol zero); version >=30 requires the dot/subprotocol and >=32
  requires digest offers. Offers use lowercase alphanumeric/hyphen tokens,
  max 32 bytes each, no duplicates, at most min(max_headers,16). Unknown digest
  names are only syntax-checked, not algorithm support or authentication proof.
  Whole line <=min(max_line,512). Older/future/development versions, CRLF greetings,
  remote-shell rsync, AUTHREQD/OK/EXIT mid-session lines and file transfer are
  outside this profile. Scope: protocol_header. No module/usernames retained.

Primary sources consulted 2026-10-19:
- [Original FastCGI specification, archived](https://fastcgi-archives.github.io/FastCGI_Specification.html), sections 3.3, 3.4, 5.1, 5.2.
- [Rsync daemon protocol notes](https://github.com/RsyncProject/rsync/blob/master/csprotocol.txt) and [implementation, exchange_protocols](https://github.com/RsyncProject/rsync/blob/master/clientserver.c).

Protocol notes are informal and some version commentary is dated; this detector
uses explicitly documented version bounds, not an inference of the latest release.

## v0.10 RADIUS Access-Request profile

Explicit UDP candidate required. This is structural recognition, not authentication.
Packet code 1 only, length 20..4096 and exactly equal to the supplied datagram.
RFC2865 permits trailing UDP padding; this conservative profile leaves padded
packets unknown. All attributes must fit their enclosing packet. At most
min(max_headers,128) attributes; overall Config.max_bytes still applies first.

Supported attribute types:
- Four-byte address/integer values: 4, 5, 6, 7, 8, 9, 12, 13, 14, 61, 62.
  Widths are checked; complete enum/policy/cross-attribute semantics are not.
- Nonempty binary strings: 1, 19, 24, 30, 31, 32, 33, 60. No assumption that
  every username/station field is UTF-8; embedded NULs are allowed by RFC2865.
- User-Password (2): ciphertext 16..128 bytes, multiple of 16; no decryption.
- CHAP-Password (3): one-byte identifier plus 16-byte response; no verification.
- Vendor-Specific (26): four-byte vendor ID with high byte zero and nonempty
  opaque vendor data. Vendor-specific encodings are not recursively interpreted.
- Message-Authenticator (80): 16-byte field, **HMAC not verified**; no shared secret.

NAS-IP-Address or NAS-Identifier required. At least one of User-Password,
CHAP-Password or State required; PAP and CHAP cannot coexist. Singleton duplicates
are rejected; types 13,14,26,33 may repeat. Other attributes, EAP, extended
attributes, replies, accounting, dynamic authorization and RADIUS-over-TCP/TLS
are outside scope. No credentials, usernames, NAS identifiers or vendor values
are emitted. Authenticator randomness/uniqueness and peer identity are unverified.

A dual-encoding test is structurally valid both as supported DNS and as RADIUS.
RADIUS is deliberately excluded from automatic routing; hints restrict validation
and cannot prove sender intent. Automatic recognition can select a different
supported structure when a hinted-only family overlaps it. No new automatic
candidate scan or UDP validator work is introduced by registering this hint.

Primary sources: [RFC2865](https://www.rfc-editor.org/rfc/rfc2865.html), sections 3,
4.1, 5 and 7.1/7.2 (independent PAP/CHAP test vectors), and
[RFC2869 Message-Authenticator](https://www.rfc-editor.org/rfc/rfc2869.html#section-5.14).
Consulted 2026-10-19. The profile is not a claim of full modern RADIUS coverage.
