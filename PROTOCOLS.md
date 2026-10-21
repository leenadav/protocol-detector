# Protocol coverage — v0.25

The engine implements 41 families with the profiles below. This is a complete
inventory of this release, not a claim to recognize every protocol or application.
All input must start at the supported message/stream boundary; no port-only match.

| Family | Transport | Selection | Observation scope | Implemented profile |
|---|---|---|---|---|
| quic | udp | Automatic profiles | datagram | QUIC v1/v2 client Initial with protection removed (public Initial keys), ClientHello SNI/ALPN as offers, Version Negotiation; no handshake completion, server Initials, 0-RTT or later packets |
| ikev2 | udp | Automatic profiles | datagram | IKE_SA_INIT initiator, bounded AES-CBC/GCM and MODP14..18 offers, KE/nonce, optional non-ESP marker; no authentication or established tunnel claim |
| dtls | udp | Automatic profiles | datagram | DTLS1.2 complete epoch-zero ClientHello in one record/datagram; client assertions only, no fragments or decryption |
| dcerpc | tcp | Automatic profiles | bind_request | Connection-oriented 5.0 Bind, NDR 2.0/NDR64 1.0 offers; no authentication, replies, stub decoding or product identity |
| giop | tcp | Automatic profiles | request_header/locate_request | GIOP 1.2 unfragmented KeyAddr Request/LocateRequest; bounded CDR; opaque arguments and service contexts |
| git | tcp | Automatic profiles | service_request | Native Git pkt-line request; bounded path, optional DNS/IPv4 host and extras; no packfile/server/version-negotiation validation |
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
| tls | tcp | Automatic profiles | initial_message/server_hello/hello_retry_request | ClientHello plus TLS1.2/1.3 ServerHello and TLS1.3 retry profiles; no decryption/authentication |
| ssh | tcp | Automatic profiles | initial_message | Leading SSH-2.0/1.99 identification; with fingerprints, one bounded KEXINIT refinement (HASSH) |
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
  ServerHello/HelloRetryRequest profiles below; no certificate authentication,
  encryption/decryption or ECH recovery.
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
| HTTP/3 | HTTP/3 itself (QPACK, SETTINGS, streams) is not validated; QUIC Initial recognition and ClientHello recovery exist since v0.25 and h3 remains an ALPN offer |
| Further DTLS profiles | Handshake-fragment assembly, coalesced records/messages, server evidence and DTLS1.3 |
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


## Native Git profile (v0.16)

- Client service requests for upload-pack, receive-pack and upload-archive. Full
  lowercase-hex pkt-line length and complete NUL-terminated request are required;
  maximum wire frame is 65520 bytes and Config.max_bytes can lower that budget.
- Path must be nonempty, without ASCII controls/DEL, and the initial field fits
  Config.max_line (including four length bytes and its NUL). Other path bytes
  are opaque. No filesystem/repository existence or authorization is inferred.
- Optional host is an ASCII DNS name or IPv4 literal with optional port 1..65535;
  authority length is at most260. IPv6 authorities are outside this profile.
- Optional extras require their separate NUL delimiter. At most min(max_headers,16)
  extras, each at most min(max_line,512) bytes, key at most64 bytes. The supported
  profile uses ASCII alphanumeric/hyphen/underscore keys and printable non-space
  values; duplicates and unsupported version offers are unknown, never matches.
- Version1/2 is recorded only as offered_version evidence. No host, repository
  path, opaque extra value or credentials are emitted as identity or telemetry.
- Automatic prefix routing does not confuse a Git-shaped HTTP extension method
  with Git. The first NUL/LF chooses strict Git/text parsing within max_line;
  the dispatch prefix itself remains bounded to24 bytes. Internal git_text is
  not a caller hint. The public git hint restricts validation to Git alone.
- No response/ref discovery, packfile, Git-over-SSH/HTTP, authentication or later
  session validation. Flush/control pkt-lines alone never identify this profile.

Primary specifications: [Git pack protocol](https://git-scm.com/docs/pack-protocol)
and [Git common protocol framing](https://git-scm.com/docs/protocol-common).

## GIOP profile (v0.17)

- Version 1.2, unfragmented Request (type 0) or LocateRequest (type 3), both
  endian orders. Header reserved flag bits must be zero. Complete advertised
  frame required; bounded by max_bytes, rejected at the header when oversized.
- KeyAddr target only; object key <=max_line bytes, including empty keys.
  Request flags 0,1,3; reserved request octets zero in this conservative profile.
  Operation is a nonempty ASCII identifier [A-Za-z_][A-Za-z0-9_]*, stored as a
  bounded CDR string including exactly one terminal NUL, total <=max_line.
- At most min(max_headers,128) contexts; IDs and bounded octet sequence lengths
  checked, context payloads opaque. Arbitrary CDR alignment padding accepted.
  Nonempty request arguments must follow 8-byte alignment; their IDL-dependent
  encoding is unverified. Empty bodies must not have alignment-only padding.
- LocateRequest must end exactly after its object key. No replies, cancel,
  fragmentation, ProfileAddr/ReferenceAddr, older/newer GIOP versions, application
  identity, request correlation or authentication. TCP segmentation is supported;
  GIOP application-level fragmentation is not.
- Automatic prefix dispatch waits at most five bytes for GIOP + binary major
  version 1. Text extensions such as GIOP / HTTP/1.1 stay on the text path.
  One parser per direction; no registry scan. Explicit giop hint remains strict.

Primary specification: [OMG CORBA interoperability](https://www.omg.org/spec/CORBA/3.4/Interoperability/PDF),
sections 9.3 CDR and 9.4.1/9.4.2/9.4.5 (normative file formal/12-11-14,
PDF labeled Part 2 v3.3), and [OMG GIOP IDL](https://www.omg.org/spec/CORBA/20120301/GIOP.idl).

## DCE/RPC profile (v0.18)

- Connection-oriented version 5.0, type 11 (Bind), complete unfragmented PDU.
  FIRST/LAST required; optional CONC_MPX and SUPPORT_HEADER_SIGN flags are offers
  only. Other flags, minor 1 and nonzero auth_length are outside this profile.
- ASCII/IEEE packed representation, big- or little-endian integers. Whole frame
  >=72 bytes and <=max_bytes. Advertised fragment-size preferences, call ID and
  association group are opaque: no endpoint negotiation/transport-limit claim.
  Zero size preferences retain C706's default encoding.
- Nonempty context list, <=min(max_headers,128), unique context IDs, zero reserved
  fields, nonnil abstract UUID; interface version is opaque. Each context offers
  one or two distinct standard transfer syntaxes, with exact UUID/version matches
  for NDR 2.0 and NDR64 1.0. Their wire UUID byte order follows packed_drep.
  Offers do not imply that subsequent stub arguments use either encoding.
- Entire list length checked, no trailing bytes. Unknown transfer syntaxes,
  Microsoft bind-time feature contexts, authentication verifiers, replies,
  application fragmentation, stub decoding, named-pipe/SMB encapsulation and
  interface-to-product mapping are unsupported. TCP segmentation is supported.
- Auto-dispatch uses 05 00; SOCKS5 requires a nonzero method count, so there is no
  valid supported overlap. A partial 05 00 is now detecting/incomplete instead
  of immediately malformed; explicit socks5 hints retain strict SOCKS validation.

Primary specifications: [Open Group C706 chapter 12](https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm),
sections 12.6.3 and 12.6.4.3; Microsoft [NDR identifier](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/b6090c2b-f44a-47a1-a13b-b82ade0137b2),
[NDR64 identifier](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/dca648a5-42d3-432c-9927-2f22e50fa266),
and [header-sign flag](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/4886f349-2a73-4f9e-9262-a8404462c7e9).

## TLS server profiles (v0.19)

- Initial handshake type2, legacy_version0303, session-ID vector<=32, null
  compression. Optional extension vector must end exactly; duplicate extensions
  rejected, at most min(max_headers,128). One complete hello required; shared
  plaintext record framing permits TCP and TLS-record fragmentation. Other initial
  handshake types remain unsupported. No preceding compatibility CCS or alerts.
- TLS1.2: cipher002f or c023..c032 (RFC5246/RFC5289); no general cipher registry.
  Supported extensions: empty SNI/status_request/extended_master_secret/session_ticket
  acknowledgements (0,5,23,35), initial renegotiation_info65281 with empty vector,
  EC point formats11 with list containing uncompressed0 and only values0..2,
  ALPN16 containing exactly one nonempty name. Unknown extensions/ciphers excluded.
  Later coalesced handshake bytes remain uninspected; this is hello scope only.
- TLS1.3: supported_versions43 must select0304; cipher1301..1305. Common record
  versions must be0303 and hello must end at record boundary. Normal ServerHello
  allows only43,41,51 and requires PSK selection41 (two-byte index), key_share51,
  or both. No PSK authenticity/offer correlation. Key shares have exact lengths
  for secp256r1/384r1/521r1 (65/97/133, uncompressed point prefix04), x25519/x448
  (32/56), ffdhe2048/3072/4096/6144/8192 (256/384/512/768/1024). Key values, curve
  membership and cryptographic validity are NOT checked. Other/hybrid/PQ groups
  are unsupported, even when used by current TLS library defaults.
- The RFC8446 special random identifies HelloRetryRequest. It permits only43,44,51
  and requires a cookie or requested group. Cookie is a nonempty two-byte-length
  vector; key_share contains only the supported group code. Scope is
  hello_retry_request, not a completed handshake. Subsequent retry/hello sequences
  and correspondence with the client's offers are not correlated.
- Server version/cipher/group and TLS1.2 selected_alpn evidence are asserted with
  server_hello/hello_retry_request provenance. They are not offered_alpn, inner
  application_protocol, hostname or authenticated identity. No certificate,
  Finished, downgrade protection, session acceptance or application verification.
  TLS1.3 ALPN is in EncryptedExtensions and is not readable here. Existing trusted
  plaintext refinement remains separate; no proxy integration was added.
- Legacy detectors.py remains an educational ClientHello-only demonstration;
  the engine and capture adapters use the broader profile described above.

Primary specifications: [RFC8446](https://www.rfc-editor.org/rfc/rfc8446.html),
sections4.1.3/4.1.4/4.2/5.1; [RFC5246](https://www.rfc-editor.org/rfc/rfc5246.html),
section7.4.1.3; [RFC5289](https://www.rfc-editor.org/rfc/rfc5289.html);
[ALPN RFC7301](https://www.rfc-editor.org/rfc/rfc7301.html);
[RFC6066](https://www.rfc-editor.org/rfc/rfc6066.html),
[RFC7627](https://www.rfc-editor.org/rfc/rfc7627.html),
[RFC5746](https://www.rfc-editor.org/rfc/rfc5746.html),
[RFC4492](https://www.rfc-editor.org/rfc/rfc4492.html),
[RFC5077](https://www.rfc-editor.org/rfc/rfc5077.html).


## DTLS ClientHello profile (v0.20)

- Automatic fixed three-byte route: handshake record22, record versionFEFF orFEFD.
  Epoch must be zero. Exactly one record, plaintext length12..16384, must occupy
  the whole UDP payload. Exactly one complete type1 handshake must occupy that
  record. Offset zero and fragment length equal total length are required.
- ClientHello versionFEFD, session ID<=32, opaque cookie<=255, nonempty even
  cipher vector and a sole null-compression offer. Cipher values are offers,
  not a negotiated or cryptographically validated selection.
- Optional extension vector must end exactly; at most min(max_headers,128)
  entries, with duplicate types rejected. Shared TLS validation checks SNI names
  and ALPN list syntax (max64 offers); other extension values stay opaque.
  supported_versions (type43) is outside this deliberately narrow profile.
- Result: encryption=dtls, application_protocol/application unset. SNI and ALPN
  have dtls_sni/dtls_alpn asserted provenance. offered_dtls_version=1.2 is a
  client assertion. Random, session ID, cookie and opaque extensions are omitted.
- Record/message sequence numbers are accepted as opaque counters, without
  replay protection or association correlation. Cookie echo, reachability,
  renegotiation, authentication, Finished and inner content are not validated.
  Encrypted epochs, other handshake types, fragments, multiple records/messages
  and DTLS1.0/1.3 negotiation return non-identification. Datagrams are never joined.
- The configured byte budget applies before parsing and to declared hello size.
  A bounded extension-count pass precedes shared TLS syntax decoding; maximum
  record size bounds copying/scanning. No port lookup or registry scan is used.

Primary format: [RFC6347 sections4.1/4.2.1/4.2.2](https://www.rfc-editor.org/rfc/rfc6347.html).
The inherited ClientHello/SNI/ALPN checks use the TLS specifications listed above.

Validation includes every truncation and fragment split, length/count boundaries,
metadata privacy, 2,500 seeded mutations, existing-family ambiguity checks and a
DHCP-cookie collision inside a valid DTLS cookie. `dtls_interop.py` additionally
checks actual LibreSSL3.3.6 ClientHello and cookie retry against a synthetic local
responder; this is not a complete DTLS interoperability or security certification.


## IKEv2 initial request profile (v0.21)

This profile recognizes plaintext IKE_SA_INIT negotiation, not ESP traffic or an
established VPN. Output is application_protocol=ikev2 with encryption/application
unset; offered_dh_group is an initiator assertion. SPI, key, nonce, cookie, vendor
and NAT hash bytes are never emitted.

- Header version2.0, exchange34, flags0x08, message ID0, nonzero initiator SPI and
  zero responder SPI. Optional four-zero-byte non-ESP marker is excluded from
  IKE length. Exactly one full message fills the datagram; no port dependency.
- Required singleton SA, KE and nonce payloads may occur in any order. Chaining
  and all nested lengths must end exactly. Reserved header/payload/proposal/KE/
  transform fields must be zero; known-payload critical bit is accepted.
- Proposals start at1, increase consecutively, specify IKE protocol and zero
  inner SPI length. Transform counts and continuation markers must agree.
  Supported IDs: ENCR12(AES-CBC) or18/19/20(AES-GCM), PRF2/5/6/7(HMAC-SHA1/2),
  INTEG2/12/13/14(HMAC-SHA1/2), DH14..18(MODP2048..8192).
- AES needs exactly one TV key-length attribute14,128/192/256 bits. Other
  transforms carry no attributes. CBC proposals require integrity; AEAD-only
  proposals must omit integrity. Mixing CBC/AEAD within one proposal is outside
  this profile; separate proposals are accepted. No algorithm security policy.
- KE public-value width must match its MODP group, which must be offered by an
  SA proposal. Nonce16..256 bytes and at least half the largest offered PRF key
  size. Public-number validity, entropy and cryptographic relationships are not
  checked. No key computation is performed.
- Optional NAT source/destination notifications16388/16389 require20-byte data
  and no SPI/protocol ID. Cookie16390 requires1..64 bytes and must be the first
  payload. Vendor IDs are nonempty opaque fields bounded by max_line. Other
  payload/transform/notification variants, ECC/PQ groups, IKEv1, responses,
  encrypted messages, later exchanges and IKE fragmentation are unsupported.
- One aggregate budget min(max_headers,128) counts payloads, proposals and
  transforms together. max_bytes applies to input and advertised message size.
  No input is retained across calls. Requests shorter than352 bytes cannot fit
  this profile and bypass the automatic IKE probe (explicit hints still validate).

The probe checks only fixed header positions0/4. It adds one competing candidate
to the existing UDP route rather than overriding random SPI collisions. Maximum
three validators; dual supported structures return unknown, competing exhausted
work budgets prevent identification. Two actual dual encodings (CoAP/IKE and
DHCP/IKE) and the three-candidate ceiling are regression-tested.

Primary specifications:
[RFC7296](https://www.rfc-editor.org/rfc/rfc7296.html),
[RFC5282 AES-GCM proposal rules](https://www.rfc-editor.org/rfc/rfc5282.html),
[RFC4868 HMAC-SHA2](https://www.rfc-editor.org/rfc/rfc4868.html),
[IANA IKEv2 identifiers](https://www.iana.org/assignments/ikev2-parameters).
Spec-derived tests include all supported algorithm combinations, truncations,
length/count limits, cookie/marker handling and3,000 mutations. Independent
tcpdump dissection agrees on both basic fixtures; no real IKE endpoint tested.

## TLS EC context correction (v0.21)

Review4319051025 was reproduced onv0.20: TLS1.2 cipher0x002f plus extension11
incorrectly identified. Extension11 now requires one of the supported ECC suites
0xc023..0xc032. RSA-only0x002f without that extension remains valid. All TCP and
TLS-record splits reject the invalid combination; all supported ECC suites retain
positive coverage. This is a structural context check, not client-offer matching.
Source: [RFC8422 section5.2](https://www.rfc-editor.org/rfc/rfc8422.html#section-5.2).
Legacy point-format values0..2 remain in the documented compatibility profile.


## App-ID verdict layer (v0.22)

The verdict layer adds no parsing and no new protocol family. It maps completed
observations to catalog names (`protocol_engine/applications.py`) and merges the
two directions of a session (`protocol_engine/appid.py`). Mapping is by family:
`http/*` and `http2` → `web-browsing`; encryption `tls` → `ssl`; `rfb` → `vnc`;
`socks5` → `socks`; `smb2` → `smb`; `dcerpc/*` → `dce-rpc`; `ikev2` → `ike`; all
other families keep their name without the version suffix. A `RuleIndex`
application replaces the name and keeps the carrier in `base_app`.

Outcomes: `unknown-tcp`/`unknown-udp` for statuses unknown, malformed and
budget_exhausted; `not-applicable` for invalidated; `insufficient-data` for
incomplete/detecting with payload; `incomplete` for a session without payload or
without a completed handshake. `port_usage` is `standard` when the server port is
listed in the catalog's standard or secure ports (ranges and `dynamic` allowed),
`nonstandard` otherwise, `unknown` when no port or no ports are known.

Session records are an adapter feature (analyze_pcap/live_capture). They are
bounded by the existing connection table and a UDP flow table of the same size;
excess UDP flows are counted and not tracked. Records expose counts and verdict
fields only; `--hostnames` adds the asserted SNI/Host name. See APPID.md.


## Custom signature contexts (v0.23)

Signatures add no protocol family and never bypass a profile. Parsers retain
bounded contexts only when `Config.retain_contexts` is set: HTTP keeps method,
path (without query), version, normalized host, the first User-Agent (1024
bytes), Content-Length and a 4096-byte lowercase-name header block; TLS keeps
the ClientHello body, legacy version, cipher and extension type sets, SNI and
ALPN (plus groups, signature algorithms, point formats and supported versions in
`ClientHelloInfo` for fingerprints); SSH keeps the identification line; SMTP the
EHLO/HELO argument; SOCKS5 the target and port; DNS (TCP and UDP) the lowercase
question name and QTYPE. Unknown TCP prefixes are buffered up to
`signature_bytes` only when the set has unknown-tcp conditions; unknown UDP
datagrams are evaluated in place. Hints restrict validation and never open
unknown-payload signatures. Full context table and pattern rules: SIGNATURES.md.


## Fingerprints and the SSH KEXINIT refinement (v0.24)

Fingerprints add no family and never influence identification. TLS/DTLS
ClientHello and TLS ServerHello digests reuse fields already validated by the
profiles. The SSH profile gains an optional second stage: with
`Config.fingerprints`, exactly one SSH_MSG_KEXINIT packet (RFC 4253 7.1) is
read after the banner: packet length 17..35000 and <= max_bytes-4, padding >= 4,
16-byte cookie, ten name-lists of printable ASCII (<= 4096 bytes each),
first_kex_packet_follows in {0,1}, zero reserved word, no trailing bytes within
the packet. Only the four client-to-server name-lists needed for HASSH are kept
until the digest is computed. Any deviation, the byte budget or EOF ends the
refinement and the identification made at the banner stands unchanged. Bytes
after the KEXINIT are not consumed. See FINGERPRINTS.md.


## QUIC Initial profile (v0.25)

- Long header with the fixed bit set, version 0x00000001 (v1, Initial type 0b00)
  or 0x6b3343cf (v2, Initial type 0b01). Connection ID lengths <= 20 and inside
  the datagram; token length varint and token inside the datagram; Length
  varint >= 17 and ending inside the datagram (bytes after it are tolerated as
  coalesced packets or padding, RFC 9000 12.2). Version 0 with a nonempty list
  of 32-bit versions (<= min(max_headers,128)) is Version Negotiation.
- With `Config.quic_decrypt` (default on) and datagram <= max_bytes, the client
  Initial keys are derived from the version salt and Destination Connection ID
  (RFC 9001 5.2, RFC 9369 3.3) with HKDF-SHA256, header protection is removed
  with AES-128-ECB on the 16-byte sample at pn_offset+4, reserved bits must be
  zero, and the payload is opened with AES-128-GCM over the unprotected header.
  Failure (server packet, retry-token flow, damaged datagram, non-zero reserved
  bits) keeps the structural identification with `initial_protection=unverified`.
- Opened frames must be PADDING, PING, ACK/ACK_ECN, CRYPTO or CONNECTION_CLOSE
  (RFC 9000 12.4); at most min(max_headers,128) non-padding frames and ACK
  ranges; CRYPTO offsets+lengths <= 16384. Any other frame type leaves the
  identification with `initial_protection=unverified`.
- CRYPTO fragments are assembled from offset zero; a complete type-1 handshake
  message is validated with the TLS ClientHello profile (SNI/ALPN syntax). With
  a host-owned `QuicAssembler` (Analyzer creates one, bounded by the UDP flow
  limit, LRU, <= 8 fragments and 16384 bytes per Destination Connection ID,
  cleared on capture gaps), a hello split across Initials completes on the
  later datagram. Otherwise `crypto_assembly=partial`.
- Output: encryption=quic, application_protocol unset, hostname/offered_alpn as
  client offers (`quic_sni`/`quic_alpn` provenance), evidence quic_version,
  packet_type, initial_protection, crypto_assembly, optional initial_token
  presence; JA4 with protocol `q` when fingerprints are enabled; `ssl-req-*`
  signature contexts under the tls family when contexts are retained.
  Connection IDs, tokens, packet numbers and random bytes are never emitted.
- Excluded: server Initials (keys depend on the client's original DCID),
  Handshake/0-RTT/1-RTT packets, Retry packets, key updates, ChaCha20 (Initial
  packets always use AES-128-GCM), HTTP/3 framing, connection tracking by CID,
  spoofing resistance. Decryption is a CPU cost of about 2 ms per 1200-byte
  Initial in pure Python; the host owns rate limiting (THREAT-MODEL T14).

Primary specifications: [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)
sections 12.2, 12.4, 17.2.2, 17.2.1; [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html)
sections 5.1, 5.2, 5.3, 5.4 and Appendix A (client Initial vector reproduced
byte for byte by the test helper); [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369.html)
sections 3.1-3.3 and Appendix A.2 (first 32 protected bytes reproduced);
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html), [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final),
[NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) (AES/GCM test vectors).

## Decoder expansion (v0.27)

v0.26 was dropped (the engine stays an application-layer classifier over TCP
and UDP). v0.27 adds 23 families and a text-ambiguity rule. All profiles are
initial-message framing checks: none claims a completed login, transfer, tunnel
or control session, and no name, path, key, cookie or credential is emitted.

### Shared text lines and bidirectional correlation

- `220 ...` server greetings are shared by SMTP and FTP; `USER`, `PASS`, `QUIT`,
  `NOOP`, `STAT`, `LIST`, `RETR`, `DELE` and `AUTH` client commands are shared by
  FTP and POP3; `* OK` without an explicit IMAP revision capability is only an
  IMAP candidate. Such a line yields `status=unknown` with one
  `ambiguous_candidates` evidence of strength `context` (never an identity).
  The session verdict intersects both directions' candidate sets: a single
  common family gives `status=correlated` (`220` + `USER` is `ftp`,
  `+OK` + `USER` is `pop3` because the greeting is exclusive, `220` + `EHLO` is
  `smtp` because EHLO identifies). Disjoint sets or one direction only remain
  `unknown-tcp`. Arguments are checked for printable framing (<= 512 bytes).
- Exclusive commands identify alone: FTP (`FEAT`, `PASV`, `TYPE A|I|E|L`,
  `STOR path`, `CWD path`, `PORT h1,h2,h3,h4,p1,p2` …), POP3 (`CAPA`, `UIDL`,
  `TOP n m`, `APOP name digest`, `RSET`, `STLS`), POP3 server status lines
  (`+OK`/`-ERR` with optional printable text), tagged IMAP client commands
  (`tag SP command`, tag `[A-Za-z0-9._-]{1,32}`, 34 known commands, argument
  presence rules, case-insensitive command names).

### Terminal, Windows and authentication

- **Telnet**: two complete negotiation commands (`IAC WILL|WONT|DO|DONT opt`,
  `IAC SB … IAC SE` <= 64 bytes, or a single-byte IAC command). A non-IAC byte
  first, an unknown command byte or an oversized subnegotiation rejects.
  `0xff 0xff` stays BGP.
- **SMB1**: NetBIOS session message type 0, 24-bit length >= 35, `\xffSMB`,
  `SMB_COM_NEGOTIATE` (0x72), zero status, request direction flag, word count
  0, byte count equal to the remainder, every dialect `0x02` + printable
  NUL-terminated string, <= min(max_headers, 32) dialects.
- **NetBIOS session service**: type 0x81, length exactly 68, two 34-byte names
  (`0x20` + 32 letters A..P + `0x00`). Names are decoded for shape only.
- **Kerberos** (TCP 4-byte length and UDP): `[APPLICATION 10|12]` AS-REQ/TGS-REQ
  wrapping one SEQUENCE of ordered context-specific fields, `pvno` 5,
  `msg-type` 10/12 agreeing with the tag, optional `padata` SEQUENCE OF
  (<= min(max_headers, 32) entries), non-empty `req-body`; definite BER lengths
  exactly filling the message; TCP length >= 40 without the extension bit.
  Principals, realms and pre-authentication data are not emitted.
- **TACACS+**: version 0xc0/0xc1, type 1..3, `seq_no` 1, reserved flags zero,
  body length 1..65535; unencrypted authentication START bodies must have
  consistent action, authen_type and field lengths. Bodies are otherwise
  opaque (normally obfuscated).

### VPN control channels

- **WireGuard** (UDP): type 1/2/3 with three zero reserved bytes and an exact
  size of 148/92/64 bytes; a type-1 sender index must be nonzero. Reported as
  `encryption=wireguard` with the message type; keys and MACs are not checked
  and no tunnel is claimed. Transport data (type 4) is not recognized.
- **OpenVPN**: client hard-reset control packets (`P_CONTROL_HARD_RESET_CLIENT_V2`
  opcode 7, `_V3` opcode 10) with key id 0, nonzero session id and either a plain
  layout (empty ACK array then packet id, 14 bytes) or a tls-auth layout with an
  HMAC of 16/20/28/32/48/64 bytes, packet id and timestamp. UDP yields
  `encryption=openvpn`; TCP uses the 2-byte length prefix (14..1500) and yields
  `application_protocol=openvpn`. Evidence `tls_auth=present|absent`.
- **PPTP**: Start-Control-Connection-Request, exactly 156 bytes, magic cookie
  0x1a2b3c4d, control message type 1, protocol version 0x0100, reserved zero,
  framing/bearer capability bits within RFC 2637, printable host/vendor names.
- **L2TPv2** (UDP): T, L and S bits set, version 2, reserved bits zero, length
  equal to the datagram, first AVP the mandatory Message Type with value SCCRQ
  (1), tunnel and session ids zero, AVP boundaries within the message and
  <= min(max_headers, 64) AVPs. L2TPv3 and data messages are outside scope.

### Discovery and telemetry (UDP)

- **SSDP**: `M-SEARCH * HTTP/1.1` with `MAN: "ssdp:discover"` and `ST`,
  `NOTIFY * HTTP/1.1` with `NT` and `NTS: ssdp:*`, or `HTTP/1.1 200 OK` with `ST`
  and `USN`; exactly one complete header block under the HTTP header budget.
  LOCATION, USN and server strings are not emitted.
- **NetFlow v5**: count 1..30, datagram exactly 24 + 48 x count, nonzero
  packet and octet counters, zero padding in each record.
  **NetFlow v9**: count 1..min(max_headers,128), at least one flowset, each
  4-byte aligned within the datagram, ids 2..255 reserved, template flowsets
  >= 8 bytes. **IPFIX**: version 10, length equal to the datagram and >= 20,
  sets 2/3/>=256 with lengths >= 4 inside the message, at least one set.
  Templates and records are not decoded.
- **sFlow v5**: IPv4 agent address, 1..min(max_headers,64) samples, each
  sample header type 1..4 with a 4-byte aligned length fitting the datagram,
  no trailing bytes.

### Industrial and building automation

- **Modbus/TCP**: MBAP protocol id 0, length 2..254, unit id, function code
  1..127; public function codes have fixed PDU lengths (1..6, 8 with 4 bytes;
  7, 11, 12, 17 empty), read quantities 1..2000 (coils) or 1..125 (registers),
  write-single-coil 0x0000/0xff00, multiple writes with a consistent byte count.
- **DNP3**: start 0x0564, length >= 5, header CRC and every 16-byte block CRC
  (DNP polynomial, inverted) verified, link function code within the request
  profile. `0x05 0x64` therefore leaves the SOCKS5 two-byte route.
- **BACnet/IP**: BVLC type 0x81, function <= 0x0c, length equal to the datagram;
  NPDU-carrying functions require version 1, zero reserved control bits,
  bounded DNET/SNET specifiers, hop count after a destination specifier, and
  an APDU type 0..7 (or a network message type). BVLC-Result and address
  entries must be 6 bytes.
- **ISO-TSAP** (RFC 1006 over TCP): TPKT version 3, length 11..1024, X.224
  connection request (0xe0) with class 0..4, unique parameters, TPDU size
  7..13, and at least one calling/called TSAP (0xc1/0xc2, 1..32 bytes).
  S7comm itself is not decoded. TPKT routing: a cookie, RDP negotiation
  request or bare request goes to RDP, otherwise to ISO-TSAP.
- **EtherNet/IP**: 24-byte encapsulation header (little-endian), commands
  ListServices/ListIdentity/ListInterfaces (no data), RegisterSession (4-byte
  body, protocol version 1, zero session handle), SendRRData/SendUnitData
  (session handle and >= 6-byte CPF body), zero status and options. The same
  profile applies to UDP ListIdentity/ListServices/ListInterfaces.
- **IEC 60870-5-104**: APCI start 0x68, length 4..253; the first TCP message
  must be a U-format frame (exactly one function bit, zero reserved octets);
  I and S frames are validated when framed but do not start a stream.

### Data infrastructure

- **Kafka**: request header with size >= 10, api key among ApiVersions(18),
  Metadata(3), Produce(0), Fetch(1), SaslHandshake(17), SaslAuthenticate(36),
  DescribeConfigs(32) with a version within the profile, nullable printable
  client id (<= 256 bytes), ApiVersions v3+ compact tagged fields and client
  software name. Selection happens at 8 bytes so fragments and whole feeds
  agree. Evidence `kafka_api_key`.
- **CQL** (Cassandra native protocol v4): request direction, reserved flag bits
  zero, opcode STARTUP (body 2..4096: string map of 1..16 printable entries
  containing `CQL_VERSION`, no trailing bytes) or OPTIONS (empty body).
  Protocol v3 and v5 are outside the profile.
- **RTP** (hint only): version 2, payload type outside 72..76, CSRC list,
  header extension and padding count within the datagram. A hint is required
  because the 12-byte fixed header is too weak for automatic selection.

### Deferred from the plan

mDNS/LLMNR (DNS multicast variants), S7comm above COTP and SMB1 session setup
were not added; they remain roadmap items.

Primary specifications: [RFC 959](https://www.rfc-editor.org/rfc/rfc959.html) (FTP),
[RFC 1939](https://www.rfc-editor.org/rfc/rfc1939.html) (POP3), [RFC 9051](https://www.rfc-editor.org/rfc/rfc9051.html) (IMAP commands),
[RFC 854](https://www.rfc-editor.org/rfc/rfc854.html)/[RFC 855](https://www.rfc-editor.org/rfc/rfc855.html) (Telnet),
[MS-CIFS 2.2.4.52 SMB_COM_NEGOTIATE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/25c8c3c9-58fc-4bb8-aa8f-0272dede84c5),
[RFC 1002 4.3.2](https://www.rfc-editor.org/rfc/rfc1002.html) (NetBIOS session request),
[RFC 4120 5.4.1](https://www.rfc-editor.org/rfc/rfc4120.html) (KDC-REQ), [RFC 8907](https://www.rfc-editor.org/rfc/rfc8907.html) (TACACS+),
[WireGuard whitepaper 5.4](https://www.wireguard.com/papers/wireguard.pdf),
[OpenVPN protocol](https://github.com/OpenVPN/openvpn/blob/master/doc/doxygen/doc_protocol_overview.h) and `ssl_pkt.h`,
[RFC 2637 2.1](https://www.rfc-editor.org/rfc/rfc2637.html) (PPTP SCCRQ), [RFC 2661 6.1](https://www.rfc-editor.org/rfc/rfc2661.html) (L2TP SCCRQ),
[UPnP Device Architecture 2.0 section 1](https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf) (SSDP),
[NetFlow v9 RFC 3954](https://www.rfc-editor.org/rfc/rfc3954.html), [IPFIX RFC 7011](https://www.rfc-editor.org/rfc/rfc7011.html),
[sFlow v5](https://sflow.org/sflow_version_5.txt), [Modbus Application Protocol V1.1b3 and Modbus/TCP](https://modbus.org/specs.php),
[IEEE 1815 (DNP3) data link layer](https://standards.ieee.org/ieee/1815/5414/), [ASHRAE 135 Annex J (BACnet/IP)](https://www.ashrae.org/technical-resources/bookstore/bacnet),
[RFC 1006](https://www.rfc-editor.org/rfc/rfc1006.html) and [ITU-T X.224 13.3](https://www.itu.int/rec/T-REC-X.224) (ISO-TSAP),
[EtherNet/IP encapsulation (ODVA CIP Volume 2)](https://www.odva.org/technology-standards/key-technologies/ethernet-ip/),
[IEC 60870-5-104 APCI](https://webstore.iec.ch/publication/25035),
[Kafka protocol guide](https://kafka.apache.org/protocol.html), [CQL binary protocol v4](https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v4.spec),
[RFC 3550 5.1](https://www.rfc-editor.org/rfc/rfc3550.html) (RTP).
