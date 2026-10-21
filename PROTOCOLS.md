# Protocol coverage — v0.32

The engine implements 70 families (63 selected automatically from the first
bytes, 7 only with an explicit candidate hint or a structural shift) with the
profiles below. This table is generated from
`protocol_engine.catalog.supported_protocols()` (`python3 -B protodetect.py
protocols`) and is a complete inventory of this release, not a claim to
recognize every protocol or application. All input must start at the supported
message/stream boundary; no port-only match. Sections below record each
milestone's exact profile and exclusions; the newest additions (v0.27
decoders, v0.28 shifts, v0.29 heuristics, v0.32 S7comm) are at the end.

| Family | Transport | Selection | Observation scope | Implemented profile |
|---|---|---|---|---|
| amqp | tcp | Automatic profiles | protocol_header | Plain 0-9-1/1.0 version header only |
| bacnet | udp | Automatic profiles | datagram | BVLC function/length and NPDU version/control framing |
| bgp | tcp | Automatic profiles | negotiation_request | BGPv4 OPEN, standard optional lengths and capability framing |
| bittorrent | tcp | Automatic profiles | initial_message | 68-byte peer handshake; encrypted transport unsupported |
| coap | udp | Automatic profiles | datagram | CoAP v1 framing, token <=8; tiny messages require coap hint |
| cql | tcp | Automatic profiles | protocol_header | Cassandra native protocol v4 STARTUP/OPTIONS |
| dcerpc | tcp | Automatic profiles | bind_request | Connection-oriented v5.0 unfragmented Bind, NDR 2.0/NDR64 1.0 offers; no authentication, replies, stub decoding or product identity |
| dhcp | udp | Automatic profiles | datagram | DHCPv4 types 1..8, no overloaded options |
| dnp3 | tcp | Automatic profiles | protocol_header | Data link frame with header and block CRCs verified |
| dns | tcp/udp | Automatic profiles | initial_message/datagram | QUERY opcode, one question; TCP length prefixes >=512 require dns hint |
| dtls | udp | Automatic profiles | datagram | DTLS1.2 complete epoch-zero ClientHello in one record/datagram; bounded extensions, client assertions only; no fragments, negotiation or decryption |
| ethernet-ip | tcp/udp | Automatic profiles | protocol_header/datagram | Encapsulation header with RegisterSession/list/data commands; CIP not decoded |
| fastcgi | tcp | Automatic profiles | initial_params | v1 BEGIN_REQUEST plus complete PARAMS stream; one request, zero reserved fields, no response/body semantics |
| ftp | tcp | Automatic profiles | initial_message | Client command line (FTP-only verbs); shared USER/PASS/QUIT verbs are ambiguous with POP3 and resolved by session correlation with a 220 greeting |
| giop | tcp | Automatic profiles | request_header/locate_request | GIOP 1.2 unfragmented KeyAddr Request/LocateRequest; bounded CDR, opaque arguments and service contexts; no replies or object identity |
| git | tcp | Automatic profiles | service_request | Native Git pkt-line service request; bounded pathname, optional DNS/IPv4 host and extra parameters; no packfile, server or negotiated-version validation |
| http | tcp | Automatic profiles | initial_message | HTTP/1.0 and 1.1 start-line/headers |
| http2 | tcp | Automatic profiles | initial_message | Client preface plus initial SETTINGS; no HPACK |
| iec-104 | tcp | Automatic profiles | protocol_header | APCI U-format start frames automatically; I/S formats with a hint |
| ikev2 | udp | Automatic profiles | datagram | IKE_SA_INIT initiator: bounded SA/KE/nonce, AES-CBC/GCM and MODP14..18 offers, optional non-ESP marker; no authentication or established IPsec claim |
| imap | tcp | Automatic profiles | protocol_header | Server CAPABILITY or OK/PREAUTH with explicit IMAP4rev1/2 capability; no commands/authentication |
| ipfix | udp | Automatic profiles | datagram | IPFIX (RFC 7011) message header and set framing, validated by the shared flow-export validator |
| iso-tsap | tcp | Automatic profiles | negotiation_request | TPKT/X.224 connection request with TSAP parameters (RFC 1006); shares the TPKT route with RDP |
| kafka | tcp | Automatic profiles | request_header | Request header for ApiVersions/Metadata/Produce/Fetch/SaslHandshake and similar first requests |
| kerberos | tcp/udp | Automatic profiles | initial_message/datagram | KDC AS-REQ/TGS-REQ ASN.1 framing (pvno 5, msg-type, req-body); principals and pre-authentication unverified |
| l2tp | udp | Automatic profiles | datagram | L2TPv2 SCCRQ control message with Message Type AVP first |
| ldap | tcp | Automatic profiles | initial_message | LDAPv3 BindRequest, simple/SASL; no controls or searches |
| memcached | tcp | Automatic profiles | initial_message | Selected binary request commands 0x00..0x10; no SASL/text/meta |
| modbus | tcp | Automatic profiles | request_header | MBAP header and public function request PDU shapes; transaction ids above 0x01ff need a hint |
| mongodb | tcp | Hint required | initial_message | Hint required: uncompressed OP_MSG body/sequences, bounded BSON and CRC-32C; no telemetry or command semantics |
| mqtt | tcp | Automatic profiles | initial_message | 3.1.1/5.0 CONNECT; MQTT5 CONNECT/Will property validation |
| mysql | tcp | Hint required | protocol_header | Hint required: modern HandshakeV10, 21-byte challenge and native/caching_sha2/sha256 plugin |
| nats | tcp | Automatic profiles | protocol_header | INFO/CONNECT with required typed JSON fields; bounded extensions, no message bodies |
| netbios-ss | tcp | Automatic profiles | negotiation_request | NetBIOS session request with two first-level encoded names; names not emitted |
| netflow | udp | Automatic profiles | datagram | NetFlow v5 record framing and NetFlow v9 flowsets (reported as netflow/5, netflow/9) |
| ntp | udp | Hint required | datagram | Hint required: v3/v4 base client/server header, no extensions/authentication |
| openvpn | tcp/udp | Automatic profiles | initial_message/datagram | Client hard-reset control packet (plain or tls-auth layout); no key exchange claim |
| opcua | tcp | Automatic profiles | negotiation_request/negotiation_response | OPC UA TCP connection messages Hello, Acknowledge, Error and ReverseHello: little-endian size, buffer minimums, bounded printable opc.tcp URLs and reasons (not emitted); no secure channel |
| pop3 | tcp | Automatic profiles | protocol_header/initial_message | Server +OK/-ERR status line or POP3-only client command; shared verbs resolved by correlation |
| postgresql | tcp | Automatic profiles | initial_message/negotiation_request | v3.0..3.2 startup or SSL/GSS request; no authentication |
| pptp | tcp | Automatic profiles | negotiation_request | Start-Control-Connection-Request (156 bytes); names not emitted |
| quic | udp | Automatic profiles | datagram | QUIC v1/v2 Initial (client protection removed with public Initial keys; ClientHello SNI/ALPN as offers) and Version Negotiation; no handshake completion, server packets or 0-RTT |
| radius | udp | Hint required | datagram | Hint required: Access-Request PAP/CHAP/State with supported attributes; no authenticator verification or EAP |
| rdp | tcp | Automatic profiles | negotiation_request | TPKT/X.224 with RDP negotiation, optional cookie/correlation; no routing token or session |
| resp | tcp | Automatic profiles | initial_message | Non-null bulk-string request array; no product inference |
| rfb | tcp | Automatic profiles | protocol_header | RFB 3.3/3.7/3.8 banner; no VNC security exchange |
| rsync | tcp | Automatic profiles | protocol_header | Daemon greeting, final protocols 27..32; version/digest offers, no authentication or transfer |
| rtp | udp | Hint required | datagram | Hint required: RTP v2 fixed header, CSRC and extension framing |
| rtsp | tcp | Automatic profiles | initial_headers | RTSP/1.0 and 2.0 header framing; no RTP/media decoding |
| s7comm | tcp | Hint required | protocol_header | One S7 PDU in a COTP data TPDU after the ISO-TSAP connection (reached by the cotp-connect shift or an explicit candidate): header, ROSCTR, public function codes, setup communication fields; addresses and values not decoded |
| sflow | udp | Automatic profiles | datagram | sFlow v5 datagram with IPv4 agent and bounded sample headers |
| sip | tcp/udp | Automatic profiles | initial_headers/datagram | SIP/2.0 required header framing; no dialogue/body semantics |
| smb1 | tcp | Automatic profiles | negotiation_request | NetBIOS session header plus SMB_COM_NEGOTIATE request with dialect strings; maps to the smb application |
| smb2 | tcp | Automatic profiles | negotiation_request | Direct TCP SMB2/3 NEGOTIATE including 3.1.1 context framing; offers only |
| smtp | tcp | Automatic profiles | initial_message | EHLO/HELO only; ambiguous 220 banners unknown |
| snmp | udp | Automatic profiles | datagram | v1/v2c Get/GetNext/GetBulk read requests; v3 messages (USM header, plaintext read/report or encrypted scoped PDU); no responses or traps |
| socks5 | tcp | Automatic profiles | initial_message/negotiation_response | Client no-auth offer plus request, or server method selection plus reply; subnegotiation and tunnel unverified |
| ssdp | udp | Automatic profiles | datagram | M-SEARCH/NOTIFY/response HTTPU header block with SSDP headers |
| ssh | tcp | Automatic profiles | initial_message | Leading SSH-2.0/1.99 identification |
| stomp | tcp | Automatic profiles | protocol_header | 1.1/1.2 CONNECT/STOMP/CONNECTED, complete empty-body NUL-terminated frame |
| stun | tcp/udp | Automatic profiles | initial_message/datagram | Binding method; attributes and optional fingerprint, no HMAC validation |
| syslog | udp | Automatic profiles | datagram | RFC5424 version 1 header/structured data; no RFC3164 |
| tacacs-plus | tcp | Automatic profiles | protocol_header | TACACS+ header for the first packet of a session; START body lengths when unencrypted |
| tds | tcp | Automatic profiles | negotiation_request/negotiation_response | MSSQL TDS 7.x PRELOGIN packet (client) or its response (server): header, option table, VERSION/ENCRYPTION mandatory, fixed option lengths; instance names, thread, trace and nonce bytes not emitted; no LOGIN7 or query stream |
| telnet | tcp | Automatic profiles | negotiation_request | Two complete IAC option negotiation commands; terminal data not inspected |
| tftp | udp | Automatic profiles | datagram | RRQ/WRQ with bounded options; no transfer state |
| tls | tcp | Automatic profiles | initial_message/server_hello/hello_retry_request | ClientHello plus bounded TLS1.2/1.3 server hello/retry profiles; optional leaf-certificate structure after a TLS 1.2 ServerHello (`certificates`); selections unauthenticated, no decryption |
| tns | tcp | Automatic profiles | negotiation_request/negotiation_response | Oracle Net CONNECT (client) or ACCEPT/REFUSE/RESEND (server) packet: header checksums zero, versions 308..319, connect data offset/length consistency, printable descriptor; descriptor contents not emitted; no DATA packets or authentication |
| websocket | tcp | Hint required | frame_header | One frame header after an HTTP Upgrade boundary (reached by the websocket-upgrade shift or an explicit candidate); payload not decoded |
| wireguard | udp | Automatic profiles | datagram | Handshake initiation/response/cookie message sizes and reserved bytes; no key or tunnel claim |

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
| NTS, SNMP responses/traps and others | Protocol-specific validation and evidence rules, especially for weak short headers (RTP is hinted since v0.27, SNMPv3 messages since v0.38) |
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

## Application shift at structural boundaries (v0.28)

Some initial messages announce that a different protocol follows them. The
engine now ends the carrier's inspection exactly at that boundary and inspects
the bytes after it as a new phase ("application shift"). Rules:

- The carrier identification is published first and is never removed. If the
  shifted phase identifies, the observation becomes the new protocol with
  `shift=<boundary>` and `shift_from=<carrier protocol>` structural evidence and
  an event of kind `shifted`; the carrier's asserted hostname (CONNECT/Host) is
  kept only when the new phase offers none. If the shifted phase ends unknown,
  malformed, incomplete or out of budget, the carrier stays identified with
  `shift` plus `shifted_payload=<status>` context evidence.
- Both phases share one byte budget (`max_bytes`) and one update budget; the
  shifted phase runs the same dispatch and parsers, restricted to the family the
  boundary promises where the protocol defines it (TLS after STARTTLS/SSLRequest/
  RDP negotiation, WebSocket after `Upgrade: websocket`, HTTP/2 preface after
  `Upgrade: h2c`), unrestricted after CONNECT. The restriction is a candidate
  selection, not an identification: a non-TLS payload after STARTTLS is
  `shifted_payload=unknown`.
- Boundaries are structural, never port-based, and each direction decides from
  its own bytes. The session verdict combines them: `ssl` after CONNECT carries
  `shifted_from=http-proxy`, STARTTLS `shifted_from=smtp|imap|pop3|ftp`, and the
  carrier is added to `implicitly_uses`; `port_usage` is standard when the port
  is standard for either the new application or the carrier (587 for ssl after
  smtp STARTTLS).

| Boundary | Carrier profile addition | Phase after |
|---|---|---|
| `http-connect` | `CONNECT authority HTTP/1.x` with an authority-form target (`host:port`, bracketed IPv6 allowed); scope `tunnel_request`, evidence `http_method=CONNECT`; verdict application `http-proxy`. A CONNECT with a path target stays plain HTTP without a shift | any protocol (unrestricted) |
| `websocket-upgrade` | request: `GET`, `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key` (22 base64 chars + `==`), `Sec-WebSocket-Version: 13`, no body; response: `101` with `Upgrade: websocket` and `Sec-WebSocket-Accept` (27 chars + `=`). Missing pieces are malformed | `websocket` |
| `h2c-upgrade` | request with `Upgrade: h2c`, `Connection: Upgrade`, `HTTP2-Settings` (base64url); since v0.36 also the `101` response with `Upgrade: h2c` and `Connection: Upgrade`, after which the server's first frame is a non-ACK SETTINGS on stream 0 without any preface (`http2-server`, a shift-only parser with the same SETTINGS rules and no fingerprint) | `http2` (client preface + SETTINGS) / `http2-server` (SETTINGS only) |
| `starttls` | SMTP: after EHLO/HELO the client direction keeps reading command lines (<= 512 bytes each, known verbs only, at most min(max_headers, 8) NOOPs) until `STARTTLS` (shift), any other command (watch ends) or an unexpected line (watch ends, identification stands). IMAP `tag STARTTLS`, POP3 `STLS` shift immediately | `tls` |
| `auth-tls` | FTP `AUTH TLS|SSL|TLS-C|TLS-P` (RFC 4217 names are FTP-only, so the shared `AUTH` verb identifies FTP here) | `tls` |
| `postgresql-sslrequest` | SSLRequest (80877103, 8 bytes). GSSENCRequest does not shift | `tls` |
| `mysql-sslrequest` | Client packet with sequence 1 and 32-byte payload: capabilities with CLIENT_PROTOCOL_41 and CLIENT_SSL, nonzero character set, 19 zero reserved bytes (the last four may carry MariaDB extended capabilities). MySQL remains a hint-only family | `tls` |
| `rdp-negotiation` | Client X.224 CR whose RDP_NEG_REQ offers any protocol other than standard RDP security (TLS, CredSSP, RDSTLS, AAD). New: server X.224 Connection Confirm (0xd0, nonzero DST-REF, class 0) with RDP_NEG_RSP (type 2, flags <= 0x1f, exactly one selected protocol; shift when nonzero) or RDP_NEG_FAILURE (type 3, code 1..6, no shift); scope `negotiation_response` | `tls` |

**WebSocket** (new family, reached only through the boundary or an explicit
candidate): one frame header per RFC 6455 5.2: RSV bits zero, opcode text/
binary/close/ping/pong (a continuation frame cannot open a stream; reserved
opcodes are malformed), minimal length encoding (16-bit >= 126, 64-bit >= 65536
with the high bit clear), control frames unfragmented and <= 125 bytes, masking
key present when the MASK bit is set. Evidence `websocket_opcode`,
`websocket_masked`. Payload bytes are not read.

Excluded: server-side CONNECT (a `200` cannot be told from a body-less response
without the request), `Upgrade: TLS`
(RFC 2817), SMTP server `220 Go ahead` correlation, RDP standard security after
a TLS offer (the shifted bytes are then `unknown`), nested shifts beyond one
boundary per direction, and any claim that the TLS handshake inside the tunnel
completed.

Primary specifications: [RFC 9110 9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#name-connect) (CONNECT),
[RFC 9110 7.8](https://www.rfc-editor.org/rfc/rfc9110.html#name-upgrade) (Upgrade), [RFC 6455 4.1, 4.2.2, 5.2](https://www.rfc-editor.org/rfc/rfc6455.html),
[RFC 7540 3.2](https://www.rfc-editor.org/rfc/rfc7540.html#section-3.2) (h2c upgrade), [RFC 3207](https://www.rfc-editor.org/rfc/rfc3207.html) (SMTP STARTTLS),
[RFC 2595 3, 4](https://www.rfc-editor.org/rfc/rfc2595.html) (IMAP STARTTLS, POP3 STLS), [RFC 4217](https://www.rfc-editor.org/rfc/rfc4217.html) (FTP AUTH TLS),
[PostgreSQL SSLRequest](https://www.postgresql.org/docs/18/protocol-message-formats.html),
[MySQL Protocol::SSLRequest](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_ssl_request.html),
[MS-RDPBCGR 2.2.1.2 Server X.224 Connection Confirm PDU](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/13757f8f-66db-4273-9d2c-385c33b1e483).

## Unknown-traffic heuristics and flow risks (v0.29)

Nothing in this milestone identifies an application. Two additions describe
what the engine could not identify, and one attaches advisory flags.

- **Payload heuristics** (`Config(heuristics=True)`, default off): a TCP prefix
  that no family selects is collected up to `heuristic_bytes` (default 512)
  before the `unknown` observation is published; a UDP datagram no validator
  accepts is profiled as a whole within the same bound. The observation gains
  `payload_class`, `payload_entropy`, `payload_printable` and
  `payload_bytes_profiled` evidence of strength `heuristic` (thresholds in
  RISKS.md). Status stays `unknown`; verdicts stay `unknown-tcp`/`unknown-udp`.
  Parsers that selected a family and then rejected the message are not
  profiled: their reason already names the violated profile.
- **DNS query-name shape** (heuristics on): `dns_query_shape`
  (`ordinary`/`suspicious`), `dns_query_labels`, `dns_query_longest_label`,
  `dns_label_entropy`. The name is not emitted.
- **New structural evidence, always on**: TLS ClientHello `tls_offered_max_version` (`supported_versions` wins over the legacy
  field, GREASE ignored); SSH `ssh_version` (`2.0` or `1.99`).
- **Flow risks**: `Verdict.risks`, a sorted tuple from the table in RISKS.md
  (`nonstandard-port`, `cleartext-credential-protocol`, `obsolete-protocol`,
  `tls-legacy-version-offer`, `tls-missing-sni`, `unknown-high-entropy-payload`,
  `malformed-protocol`, `dns-suspicious-query-name`, `http-proxy-tunnel`,
  `desktop-or-file-sharing-session`). Session records, offline/live
  classification events and live summaries carry them.

Excluded: certificate checks, cipher-strength assessment, beaconing or
periodicity analysis, scan detection, learned byte-distribution models, and
any risk needing more than the initial message (RISKS.md).

Primary references: [nDPI flow risks](https://github.com/ntop/nDPI/blob/dev/doc/flow_risks.rst)
(vocabulary), [RFC 8446 4.2.1](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.1) (supported_versions precedence),
[RFC 8701](https://www.rfc-editor.org/rfc/rfc8701.html) (GREASE values), [RFC 4253 4.2](https://www.rfc-editor.org/rfc/rfc4253.html#section-4.2) (SSH version string),
Shannon entropy over a byte histogram (standard definition; no external model).

## S7comm after the ISO-TSAP connection (v0.32)

- **ISO-TSAP** now also validates the server's X.224 Connection Confirm
  (0xd0): length byte, nonzero destination reference, class 0..4, unique
  parameters with the TPDU-size/TSAP rules of the request; a confirm without
  parameters is outside the profile. Requests must carry a zero destination
  reference. The TPKT route sends a 0xd0 body to RDP only when it carries an
  RDP_NEG_RSP/RDP_NEG_FAILURE (type 2/3, length 8), otherwise to ISO-TSAP.
- Both the request and the confirm announce the `cotp-connect` shift: the
  bytes after them are inspected as **s7comm** only (a candidate restriction,
  not an identification). A failed or missing S7 phase leaves `iso-tsap`
  identified with `shifted_payload` context, as for every shift.
- **S7comm** (new family, reached through the shift or an explicit candidate):
  TPKT (length 17..8192) + COTP data TPDU `02 f0 80` + S7 header with protocol
  id 0x32, ROSCTR job/ack/ack-data/userdata, zero reserved field, parameter
  and data lengths that fill the PDU exactly (ack/ack-data add the two error
  bytes, error class <= 0x8f). Job and ack-data parameters start with a public
  function code (CPU services, read/write var, download/upload family, PLC
  control/stop, setup communication); setup communication is exactly eight
  bytes with queue sizes 1..255 and a PDU length from {240, 480, 960, 1920,
  2048, 4096, 8192}; userdata needs at least eight parameter bytes. Evidence
  `s7_rosctr`, `s7_function`. Item addresses, values, block names and
  passwords are not decoded or emitted. Catalog: `s7comm` (business-systems/
  ics-protocol, tcp/102, aliases `s7`, `siemens-s7`), implicitly uses
  `iso-tsap`.
- Excluded: S7comm-plus (S7-1200/1500 0x72 protocol), fragmented PDUs,
  response correlation, authentication state.

Primary specifications: [RFC 1006](https://www.rfc-editor.org/rfc/rfc1006.html), [ITU-T X.224 13.4 (CC TPDU)](https://www.itu.int/rec/T-REC-X.224),
S7comm protocol as documented by the [Wireshark S7comm dissector](https://wiki.wireshark.org/S7comm) and
[Snap7](https://snap7.sourceforge.net/) (public PDU layout; no vendor specification is reproduced).

## Server-side CONNECT correlation (v0.33)

A `2xx` answering a `CONNECT` cannot be told from a body-less reply by the
server direction alone, so v0.28 left the server side of a tunnel at
`http/1.x`. The Analyzer now correlates both directions of a connection: when
the client direction carries `http_method=CONNECT` (or has already shifted at
`http-connect`) and the server direction is identified HTTP with
`http_status` 200..299, the host opens the `http-connect` shift on the server
Inspector (`Inspector.open_shift`, shift evidence source `wire:peer`). The
server's later bytes are inspected as the tunnel, typically a TLS ServerHello,
which brings `selected_tls_version`, JA3S/JA4S and the TLS server risks into
the session; `server_protocol` becomes `tls`. Nothing is retracted: the HTTP
identification stands until the shifted phase publishes, and a tunnel whose
server bytes match nothing leaves `http/1.x` with `shifted_payload` context.
A 3xx/4xx/5xx answer, a plain request or an unobserved direction opens
nothing. HTTP responses now carry `http_status` evidence. Capture order does
not matter: the check runs on every identification in either direction.

## SNMPv3 messages (v0.38)

The `snmp` family now also validates version-3 messages (RFC 3412 section 6,
USM parameters per RFC 3414): `msgGlobalData` with `msgID >= 0`,
`msgMaxSize >= 484`, a one-byte `msgFlags` with reserved bits clear and no
privacy without authentication, `msgSecurityModel >= 1`;
`msgSecurityParameters` as the USM SEQUENCE (engine id <= 32 bytes, boots and
time >= 0, user <= 32, authentication parameters <= 64 and present when the
auth flag is set, privacy parameters <= 32 and present when the priv flag is
set) or, for other models, an opaque string <= 256 bytes; then either an
encrypted scoped PDU (non-empty OCTET STRING, required when priv is set) or a
plaintext ScopedPDU (context engine and name <= 32 bytes) carrying a
Get/GetNext/GetBulk request with NULL values or a Report PDU with one value per
binding, <= 128 bindings. Reported as `snmp/3` with structural evidence
`snmp_security` (`usm` or `model-N`), `snmp_scoped_pdu` (`plaintext`/
`encrypted`) and `snmp_flags`. User names, engine ids, authentication/privacy
parameters, context names and values are never emitted. Set, Inform, Trap and
Response PDUs, SNMPv3 over TCP and key or digest verification are outside the
profile; the v1/v2c read-request profile is unchanged (both now share the PDU
walk).

Primary specifications: [RFC 3412 6](https://www.rfc-editor.org/rfc/rfc3412.html#section-6),
[RFC 3414 2.4](https://www.rfc-editor.org/rfc/rfc3414.html#section-2.4), [RFC 3416](https://www.rfc-editor.org/rfc/rfc3416.html).

## TLS 1.2 server certificate structure (v0.39)

With `Config(certificates=True)` (`--certificates`), a direction identified by
a TLS 1.2 ServerHello keeps its parser as a continuation and reads the
handshake records that follow until the first entry of the Certificate message
(type 11) is complete. The leaf is walked as DER (RFC 5280 section 4.1): every
element length is checked against its container before any byte is read,
definite minimal lengths only, version `[0]` v2/v3 when present, serial 1-32
octets, AlgorithmIdentifier, issuer and subject Names as SEQUENCE OF SET OF
SEQUENCE { OID, value } with at most 32 components each, Validity as UTCTime or
GeneralizedTime with seconds in UTC and `notAfter >= notBefore`,
SubjectPublicKeyInfo (RSA modulus/exponent framing, named-curve EC point
length, Ed25519/Ed448 sizes), optional unique identifiers (v2+) and extensions
(v3 only, at most 64, each OID + optional BOOLEAN + OCTET STRING), then an
outer signature AlgorithmIdentifier identical to the inner one and a signature
BIT STRING with no unused bits. The leaf is at most 16 KiB; the watch shares
the direction's `max_bytes` budget and never reads past it, and later chain
entries are not read at all.

Evidence (source `wire:certificate`): `tls_certificate_chain` (`single`/`chain`
from the list lengths, structural) and, asserted by the server,
`tls_certificate_version` (1-3), `tls_certificate_self_issued` (`yes` when the
issuer DER equals the subject DER), `tls_certificate_key` (`rsa-N`, `ec-256`,
`ec-384`, `ec-521`, `ec-other`, `ed25519`, `ed448`, `other`),
`tls_certificate_signature` (`md5-rsa`, `sha1-rsa`, `sha256-rsa`, `sha384-rsa`,
`sha512-rsa`, `rsa-pss`, `ecdsa-sha1`, `ecdsa-sha256/384/512`, `ed25519`,
`ed448`, `other`) and `tls_certificate_lifetime_days`. Issuer, subject, serial,
alternative names, key bytes and signature bytes are never emitted. RISKS.md
derives `tls-self-issued-certificate`, `tls-weak-certificate-key`,
`tls-weak-certificate-signature` and `tls-certificate-lifetime-excessive`.

Anything else after the ServerHello (a ChangeCipherSpec record of an
abbreviated handshake, an alert, ServerHelloDone first, an empty list, length
disagreements, any DER violation, a leaf beyond the budget) ends the
continuation quietly: the ServerHello identification and its evidence stand
(SR-21) and no certificate field appears. TLS 1.3 encrypts its Certificate
message and HelloRetryRequest precedes a second ClientHello, so neither starts
the watch. Nothing is verified: no signature, chain, name match, revocation or
expiry check (the engine has no clock; the lifetime is reported for policy).

Primary specifications: [RFC 5246 7.4.2](https://www.rfc-editor.org/rfc/rfc5246.html#section-7.4.2),
[RFC 5280 4.1](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1), [RFC 5480](https://www.rfc-editor.org/rfc/rfc5480.html),
[RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html).

## Enterprise database negotiation: MSSQL TDS and Oracle Net (v0.40)

`tds` (MS-TDS 2.2.6.5) accepts a PRELOGIN packet from the client (type 0x12)
or its tabular response from the server (type 0x04): status with the EOM bit
and no bits outside 0x1b, window zero, SPID zero on the client packet, length
20..4096 covering the whole packet, then an option table of 5-byte entries
(token, offset, length) ended by 0xff. Tokens 0x00..0x07 may appear once each
in any order; VERSION (6 bytes) and ENCRYPTION (1 byte, OFF/ON/NOT_SUP/REQ) are
mandatory; INSTOPT is a terminated string, THREADID 0 or 4 bytes, MARS and
FEDAUTHREQUIRED 0/1, TRACEID 36 bytes (empty in a response), NONCE 32 bytes.
Every data region lies after the table and inside the packet, and nothing
follows the last datum. Evidence: `tds_encryption`, `tds_mars`,
`tds_federated_auth` (offered). Driver versions, instance names, thread and
trace identifiers and nonces are never emitted. LOGIN7, TLS carried inside
TDS packets, TDS 8.0 strict (which starts with a plain TLS ClientHello and is
identified as `tls`) and the query stream are outside the profile. Prefix: a
first byte 0x12 routes to `tds`; a type-4 packet routes to `tds` instead of
`cql` when its status has the EOM bit, the window byte is zero and the first
payload byte is the VERSION token, which a CQL request cannot produce without
a body of at least 64 KiB.

`tns` (Oracle Net, SQL*Net) accepts the first packet of either direction: an
8-byte header with packet checksum, reserved byte and header checksum all zero
and length 8..8192, then CONNECT (type 1: version 308..319, version-compatible
300, byte-order marker 0x0001/0x0100, connect data length >= 1, offset 34..74,
descriptor either absent from this packet (`deferred`, sent in a following
DATA packet) or exactly filling it as a printable string starting with `(`),
ACCEPT (type 2: version in range, marker, data region inside the packet),
REFUSE (type 4: data length matching, printable `(`-descriptor when present)
or RESEND (type 11: header only). Evidence: `tns_version` (asserted),
`tns_connect_data` (`inline`/`deferred`), `tns_response`
(`accept`/`refuse`/`resend`). Service names, hosts, programs, users, error
descriptors and reason codes are never emitted. DATA packets, O5LOGON
authentication, redirects and marker/attention packets are outside the
profile. Prefix: a header whose checksum, reserved and header-checksum bytes
are zero with one of the four types (and the version bytes for CONNECT/ACCEPT)
routes to `tns` ahead of the length-prefixed families sharing a leading 0x00
byte; DNS over TCP (question count 1), Modbus (length 2..254) and PostgreSQL
(protocol 3 or request codes) cannot match that header.

Primary specifications: [MS-TDS 2.2.6.5](https://learn.microsoft.com/openspecs/windows_protocols/ms-tds/60f56408-0188-4cd5-8b90-25c6f2423868);
Oracle Net has no public specification, the framing follows the Wireshark TNS dissector and observed clients.

## OPC UA connection messages and the SOCKS5 server direction (v0.41)

`opcua` (OPC 10000-6 section 7.1) accepts one connection-protocol message:
three-letter type `HEL`, `ACK`, `ERR` or `RHE`, chunk type `F`, a
little-endian message size of 8..8208 bytes covering the whole message. Hello
and Acknowledge carry ProtocolVersion, receive and send buffer sizes of at
least 8192, MaxMessageSize and MaxChunkCount; Hello adds an EndpointUrl, a
non-null printable string of at most 4096 bytes with the `opc.tcp://` scheme.
Error carries a status code whose severity bit says Bad and a reason string
(null or printable, at most 4096 bytes). ReverseHello carries a ServerUri
(null or printable) and an `opc.tcp://` EndpointUrl. Each message must end
exactly where its last field ends. Evidence: `opcua_message` (`hello`,
`acknowledge`, `error`, `reverse-hello`) and `opcua_protocol_version` for
Hello/Acknowledge. URLs, URIs, reasons and status codes are never emitted.
Secure-channel messages (`OPN`, `MSG`, `CLO`), chunking and security policies
are outside the profile. Prefix: `HELF`/`ACKF`/`ERRF`/`RHEF` followed by a size
whose two high bytes are zero routes to `opcua`; the same four letters followed
by a space remain HTTP extension methods or SMTP (`HELO`) text, and the
decision waits for the fourth byte only for prefixes of those magics.

`socks5` now also accepts the server direction: the method selection
(`05 00` no authentication or `05 02` username/password) immediately followed
by the complete reply (`05 REP 00 ATYP BND.ADDR BND.PORT`, REP 0..8, IPv4,
domain or IPv6 bound address). Evidence: `socks_method` and `socks_reply`
(`succeeded`, `general-failure`, `not-allowed`, `network-unreachable`,
`host-unreachable`, `connection-refused`, `ttl-expired`,
`command-not-supported`, `address-type-not-supported`); the bound address is
never emitted. A client greeting offering two methods is told apart from a
username/password selection by byte 4 (request version 5 versus the reply's
reserved zero); `05 ff` alone (no acceptable methods) never identifies, and
subnegotiation bytes stay outside the profile. Prefix: `05 00` now waits for
six bytes and routes to `socks5` when they read as a reply header, otherwise to
`dcerpc` (minor version zero) as before.

Primary specifications: [OPC 10000-6 7.1](https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1),
[RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.html).
