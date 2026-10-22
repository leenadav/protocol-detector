
## Direction coverage (generated, v0.48)

`tools/coverage_matrix.py` classifies every fixture (stream, datagram, hinted,
demo examples and the listed server-side fixtures) and attributes each
identified observation to the client or the server side by its scope, by
direction-bearing evidence (DNS message kind, SNMP PDU, DTLS handshake, RADIUS
code, OpenVPN control, IKE exchange, Kerberos message, TLS handshake) or by a
fixture explicitly declared as a server message. `same shape` marks families
whose initial message looks the same from either side; `n/a (one-way)` marks
exporter-to-collector families. CI fails when this table drifts from the
fixtures (`--check`); regenerate with `--write PROTOCOLS.md`. The evidence
column lists every field the fixtures make the engine emit, which is also the
closed set reviewers should expect in records.

<!-- coverage-matrix:start -->
| Family | Transports | Client | Server | Evidence fields |
|---|---|---|---|---|
| afp | tcp | yes | yes | `afp_command`, `dsi_message` |
| amqp | tcp | yes | yes | `amqp_message` |
| bacnet | udp | yes | same shape | - |
| bgp | tcp | yes | same shape | - |
| bittorrent | tcp | yes | same shape | - |
| bolt | tcp | yes | yes | `bolt_message`, `bolt_version` |
| coap | udp | yes | same shape | - |
| cql | tcp | yes | yes | `cql_response` |
| dcerpc | tcp | yes | yes | `accepted_transfer_syntax`, `dcerpc_pdu`, `offered_transfer_syntax` |
| dhcp | udp | yes | yes | `dhcp_message`, `dhcp_operation` |
| diameter | tcp | yes | yes | `diameter_message`, `diameter_result` |
| dnp3 | tcp | yes | same shape | - |
| dns | tcp/udp | yes | yes | `dns_message`, `dns_query_type`, `dns_rcode` |
| dtls | udp | yes | yes | `handshake`, `offered_dtls_version`, `selected_cipher`, `selected_cipher_mode`, `selected_dtls_version`, `selected_key_exchange` |
| ethernet-ip | tcp/udp | yes | same shape | `enip_command` |
| fastcgi | tcp | yes | yes | `fastcgi_record`, `fastcgi_role` |
| fins | tcp | yes | yes | `fins_frame`, `fins_message` |
| ftp | tcp | yes | - | - |
| giop | tcp | yes | yes | `giop_message`, `giop_status` |
| git | tcp | yes | yes | `git_message`, `offered_version` |
| http | tcp | yes | yes | `hostname`, `http_accept`, `http_auth_challenge`, `http_auth_scheme`, `http_content_type`, `http_method`, `http_status`, `http_upgrade` |
| http2 | tcp | yes | yes | `hostname`, `http2_content_type`, `http2_message`, `http2_method`, `http2_scheme`, `http2_status` |
| iec-104 | tcp | yes | same shape | - |
| ikev2 | udp | yes | yes | `exchange`, `offered_dh_group`, `selected_dh_group` |
| imap | tcp | yes | yes | - |
| ipfix | udp | yes | n/a (one-way) | - |
| irc | tcp | yes | - | `irc_message` |
| iso-tsap | tcp | yes | yes | - |
| kafka | tcp | yes | - | `kafka_api_key` |
| kerberos | tcp/udp | yes | yes | `kerberos_error`, `kerberos_message` |
| l2tp | udp | yes | yes | `l2tp_message` |
| ldap | tcp | yes | yes | `gss_mechanism`, `ldap_bind`, `ldap_extended`, `ldap_message`, `ldap_result`, `ntlm_message` |
| llmnr | udp | yes | yes | `dns_message`, `dns_query_type`, `dns_rcode`, `llmnr_flags` |
| mdns | udp | yes | yes | `dns_message`, `dns_query_type`, `dns_rcode`, `mdns_profile` |
| memcached | tcp | yes | yes | `memcached_message`, `memcached_status` |
| modbus | tcp | yes | yes | `modbus_exception`, `modbus_pdu` |
| mongodb | tcp | yes | yes | `mongodb_message` |
| mqtt | tcp | yes | - | - |
| mysql | tcp | yes | yes | `mysql_auth_plugin`, `mysql_client_ssl`, `mysql_tls_supported` |
| nats | tcp | yes | yes | - |
| netbios-ns | udp | yes | yes | `dns_message`, `dns_query_type`, `dns_rcode`, `nbns_opcode` |
| netbios-ss | tcp | yes | - | - |
| netflow | udp | yes | n/a (one-way) | - |
| ntp | udp | yes | yes | `ntp_mode` |
| onc-rpc | tcp/udp | yes | yes | `rpc_accept_status`, `rpc_credential`, `rpc_message`, `rpc_program`, `rpc_program_version`, `rpc_reject_status`, `rpc_reply` |
| opcua | tcp | yes | yes | `opcua_message`, `opcua_protocol_version` |
| openvpn | tcp/udp | yes | yes | `openvpn_control`, `tls_auth` |
| pop3 | tcp | yes | yes | - |
| postgresql | tcp | yes | yes | `postgresql_auth`, `postgresql_error_class`, `postgresql_message` |
| pptp | tcp | yes | yes | `pptp_message`, `pptp_result` |
| quic | udp | yes | - | `crypto_assembly`, `hostname`, `initial_protection`, `offered_alpn`, `packet_type`, `quic_version` |
| radius | udp | yes | yes | `radius_code` |
| rdp | tcp | yes | yes | `rdp_security_flags`, `rdp_selected_protocol` |
| resp | tcp | yes | - | - |
| rfb | tcp | yes | same shape | - |
| rip | udp | yes | yes | `rip_authentication`, `rip_command` |
| rsync | tcp | yes | - | `rsync_protocol` |
| rtcp | udp | yes | same shape | `rtcp_packet`, `rtcp_packets` |
| rtp | udp | yes | same shape | - |
| rtsp | tcp | yes | same shape | - |
| s7comm | tcp | yes | yes | `s7_function`, `s7_rosctr` |
| sflow | udp | yes | n/a (one-way) | - |
| sip | tcp/udp | yes | same shape | - |
| smb1 | tcp | yes | yes | `gss_mechanism`, `ntlm_message`, `smb1_dialect_layout`, `smb1_message`, `smb_session` |
| smb2 | tcp | yes | yes | `gss_mechanism`, `ntlm_message`, `smb_dialect`, `smb_message`, `smb_session`, `smb_signing` |
| smtp | tcp | yes | - | `smtp_client_identity` |
| snmp | udp | yes | yes | `snmp_flags`, `snmp_pdu`, `snmp_scoped_pdu`, `snmp_security` |
| socks5 | tcp | yes | yes | `socks_command`, `socks_method`, `socks_port`, `socks_reply`, `socks_target` |
| spice | tcp | yes | yes | `spice_channel`, `spice_link_error`, `spice_message` |
| ssdp | udp | yes | same shape | - |
| ssh | tcp | yes | same shape | `ssh_kex_class`, `ssh_terrapin`, `ssh_version`, `ssh_weak_algorithm` |
| stomp | tcp | yes | yes | - |
| stun | tcp/udp | yes | same shape | `stun_class`, `stun_method` |
| syslog | udp/tcp | yes | n/a (one-way) | `syslog_framing` |
| tacacs-plus | tcp | yes | yes | `tacacs_packet`, `tacacs_type` |
| tds | tcp | yes | yes | `tds_encryption`, `tds_federated_auth`, `tds_mars` |
| telnet | tcp | yes | same shape | - |
| tftp | udp | yes | yes | `tftp_packet` |
| tls | tcp | yes | yes | `hostname`, `offered_alpn`, `requested_group`, `selected_alpn`, `selected_cipher`, `selected_cipher_mode`, `selected_group`, `selected_key_exchange`, `selected_tls_version`, `tls_certificate_ca`, `tls_certificate_chain`, `tls_certificate_eku`, `tls_certificate_key`, `tls_certificate_lifetime_days`, `tls_certificate_not_after`, `tls_certificate_not_before`, `tls_certificate_san`, `tls_certificate_self_issued`, `tls_certificate_signature`, `tls_certificate_version`, `tls_ech`, `tls_handshake`, `tls_offered_max_version` |
| tns | tcp | yes | yes | `tns_connect_data`, `tns_response`, `tns_version` |
| websocket | tcp | yes | yes | `websocket_masked`, `websocket_opcode` |
| wireguard | udp | yes | yes | `message_type` |
| x11 | tcp | yes | yes | `x11_authorization`, `x11_byte_order`, `x11_message` |
| xmpp | tcp | yes | yes | `hostname`, `xmpp_namespace`, `xmpp_stream`, `xmpp_version` |
| zmtp | tcp | yes | yes | `zmtp_mechanism`, `zmtp_role` |

85 families in the catalog, 85 with fixtures, 72 proven on both sides (or symmetric), 4 one-way; server side still unproven: ftp, irc, kafka, mqtt, netbios-ss, quic, resp, rsync, smtp.
<!-- coverage-matrix:end -->

## Direction evidence and remaining replies (v0.49)

Families that already accepted both directions now say which side they saw:
`dhcp_operation` (`request`/`reply`) and `dhcp_message` (discover, offer,
request, decline, ack, nak, release, inform), `ntp_mode` (`client`/`server`),
`mongodb_message` (`request`/`reply`, from a nonzero responseTo; replies carry
scope `response_header` and skip the command-first rule), and the existing
WireGuard `message_type` is read by the coverage matrix.

New server-side profiles: TFTP OACK (1..16 pairs of the RFC 2348/2349/7440
options blksize, timeout, tsize and windowsize with numeric values) and, with
the `tftp` hint only, ERROR (code 0..8 and a non-empty printable message; its
first bytes are those of a NetFlow v5 header, so it never selects itself),
L2TP
SCCRP (message type 2 with the peer's nonzero tunnel id and zero session id),
PPTP SCCRP (156 bytes, result 1..5, error code 0..6 only with a general error),
memcached binary responses (magic 0x81, data type raw, a known status, and
key/extras/value sizes consistent with the command or the error; evidence
`memcached_status`), the git server's first pkt-line (SHA-1 or SHA-256 object
id, space, `HEAD` or `refs/...`, NUL, capabilities, LF; or `version 2`) and
FastCGI application-server records (STDOUT/STDERR with content, END_REQUEST
with protocol status 0..3 and zero reserved bytes). Prefix rules: 0x81 routes
to `netbios-ss` only for the fixed 68-byte session request and to `memcached`
otherwise; a pkt-line length followed by hex digits waits for 24 bytes before
choosing `git`; FastCGI records of types 3/6/7 with a nonzero request id route
to `fastcgi`. Values, keys, error messages, refnames, capabilities, object ids
and record contents are never emitted.

Still unproven on the server side after this release: FTP and SMTP (the 220
banner alone is ambiguous between them), MQTT CONNACK and RESP replies (four
to five bytes, too weak without port context and overlapping the POP3
greeting), Kafka responses (a correlation id only), rsync and the NetBIOS
positive session response (four bytes), and the QUIC server Initial (its keys
derive from the client's original connection id, which the packet does not
carry).

## HTTP/2 HEADERS after SETTINGS (v0.50)

The `http2` profile no longer stops at the client preface and initial SETTINGS.
Identification is still published there (`initial_message`); the parser then
keeps reading frames until the first header block ends and publishes a
`refined` observation with scope `request_headers` (client) or
`response_headers` (server, after the h2c upgrade or with the `http2-server`
candidate, which `analyze_pcap` now sets on the server direction once the
client preface identified the connection: `http2_servers_expected`, evidence
`candidate_hint` from `peer:http2-preface`). Hints select the parser; the
server bytes still have to validate.

Frames accepted before HEADERS, at most eight: SETTINGS (ACK with empty payload,
or a further non-ACK frame validated like the first), WINDOW_UPDATE (4 bytes,
positive increment), PRIORITY (5 bytes, not on stream 0, not self-dependent),
PING (8 bytes, stream 0). HEADERS must open a client-initiated (odd) stream
with known flags only; PADDED and PRIORITY fields are removed structurally
(padding inside the frame, dependency not the stream itself). CONTINUATION
frames must follow on the same stream with no other frame between, at most
eight per block; the block is capped at 16384 bytes and the remaining
`max_bytes`. DATA, RST_STREAM, PUSH_PROMISE, GOAWAY and unknown types end the
watch quietly, as does any ParseError or exceeded budget: the SETTINGS
identification stands without header evidence. DATA payloads are never read.

The block is decoded with `protocol_engine/hpack.py` (RFC 7541): static table,
canonical Huffman code (complete, nibble-table decoder, strict padding, EOS
is an error), integers limited to four continuation bytes, literals with and
without indexing, dynamic table never above 4096 bytes (size updates only at
the start of a block, at most two), field count `min(max_headers, 128)`, string
length `min(max_line, 8192)`, decoded list size 16384 bytes. The header list
must satisfy RFC 9113 8: lowercase token names, no connection-specific fields,
`te` only `trailers`, values without NUL/CR/LF or edge whitespace, pseudo
headers before regular ones and each at most once. Requests need `:method`
(a token, 32 bytes at most), `:scheme` and a non-empty `:path`, except CONNECT
which needs `:authority` alone; an extended CONNECT (`:protocol`, RFC 8441)
needs scheme, path and authority. Responses need a three-digit `:status`
100..599 and no other pseudo header.

Emitted evidence is a closed vocabulary: `http2_message` (`request`/
`response`), `http2_method` (the nine RFC 9110 methods or `extension`),
`http2_scheme` (`http`, `https`, `other`), `http2_protocol` (`websocket`/
`other`, asserted), `http2_status` (the code), `http2_content_type`
(asserted class: `grpc`, `grpc-web`, `json`, `xml`, `form`, `multipart`,
`protobuf`, `binary`, `text`, `other`) and `hostname` from `:authority`
(port removed, DNS names only; IPv4 literals and bracketed IPv6 literals,
validated with the standard library, give no hostname; userinfo, an invalid
bracket content or a port outside 1..65535 rejects the block). Paths, user agents, cookies and every other
value are never emitted; with `retain_contexts` they feed the `http2-req-*`
and `http2-rsp-status` signature contexts (SIGNATURES.md). With
`fingerprints`, `h2_pseudo_order` records the pseudo-header order
(`m,s,p,a` style). App-ID: a POST with a `grpc`/`grpc-web` content class is
`grpc` (implicitly web-browsing), CONNECT is `http-proxy`, an extended
CONNECT for `websocket` is `websocket`.

Not in the profile: later streams and trailers, PUSH_PROMISE, header blocks
larger than 16 KiB, SETTINGS_HEADER_TABLE_SIZE above the default, HTTP/2 over
TLS without `feed_decrypted`, and HTTP/3 (QPACK).

## ONC RPC, Diameter, ZMTP, Bolt and HTTP content classes (v0.51)

Four new families (74 in total, 67 automatic) and two HTTP refinements.

`onc-rpc` (RFC 5531, `onc-rpc/2`, TCP and UDP): a CALL carries xid, message
type 0, RPC version 2, program, version, procedure (at most 65535) and two
opaque_auth structures. Known programs are reported as labels (`rpc_program`:
`portmap` 100000, `nfs` 100003, `mount` 100005, `nlm` 100021, `nsm` 100024,
`nfs-acl` 100227, `rquota` 100011, otherwise `other`) with their published
version ranges enforced; unknown programs need a nonzero number and a version
at most 255. Credentials: AUTH_NONE (empty), AUTH_SYS (stamp, printable
machine name up to 255 bytes with zero padding, uid, gid, at most 16 gids,
exact length), AUTH_SHORT, AUTH_DH and RPCSEC_GSS by flavor and a 4-aligned
length at most 400; the verifier is never AUTH_SYS. Procedure arguments are
not decoded. A REPLY is accepted (verifier, accept status 0..5, version range
for PROG_MISMATCH) or denied (RPC_MISMATCH with a version range, or AUTH_ERROR
with status 1..14); only a successful reply may carry results. Over TCP one
last-fragment record of at least 20 bytes must hold the message; first byte
0x80 with a zero second byte routes to RPC only when bytes 8..16 hold message
type 0 with version 2, or message type 1 with reply status 0/1 (a memcached GET
always has a non-empty body and never a 24-byte key with opaque 0 or 1). Over
UDP the same words select the candidate. Evidence: `rpc_message`
(`call`/`reply`), `rpc_program`, `rpc_program_version`, `rpc_credential`
(asserted flavor), `rpc_reply` (`accepted`/`denied`), `rpc_accept_status`,
`rpc_reject_status`. Machine names, uids, gids, GSS tokens, arguments and
results are never emitted. App-ID: `portmapper` (100000), `nfs` (NFS, mount,
NLM, NSM, NFS ACL) and `sun-rpc` otherwise; replies are `sun-rpc`, which the
session merge treats as the carrier rather than a conflicting identification.

`diameter` (RFC 6733, TCP): Capabilities-Exchange-Request and -Answer on the
base application only: version 1, length a multiple of four, reserved command
flags zero, P clear (never proxiable), no E on a request and no T on an
answer. Every AVP header is checked (reserved flags, length within the message
and at least its header, zero padding, vendor id when V is set, at most
`min(max_headers, 128)` AVPs); Origin-Host, Origin-Realm, Host-IP-Address
(IPv4 or IPv6 Address), Vendor-Id and Product-Name are mandatory, carry the M
flag and, except Host-IP-Address, appear once; a CEA needs a Result-Code in
1001..5999. Evidence: `diameter_message` (`cer`/`cea`) and `diameter_result`
(`informational`, `success`, `protocol-error`, `transient-failure`,
`permanent-failure`). Identities, addresses, product names and vendor-specific
AVP contents are never emitted. Other commands (watchdog, disconnect,
application messages) are outside the profile.

`zmtp` (ZeroMQ ZMTP 3.0/3.1, TCP): the 64-byte greeting (0xff, eight padding
bytes whose first is zero as every known implementation sends, 0x7f, major 3, minor 0 or 1, a 20-byte upper-case mechanism name with
zero padding, as-server 0/1, 31 zero filler bytes). Evidence: `zmtp_mechanism`
(`null`, `plain`, `curve`, `gssapi`, `other`) and `zmtp_role` (`client`, or
`server` for the bind side). The `cleartext-credential-protocol` risk applies
to the PLAIN mechanism only. Handshake commands and frames are not read.

`bolt` (Neo4j, TCP): the client handshake (magic 60 60 b0 17 and four version
ranges, each reserved byte zero, range at most the minor, major and minor
within the published versions 1.0–5.x, zero slots only after the last
proposal) is automatic; the four-byte server version response is accepted
only with the `bolt` hint, because four bytes alone never select a family.
Evidence: `bolt_message` (`handshake`/`version-response`) and `bolt_version`
(preferred or selected version, `none` when the server declines).

HTTP/1.x requests now report `http_method` (the eight RFC 9110 methods or
`extension`; CONNECT only in authority-form as before), the first
`content-type` as `http_content_type` (asserted class, same vocabulary as
HTTP/2 plus `dns` for `application/dns-message`) and `http_accept` = `dns`
when the first accepted media type is a DNS message; HTTP/2 gains the same
`dns` class and `http2_accept`. App-ID: a request or response carrying a DNS
message, or a request accepting one, is `dns-over-https` (implicitly
web-browsing) over HTTP/1.x and HTTP/2. Header values are never emitted.

## XMPP, syslog over TCP and HTTP-carried applications (v0.52)

`xmpp` (RFC 6120, TCP, 75 families in total, 68 automatic): the initial stream
header in either direction. An optional XML declaration (`version="1.x"`,
optional UTF-8 encoding and standalone) may precede the `<stream:stream` open
tag, which must be followed by whitespace or `>`; the tag is read up to 4096
bytes (bounded by `max_line`) to the first `>` outside a quoted attribute
value (`>` is legal inside quotes and the quote state survives feed
boundaries) and holds at most 16 attributes, each quoted and free of `<`, `&`
and control bytes, at most 1023 bytes, no duplicates. Required:
`xmlns` in {jabber:client, jabber:server, jabber:component:accept} and
`xmlns:stream` equal to the streams namespace; `version`, when present, is
numeric. A header carrying a non-empty `id` is the receiving entity's response
(scope `negotiation_response`); otherwise it is the initiating header. The
`to` domain (initiating) or `from` domain (response) becomes an asserted
`hostname` from source `xmpp_stream` (IPv4 literals give none; invalid names
reject). Evidence: `xmpp_stream` (`initiating`/`response`), `xmpp_namespace`
(`client`/`server`/`component`), `xmpp_version` (`1.0`, `legacy`, `other`).
Stream ids, languages, the initiating `from` JID, features, STARTTLS and
stanzas are never read or emitted; a header preceded by whitespace or using a
prefix other than `stream:` is outside the profile. Dispatch: a first byte `<`
followed by a digit is syslog, `<?xml` or `<stream:stream` is XMPP, anything
else is unknown.

`syslog` over TCP (RFC 6587): one complete frame in octet-counting form (a
decimal count of at most five digits without a leading zero, a space, exactly
that many bytes, at least 16 and at most `min(max_line, 8192)`) or
non-transparent form (`<PRI>` through LF, CRLF tolerated); the message itself
must satisfy the RFC 5424 profile already used for UDP. Evidence:
`syslog_framing` (`octet-counting`/`non-transparent`). Dispatch: one to five
digits, a space and `<` select syslog; other digit-first text (SMTP/FTP
replies, RESP arrays, git pkt-lines) keeps its route.

HTTP-carried applications (App-ID only; the HTTP profile is unchanged): the
method vocabulary now includes the WebDAV methods (PROPFIND, PROPPATCH, MKCOL,
COPY, MOVE, LOCK, UNLOCK, REPORT, SEARCH) on HTTP/1.x and HTTP/2, and the
content classes `ipp` (application/ipp), `ocsp` (application/ocsp-request or
-response) and `soap` (application/soap+xml, before the generic `+xml` rule).
A WebDAV method is `webdav`; a POST or a response with an `ipp` or `soap`
class is `ipp` or `soap`; an `ocsp` class in either direction is `ocsp`. All
four implicitly use web-browsing and inherit the asserted nature of the
header they read.

## X11, SPICE, AFP over DSI, Omron FINS/TCP, RIP and RTCP (v0.53)

Six new families (81 in total, 73 automatic).

`x11`: the client connection setup is automatic: byte-order byte `B` or `l`
followed by a zero unused byte (no text protocol has NUL there), protocol
11.0, authorization protocol name at most 64 bytes (printable) and data at
most 1024 bytes, both padded to four; data without a name is rejected.
Evidence: `x11_message` (`setup-request`), `x11_byte_order` (`msb`/`lsb`),
`x11_authorization` (asserted: `mit-magic-cookie-1`, `xdm-authorization-1`,
`sun-des-1`, `mit-kerberos-5`, `other`, `none`); the cookie is never read
beyond its length. The server setup reply (status 0 failed, 1 success, 2
authenticate; byte order inferred from the major version 11; success replies
need consistent image byte order, bitmap bit order, scanline unit and pad,
keycode range and vendor/format/screen sizes within the reply) is accepted
only with the `x11-server` hint because its first byte is 0, 1 or 2
(`x11_message` `setup-success`/`setup-failed`/`setup-authenticate`, scope
`negotiation_response`). Vendor strings and reasons are never emitted.

`spice`: the SpiceLinkHeader (magic REDQ, major 2, minor at most 2, size)
followed by the client SpiceLinkMess (channel type, capability counts at most
32 each, caps offset 18, exact size; secondary channels need a connection id)
or the server SpiceLinkReply (error 0..9, 162-byte public key, caps offset
178, exact size). The client layout is tested first: a reply can never
satisfy it because the bytes the client layout reads as the capability offset
lie inside the reply's DER-encoded public key, whose fixed object identifier
never encodes 18, while a client message whose last capability word happens
to equal 178 is not a reply (review round 1). Evidence: `spice_message` (`link-message`/`link-reply`),
`spice_channel` (main, display, inputs, cursor, playback, record, tunnel,
smartcard, usbredir, port, webdav, other), `spice_link_error` (closed labels).
Connection ids, public keys and capabilities are never emitted.

`afp` (DSI): GetStatus and OpenSession requests (flags 0, data offset 0) and
replies (flags 1, AFP result 0 or negative), reserved bytes zero, payload at
most 64 bytes (OpenSession options: attention quantum, server request quantum,
replay cache size, each four bytes) or 4096 bytes (the server information
answering GetStatus, not decoded). Dispatch tests the whole 16-byte header
before the Kafka probe. Evidence: `dsi_message` (`request`/`reply`),
`afp_command` (`open-session`/`get-status`). DSICommand and later AFP
commands are outside the profile.

`fins` (Omron FINS/TCP): magic FINS, length, command 0 (node address request:
length 12, one node address 0..254), 1 (reply: two node addresses) or 2 (a
FINS frame of 20..2048 bytes whose ICF has only the command/response bits,
reserved zero, gateway count at most 7 and network and unit addresses within
range; responses carry an end code). Evidence: `fins_message`
(`node-address-request`, `node-address-reply`, `frame`), `fins_frame`
(`command`/`response`). Memory areas, addresses and data are never read.

`rip` (UDP): command 1 or 2, version 1 or 2, zero field, 1..25 twenty-byte
entries; a v2 authentication entry (simple password or MD5 with packet length,
key id, 16-byte digest length and the trailer entry) may open the datagram;
entries need address family IP, metric 1..16 and, in v1, zero route tag, mask
and next hop; a one-entry request with family 0 and metric 16 is the
whole-table request. Evidence: `rip_command`, `rip_authentication` (`none`,
`simple-password`, `md5`); the password is never emitted and only
`simple-password` keeps the `cleartext-credential-protocol` risk. Candidate
selection needs the command/version bytes, a zero field and a length of
4 + 20n with n at least one.

`rtcp` (UDP, hint only): a compound packet beginning with SR or RR, every
packet version 2 with a known type 200..207 and a length within the datagram
(SR/RR report blocks and BYE sources bounded by their counts), at most eight
packets. Evidence: `rtcp_packet` (first type), `rtcp_packets` (count). Report
contents and SDES items are never read.

## LDAP StartTLS, IRC, TURN methods, DNS query types and RPC over HTTP (v0.54)

One new family (82 in total, 74 automatic), one new shift boundary and four
new applications named from structural evidence.

`ldap`: besides BindRequest and BindResponse, the first message may be an
ExtendedRequest (0x77: requestName as a numeric OID of at most 31 arcs, an
optional requestValue) or an ExtendedResponse (0x78: LDAPResult, optional
responseName OID, optional responseValue). Evidence: `ldap_message`
(`bind_request`, `bind_response`, `extended_request`, `extended_response`),
`ldap_extended` (`starttls`, `whoami`, `password-modify`, `cancel`,
`notice-of-disconnection`, `other`, `unnamed`), `ldap_result`. A StartTLS
request (OID 1.3.6.1.4.1.1466.20037, which carries no value) announces
nothing by itself: the client must wait for the answer and continues in
plaintext after a refusal (RFC 4511 4.14), so the client direction is never
shifted from the request alone (review round 1; this differs from the
SMTP/IMAP/POP3/FTP client-side STARTTLS shifts of v0.28, which stand as
documented). A StartTLS response whose responseName is present and whose
result is success announces the `ldap-starttls` shift on the server
direction (its next bytes are the ServerHello). `analyze_pcap` correlates
both directions: when the server's ExtendedResponse carries success for the
*same message id* as the client's StartTLS request (the id is private
correlation metadata on the Inspector, never evidence), it opens the TLS
phase on the client direction and, for a success without responseName (RFC
4511 allows the omission), on the server direction too
(`ldap_starttls_correlated`). A refusal, an unrelated message id or a success
for another operation opens nothing. The phase is opened through the
reassembly stream (`Stream.open_shift`), which replays the bytes that
direction already carried past its LDAP message and the inspector skipped
while terminal (`Inspector.boundary`, `Inspector.replay`): a ClientHello
recorded before the server's answer, or coalesced with the request in one
segment, is inspected exactly once and counted once (review round 2). The
events such a replay publishes belong to the replayed direction: the
analyzer extends the packet's own events when it is the same direction and
exposes the other direction's as `Analyzer.peer_events` (source,
destination, event), which the live observer emits with that direction
(review round 3). The CONNECT correlation of v0.33 uses the same path, so a
ServerHello sharing the 2xx's segment is no longer lost. Any response value on a StartTLS
response, a non-OID name or a result code above 123 is malformed; controls
remain outside the profile (unknown). Extended values, DNs and diagnostics
are never emitted. The `cleartext-credential-protocol` risk stays on an
LDAP observation until the correlated shift to `ssl` is established.

`irc` (new family, automatic): a client registration line (`NICK` with the
RFC 2812 nickname grammar, at most 64 characters; `CAP` with a subcommand
LS/LIST/REQ/ACK/NAK/END/NEW/DEL and a three-digit LS version) reaches the
IRC profile through the text route. `USER` with exactly its four parameters
is validated against the IRC grammar but reported as ambiguous between
`ftp` and `irc` (an FTP user name is a free-form string that may contain
spaces, RFC 959; POP3 takes one space-free argument and is excluded), and
`PASS` stays ambiguous with `ftp,pop3,irc`; the session verdict resolves
both from the server direction, and the `irc` hint selects the IRC parser
for them with the same line validation (review round 1). A server opening line is routed by its `:`
prefix (a server name or `nick!user@host`) followed by a three-digit numeric
reply naming a nickname or `*`, or NOTICE, PING, PONG, CAP, MODE, NICK,
JOIN, AUTHENTICATE or PRIVMSG with their parameter counts; the unprefixed
`NOTICE AUTH`/`NOTICE *` and `PING` lines some servers send first are
accepted on the text route. Lines are at most 512 bytes including CRLF: on
the `:` route and with the `irc` hint the limit is enforced before any
newline arrives (a longer pending line is malformed at once); on the shared
text route a pending line is bounded by `max_line` like every other text
first line and an IRC candidate longer than 510 bytes is malformed once the
line completes (review round 1). Parameters at most 15, no NUL/CR/LF. Evidence: `irc_message` (`nick`, `user`, `cap`, `pass` with the
irc hint only, `notice`, `ping`, `pong`, `numeric`, `error`, `mode`,
`privmsg`, `join`, `authenticate`). Nicknames, user names, hosts, channels,
passwords and message text are never emitted. JOIN/PRIVMSG/CTCP/DCC
sessions, server-to-server links and IRCv3 tags are outside the profile.

`stun`: the TURN methods (RFC 5766/6062) validate alongside Binding:
Allocate, Refresh, Send, Data, CreatePermission, ChannelBind, Connect,
ConnectionBind and ConnectionAttempt. Send, Data and ConnectionAttempt exist
only as indications; the other methods never as indications (Binding
indications are keepalives and stay valid). TURN attributes are checked:
REQUESTED-TRANSPORT (4 bytes, UDP or TCP, zero reserved bytes), LIFETIME (4),
CHANNEL-NUMBER (4, 0x4000..0x7FFF with zero reserved bytes), EVEN-PORT (1,
only the R bit), RESERVATION-TOKEN (8), XOR-PEER-ADDRESS and
XOR-RELAYED-ADDRESS as address attributes, USERNAME (at most 513 bytes),
REALM/NONCE/SOFTWARE (at most 763), ERROR-CODE (class 3..6, number 0..99,
reason at most 763). Evidence: `stun_method` (closed labels), `stun_class`
(`request`, `indication`, `success-response`, `error-response`); the TURN
methods map to the `turn` application (`implicitly_uses` stun). Relayed
addresses, user names, realms, nonces and HMACs are never emitted or
verified. Undefined methods remain unknown.

`dns`: `dns_query_type` (closed labels: a, ns, cname, soa, ptr, mx, txt, aaaa,
srv, naptr, ds, rrsig, dnskey, svcb, https, any, nb, nbstat, other) joins the
query and response evidence on UDP and TCP. NetBIOS name service queries
share the DNS layout; the NB (0x20) and NBSTAT (0x21) types are told from DNS
only when the first label is the 32-byte first-level encoding over A..P, so
an SRV query (also type 33) keeps its label and a type-32 question with an
ordinary name is `other`. `nb`/`nbstat` map to the `netbios-ns` application
(udp/137). Names are never emitted.

`http`: the RPC over HTTP methods `RPC_CONNECT`, `RPC_IN_DATA` and
`RPC_OUT_DATA` (MS-RPCH) are recognised method tokens; a request with one of
them maps to `ms-rpc-over-http` (`implicitly_uses` web-browsing). The
encapsulated DCE/RPC PDUs are not inspected.

Dispatch: `:` (0x3a) routes to the IRC server-line parser; a mutated first
byte that used to be unknown there is now malformed when the IRC grammar
rejects it. No other route changed.

## Name services on the DNS layout: mDNS, NetBIOS-NS, LLMNR (v0.55)

Three new families (85 in total, 76 automatic) share the DNS message layout
and are told apart by structure, never by port. The validator in `wire.py`
walks the sections once and names the family afterwards; names are returned
only for signature contexts and are never emitted.

Candidate selection (`dns_probe`): the QUERY opcode with exactly one question
selects as before. The rarer layouts also select, under a plausibility rule
that keeps other datagrams (RIP entries, DTLS records) out: the first name
must start with a label of 1..63 bytes and the four section counts must sum
to 1..32. They are: QUERY with 2..8 questions, QUERY with no question when
the message is a response carrying answers, and the NetBIOS name service
opcodes 5..8 with at most one question. The TCP dispatch is unchanged (one
question in the twelve header bytes); mDNS and NetBIOS-NS are UDP profiles,
so over TCP the family stays `dns` and only the evidence rows below are
added, while NetBIOS registration opcodes over TCP are unknown.

`mdns` (RFC 6762, automatic): a message whose first question name, or the
first record's owner name when there is no question, ends in `.local`, or
whose question carries the QU bit (class 0x8000), or whose response record
carries the cache-flush bit, or which has several questions or no question at
all with answers (an announcement is named by its first record, so a shared
record without the cache-flush bit is one too; a compressed later owner is
not expanded). Queries may carry answers (known-answer suppression) and
authority records (probes) but never the AA bit, a response code or the
cache-flush bit, which exists only in response record sections (RFC 6762
10.2; no DNS class has that bit, so a query carrying it is malformed on every
layout); responses must carry AA and a zero response code. Evidence: `dns_message`, `dns_rcode`, `dns_query_type` (the first
question's type, or the first answer's type in an announcement) and
`mdns_profile`: `announcement` (no question), `probe` (query with authority
records), `known-answer` (query with answers), `unicast-requested` (QU bit),
`plain`. Several questions without any marker stay outside the profile
(unknown); a response without a question and without a marker is malformed.
Service instance names, host names, addresses and TXT records are never
emitted. App-ID: `mdns` (aliases bonjour, zeroconf), udp/5353.

`netbios-ns` (RFC 1002, automatic; the v0.54 `dns` + `nb`/`nbstat`
refinement becomes a family): a NB (0x20) or NBSTAT (0x21) question whose
first label is the 32-byte first-level encoding over A..P, with the QUERY
opcode, or the opcodes registration (5), release (6), WACK (7) and refresh
(8) with that encoded name. Requests carry one question and, for the
registration-class opcodes, exactly one additional NB record; responses carry
at most one question and one answer and no other section. Record data is
keyed by message kind (review round 1): a WACK (opcode 7, response only)
carries exactly the two-byte flags word; any other NB record carries one or
more 6-byte entries (NB_FLAGS with zero reserved bits, IPv4 address); an
NBSTAT record appears only in responses and carries NUM_NAMES, exactly that
many 18-byte node-name entries (NAME_FLAGS with zero reserved bits) and the
46-byte statistics block. Evidence: `dns_message`, `dns_rcode` (NBNS result codes read
through the DNS table: ACT_ERR is `yxdomain`, RFS_ERR `refused`, SRV_ERR
`servfail`), `dns_query_type` (`nb`/`nbstat`), `nbns_opcode` (`query`,
`registration`, `release`, `wack`, `refresh`). Names, addresses and node
status tables are never emitted. The `dns-error-response` risk applies to
`servfail`, `nxdomain` and `refused` as for DNS.

`llmnr` (RFC 4795, hint only): the bytes of an LLMNR query are those of a
unicast DNS query with RD clear, so only the `llmnr` candidate selects this
profile; the port never does. With the hint: opcode zero, exactly one
question, a zero Z nibble; the C bit (DNS's AA position) and T bit (DNS's RD
position) are read with their LLMNR meaning: a query carries neither answers,
authority records, a response code nor the T bit; `.local` and NetBIOS names
are not LLMNR (unknown). Evidence: `dns_message`, `dns_rcode`,
`dns_query_type`, `llmnr_flags` (`none`, `conflict`, `tentative`). Without
the hint an LLMNR query identifies as `dns` and a conflict query (C bit) is
malformed DNS, both as before.

Behaviour change: UDP NB/NBSTAT queries now identify as `netbios-ns` rather
than `dns` with the `nb` row (the App-ID verdict is unchanged); a `.local`
query identifies as `mdns`. Two seeded DTLS mutations that used to be unknown
briefly read as malformed before the non-empty-section rule was added to the
probe; the released probe keeps them unknown.

## Authentication mechanism evidence: SMB session setup, LDAP bind, HTTP Authorization (v0.56)

No new family. The first authentication step of a session names its mechanism
as a closed label; credentials, principals, domains, challenges, tickets and
MICs are never decoded. `protocol_engine/gss.py` classifies the token layouts
these messages carry (RFC 2743 InitialContextToken, RFC 4178 SPNEGO
NegTokenInit/NegTokenResp, MS-NLMP NTLMSSP): `gss_mechanism` is `kerberos`
(the krb5, MS krb5 or user-to-user OID, or a Kerberos GSS token whose TOK_ID
01 00, 02 00, 03 00 or 04 00 is followed by exactly the AP-REQ, AP-REP,
KRB-ERROR or TGT-REQ it names, whether the token stands alone or is carried as
a mechToken/responseToken; the message must pass its RFC 4120 envelope: pvno 5,
the msg-type of its TOK_ID, the required context fields in increasing order,
AP-REQ ap-options as a DER KerberosFlags BIT STRING (at least 32 significant
bits, unused-bit count 0..7, padding bits zero), a Ticket
[APPLICATION 1] with tkt-vno 5, a non-empty realm, a PrincipalName of 1..8
components and EncryptedData, EncryptedData with an Int32 etype, optional kvno
and non-empty cipher, KRB-ERROR through the Kerberos family's own profile
(whose ctime/stime microseconds must lie in RFC 4120's 0..999999);
names, realms and ciphertext are framed only), `ntlm` (the NTLMSSP OID or an NTLMSSP mechToken/responseToken),
`negoex`, `spnego-other` (SPNEGO without a known preferred mechanism) or
`other` (a non-SPNEGO GSS OID); `ntlm_message` is `negotiate`, `challenge` or
`authenticate`. A NegTokenInit names the first listed mechType unless its
mechToken carries NTLMSSP or Kerberos; a NegTokenResp names its supportedMech
or its responseToken. Budgets: 4096-byte tokens, 8 mechTypes, fixed DER depth,
exact lengths at every level. Malformed tokens are `ParseError` and end the
continuation without touching the carrier identification.

`smb2`: after a NEGOTIATE in either direction the parser watches exactly one
more direct-TCP frame. A SESSION_SETUP request (StructureSize 25, flags 0/1,
SecurityMode 1..3, security buffer at offset 88 filling the frame, STATUS
zero) adds `smb_message=session-setup-request` and the token's
`gss_mechanism`/`ntlm_message`; a SESSION_SETUP response (StructureSize 9,
STATUS_SUCCESS or STATUS_MORE_PROCESSING_REQUIRED, SessionFlags within
guest/null/encrypt, buffer at 72) adds `smb_message=session-setup-response`,
`smb_session` (`continuing`, `guest`, `anonymous`, `encrypted`,
`authenticated`) and the token labels. The NEGOTIATE request now also carries
`smb_signing` (`enabled`/`required`) like the response. The SMB2 header flags
must fit the direction without relying on a negotiated dialect, which this
one-direction watch never learns: a request carries no flags (the SMB 3.1.1
priority value and the signed session-binding request are dialect-dependent
and end the watch); a response carries SERVER_TO_REDIR and, only on the final
STATUS_SUCCESS response that every dialect may sign, SIGNED; the signature is
never verified; an unsigned frame must carry a zero signature field; ASYNC,
RELATED_OPERATIONS, DFS, REPLAY and reserved bits are rejected. Any
other command, a compounded frame, a signed frame elsewhere, a status outside
the two, or a buffer that does not fill the frame leaves the NEGOTIATE
identification as published (a non-SMB frame is not consumed at all); the
watch never reads a third frame.

`smb1`: after a NEGOTIATE in either direction, one SESSION_SETUP_ANDX
(0x73): the 12-word extended-security request classifies its security blob;
the 13-word NT LM 0.12 request reports `gss_mechanism=ntlm-response` when the
case-insensitive (at most 24 bytes) or case-sensitive (at most 1024) password
response is present, `none` otherwise; the 10-word LAN Manager request reports
`lm-response` or `none`; a response (3 or 4 words, action within the defined
bits) reports `smb_session` (`guest`, `authenticated`, `continuing`) and the
blob labels. Account, domain, OS and LAN Manager strings are bounded by the
byte count and never read.

`ldap`: BindRequest adds `ldap_bind`: `simple`, or `sasl-gssapi`,
`sasl-gss-spnego`, `sasl-plain`, `sasl-digest-md5`, `sasl-cram-md5`,
`sasl-scram`, `sasl-ntlm`, `sasl-external`, `sasl-other`; a GSS-SPNEGO bind
with credentials adds the token's `gss_mechanism`/`ntlm_message`. The
mechanism string itself is never emitted.

`http`: HTTP/1 and HTTP/2 requests report `http_auth_scheme`
(`http2_auth_scheme`) for every distinct scheme across all
`Authorization`/`Proxy-Authorization` headers (one credential per header, so
only its first token is read), responses `http_auth_challenge`
(`http2_auth_challenge`) for every distinct challenge across all
`WWW-Authenticate`/`Proxy-Authenticate` headers and within each
comma-separated list: an element whose leading token is followed by `=` is an
auth-param, any other element starts a challenge, commas inside quoted strings
do not split, and at most 32 list elements per header are examined. Labels:
`basic`, `bearer`, `digest`, `negotiate`, `ntlm`, `other`, `empty`. Only scheme
tokens are read.

Risks (RISKS.md): `ntlm-authentication`, `http-basic-authentication`,
`smb-guest-or-anonymous-session`; `cleartext-credential-protocol` clears on
LDAP binds whose mechanism never carries the password.

Review round 1 repairs: a Kerberos token carried inside SPNEGO now passes the
same TOK_ID validator as a direct one (a bad TOK_ID makes the whole token
malformed instead of yielding `kerberos`); the SMB2 SESSION_SETUP header flags
are checked as above (previously a signed or async frame was accepted against
this section's own rule); repeated credential headers and challenge lists no
longer hide a later Basic or NTLM scheme. Round 2 repairs: the Kerberos
message after the TOK_ID must pass its envelope (an empty or arbitrary
application body no longer yields `kerberos`), and the dialect-dependent
request flags (priority, signed binding) now end the watch instead of being
taken as proof of SMB 3.x. Round 3 repairs (carried into the v0.57 request,
the round limit being reached): ap-options must carry at least 32 significant
bits with zero padding, and the shared KRB-ERROR validator rejects cusec/susec
outside 0..999999, which also tightens the standalone Kerberos family.

## TLS posture: server key exchange, leaf certificate purpose and validity (v0.57)

No new family. The ServerHello and the opt-in leaf certificate watch (v0.39)
gain posture labels drawn from closed sets; nothing is verified and nothing
names the server.

Server selections (`protocol_engine/tls_server.py`, TLS 1.2, TLS 1.3 and
DTLS 1.2 ServerHello; a HelloRetryRequest selects nothing and carries neither):

| Evidence | Values | Rule |
|---|---|---|
| `selected_key_exchange` | `ecdhe`, `dhe`, `static-ecdh`, `static-rsa`, `psk` | TLS 1.2 from the suite: `TLS_RSA_*` (0x002f) is `static-rsa`; `TLS_ECDH_*` (0xc025, 0xc026, 0xc029, 0xc02a, 0xc02d, 0xc02e, 0xc031, 0xc032) use the certificate's static key and are `static-ecdh`; `TLS_ECDHE_*` are `ecdhe`. TLS 1.3 from the extensions: a `key_share` names `ecdhe` (x25519, x448, P-256/384/521) or `dhe` (ffdhe2048..8192), with or without `pre_shared_key`; `pre_shared_key` alone is `psk` (psk_ke resumption, RFC 8446 4.2.9) |
| `selected_cipher_mode` | `aead`, `cbc` | GCM suites and every TLS 1.3 suite are `aead`; the CBC suites (0x002f, 0xc023..0xc02a) are `cbc` |

Both are `asserted`: the server's selection, unauthenticated, with handshake
completion unverified. Risk `tls-no-forward-secrecy` (`static-rsa`,
`static-ecdh`, `psk`).

Leaf certificate (`protocol_engine/x509.py`, `--certificates`): the extension
walk keeps checking every extension's framing as before and now interprets
exactly three of them; any other extension is never read beyond its framing.

| Evidence | Values | Rule |
|---|---|---|
| `tls_certificate_ca` | `yes`, `no` | basicConstraints (2.5.29.19) `cA`. DER omits the FALSE default, so an encoded FALSE (or any BOOLEAN other than 0xff) is malformed; `pathLenConstraint` only with cA TRUE (RFC 5280 4.2.1.9), a 1..4-octet non-negative minimally encoded INTEGER; any other field is malformed. Absent extension: `no` |
| `tls_certificate_eku` | `server-auth`, `any`, `other`, `absent` | extendedKeyUsage (2.5.29.37), 1..16 key purposes: `server-auth` when id-kp-serverAuth is listed, else `any` for anyExtendedKeyUsage, else `other` |
| `tls_certificate_san` | `present`, `absent` | subjectAltName (2.5.29.17): a non-empty SEQUENCE of 1..256 GeneralName choices, each in its DER form (otherName [0], x400Address [3], directoryName [4] and ediPartyName [5] constructed; rfc822Name [1], dNSName [2], URI [6], iPAddress [7] and registeredID [8] primitive) with its inner framing (non-empty IA5 text names, a 4- or 16-octet address, a DER registeredID, an otherName OID plus a [0] holding exactly one element, 1..32 complete elements in an x400Address, one Name in a directoryName, an ediPartyName of optional [0] and required [1] each holding exactly one element); bytes are checked, never read into output |
| `tls_certificate_not_before`, `tls_certificate_not_after` | `YYYY-MM-DD` | The validity window at calendar-day granularity (the time of day is dropped so the window is a coarse posture fact rather than a fingerprint) |

`ca`, `eku` and `san` appear only for v3 certificates (v1 and v2 cannot carry
extensions). The same extension OID twice is malformed (RFC 5280 4.2), and so
is an encoded `critical` FALSE on any extension (DER omits the default; review
round 1, the same rule as cA). Before v0.57 an explicit FALSE was accepted, so
such leaves now end the watch without certificate labels. Every object
identifier in the walk (algorithms, attribute types, extensions, key purposes,
registeredID, otherName and, since the round-3 repair carried into v0.58, the
EC named-curve parameter) must be DER: minimally encoded arcs and a complete
last arc, one OID filling the curve parameters (review rounds 2 and 3). As in
v0.39, any deviation ends the watch with no certificate evidence and keeps the
ServerHello identification.

Validity at capture time: the engine has no clock. The hosts pass the capture
time (`classify(..., at=)`, `session_verdict(..., at=)`): `analyze_pcap` the
session's first packet, `live_capture` the packet that produced the event.
Session records and live events add `certificate.validity` (`current`,
`expired`, `not-yet-valid`) and the risk `tls-certificate-outside-validity`.
Boundary days count as inside, and a session is judged at its start, so the
comparison errs towards not flagging. A capture clock before 2000-01-01 (zeroed
or synthetic timestamps) or beyond year 9999 is treated as unset: no validity,
no risk. The wall clock of the analysis run is never read, so replaying an old
capture judges certificates as they were at capture time.

Risks: `tls-no-forward-secrecy`, `tls-ca-certificate-as-leaf`,
`tls-certificate-not-for-server-auth`, `tls-certificate-without-san`,
`tls-certificate-outside-validity` (RISKS.md). Still out of scope: chain
building, signature and name verification, revocation, keyUsage bits, name
constraints, policies, and TLS 1.3 certificates (encrypted).

Behaviour diff against v0.56: `tools/compare_engine.py` covers the DTLS
ServerHello (176 of its inputs gain the two selection rows, nothing else
changes); its fixture set has no TLS server flight, so a supplementary run fed
identical TLS 1.2, TLS 1.3, HelloRetryRequest and certificate flights (with
seeded mutations, certificates on and off) to both trees: no status, protocol
or reason changes; ServerHellos gain the selection rows, certificate flights
the posture rows, and 2 of 410 mutated certificate flights now end the watch
without certificate evidence because the mutation fell inside an extension
v0.57 interprets.

## SSH algorithm posture from KEXINIT (v0.58)

No new family. After the banner the SSH parser now always reads the one
SSH_MSG_KEXINIT it already validated for HASSH (same RFC 4253 7.1 profile and
budgets: packet 17..35000 bytes within `max_bytes`, ten printable name-lists of
at most 4096 bytes, a valid trailer, nothing after it) and publishes a
`refined` event with closed-set classes. Algorithm names, the cookie and the
lists are never emitted. A KEXINIT is each side's offer: nothing is negotiated,
selected or verified, so the classes describe what a side is willing to use.

| Evidence | Values | Rule |
|---|---|---|
| `ssh_kex_class` | `pq-hybrid`, `ecdh`, `dh-sha2`, `dh-sha1`, `other` | The strongest family among the offered key exchange names: sntrup761x25519 / mlkem768x25519 / mlkem768nistp256 / mlkem1024nistp384 (`pq-hybrid`); curve25519, curve448, ecdh-sha2-nistp* (`ecdh`); diffie-hellman group14-sha256, group15..18-sha512, group-exchange-sha256 (`dh-sha2`); group1-sha1, group14-sha1, group-exchange-sha1 (`dh-sha1`); anything else, including only pseudo-algorithms, is `other` |
| `ssh_weak_algorithm` | `kex-sha1`, `hostkey-dss`, `hostkey-rsa-sha1`, `cipher-none`, `cipher-rc4`, `cipher-3des-or-64-bit-block`, `cipher-cbc`, `mac-none`, `mac-md5`, `mac-truncated` | One row per weak class offered in either direction's list (exact, case-sensitive names; empty names ignored) |
| `ssh_terrapin` | `strict`, `exposed`, `not-applicable` | `strict` when kex-strict-c-v00@openssh.com or kex-strict-s-v00@openssh.com is offered; otherwise `exposed` when chacha20-poly1305@openssh.com, or an `-etm@openssh.com` MAC together with a CBC or 64-bit-block cipher, is offered (CVE-2023-48795); otherwise `not-applicable` |

Risks (RISKS.md): `ssh-weak-algorithm-offered` (every weak class except
`hostkey-rsa-sha1`, which many clients still offer for compatibility, and
`cipher-none`, which has its own risk), `ssh-none-cipher-offered`,
`ssh-terrapin-exposed`. Both directions are inspected; the session verdict
carries each risk once.

Behaviour change: an SSH stream now consumes its KEXINIT without
`--fingerprints` (one more bounded packet per direction) and publishes a
`refined` event. A banner without a KEXINIT, a malformed packet, the byte
budget or EOF end the continuation with the identification unchanged and no
classes. `tools/compare_engine.py` has no banner-plus-KEXINIT fixture in its
generic stream list (those identify before their last byte), so the new
fixtures `SSH_MODERN_STREAM` and `SSH_LEGACY_STREAM` are registered in the
coverage matrix extras and exercised by `test_v058.py`.
