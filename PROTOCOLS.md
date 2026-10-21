
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
| dns | tcp/udp | yes | yes | `dns_message`, `dns_rcode` |
| dtls | udp | yes | yes | `handshake`, `offered_dtls_version`, `selected_cipher`, `selected_dtls_version` |
| ethernet-ip | tcp/udp | yes | same shape | `enip_command` |
| fastcgi | tcp | yes | yes | `fastcgi_record`, `fastcgi_role` |
| fins | tcp | yes | yes | `fins_frame`, `fins_message` |
| ftp | tcp | yes | - | - |
| giop | tcp | yes | yes | `giop_message`, `giop_status` |
| git | tcp | yes | yes | `git_message`, `offered_version` |
| http | tcp | yes | yes | `hostname`, `http_accept`, `http_content_type`, `http_method`, `http_status`, `http_upgrade` |
| http2 | tcp | yes | yes | `hostname`, `http2_content_type`, `http2_message`, `http2_method`, `http2_scheme`, `http2_status` |
| iec-104 | tcp | yes | same shape | - |
| ikev2 | udp | yes | yes | `exchange`, `offered_dh_group`, `selected_dh_group` |
| imap | tcp | yes | yes | - |
| ipfix | udp | yes | n/a (one-way) | - |
| iso-tsap | tcp | yes | yes | - |
| kafka | tcp | yes | - | `kafka_api_key` |
| kerberos | tcp/udp | yes | yes | `kerberos_error`, `kerberos_message` |
| l2tp | udp | yes | yes | `l2tp_message` |
| ldap | tcp | yes | yes | `ldap_result` |
| memcached | tcp | yes | yes | `memcached_message`, `memcached_status` |
| modbus | tcp | yes | yes | `modbus_exception`, `modbus_pdu` |
| mongodb | tcp | yes | yes | `mongodb_message` |
| mqtt | tcp | yes | - | - |
| mysql | tcp | yes | yes | `mysql_auth_plugin`, `mysql_client_ssl`, `mysql_tls_supported` |
| nats | tcp | yes | yes | - |
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
| smb1 | tcp | yes | yes | `smb1_dialect_layout`, `smb1_message` |
| smb2 | tcp | yes | yes | `smb_dialect`, `smb_signing` |
| smtp | tcp | yes | - | `smtp_client_identity` |
| snmp | udp | yes | yes | `snmp_flags`, `snmp_pdu`, `snmp_scoped_pdu`, `snmp_security` |
| socks5 | tcp | yes | yes | `socks_command`, `socks_method`, `socks_port`, `socks_reply`, `socks_target` |
| spice | tcp | yes | yes | `spice_channel`, `spice_link_error`, `spice_message` |
| ssdp | udp | yes | same shape | - |
| ssh | tcp | yes | same shape | `ssh_version` |
| stomp | tcp | yes | yes | - |
| stun | tcp/udp | yes | same shape | - |
| syslog | udp/tcp | yes | n/a (one-way) | `syslog_framing` |
| tacacs-plus | tcp | yes | yes | `tacacs_packet`, `tacacs_type` |
| tds | tcp | yes | yes | `tds_encryption`, `tds_federated_auth`, `tds_mars` |
| telnet | tcp | yes | same shape | - |
| tftp | udp | yes | yes | `tftp_packet` |
| tls | tcp | yes | yes | `hostname`, `offered_alpn`, `requested_group`, `selected_alpn`, `selected_cipher`, `selected_group`, `selected_tls_version`, `tls_certificate_chain`, `tls_certificate_key`, `tls_certificate_lifetime_days`, `tls_certificate_self_issued`, `tls_certificate_signature`, `tls_certificate_version`, `tls_ech`, `tls_handshake`, `tls_offered_max_version` |
| tns | tcp | yes | yes | `tns_connect_data`, `tns_response`, `tns_version` |
| websocket | tcp | yes | yes | `websocket_masked`, `websocket_opcode` |
| wireguard | udp | yes | yes | `message_type` |
| x11 | tcp | yes | yes | `x11_authorization`, `x11_byte_order`, `x11_message` |
| xmpp | tcp | yes | yes | `hostname`, `xmpp_namespace`, `xmpp_stream`, `xmpp_version` |
| zmtp | tcp | yes | yes | `zmtp_mechanism`, `zmtp_role` |

81 families in the catalog, 81 with fixtures, 69 proven on both sides (or symmetric), 4 one-way; server side still unproven: ftp, kafka, mqtt, netbios-ss, quic, resp, rsync, smtp.
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
(port removed, DNS names only; IP literals give no hostname; userinfo or a
bad port rejects the block). Paths, user agents, cookies and every other
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
bytes (bounded by `max_line`) and at most 16 attributes, each quoted and free
of `<`, `&` and control bytes, at most 1023 bytes, no duplicates. Required:
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
178, exact size). Evidence: `spice_message` (`link-message`/`link-reply`),
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
