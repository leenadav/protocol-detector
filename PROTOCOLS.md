
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
| amqp | tcp | yes | yes | `amqp_message` |
| bacnet | udp | yes | same shape | - |
| bgp | tcp | yes | same shape | - |
| bittorrent | tcp | yes | same shape | - |
| coap | udp | yes | same shape | - |
| cql | tcp | yes | yes | `cql_response` |
| dcerpc | tcp | yes | yes | `accepted_transfer_syntax`, `dcerpc_pdu`, `offered_transfer_syntax` |
| dhcp | udp | yes | yes | `dhcp_message`, `dhcp_operation` |
| dnp3 | tcp | yes | same shape | - |
| dns | tcp/udp | yes | yes | `dns_message`, `dns_rcode` |
| dtls | udp | yes | yes | `handshake`, `offered_dtls_version`, `selected_cipher`, `selected_dtls_version` |
| ethernet-ip | tcp/udp | yes | same shape | `enip_command` |
| fastcgi | tcp | yes | yes | `fastcgi_record`, `fastcgi_role` |
| ftp | tcp | yes | - | - |
| giop | tcp | yes | yes | `giop_message`, `giop_status` |
| git | tcp | yes | yes | `git_message`, `offered_version` |
| http | tcp | yes | yes | `hostname`, `http_status`, `http_upgrade` |
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
| rsync | tcp | yes | - | `rsync_protocol` |
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
| ssdp | udp | yes | same shape | - |
| ssh | tcp | yes | same shape | `ssh_version` |
| stomp | tcp | yes | yes | - |
| stun | tcp/udp | yes | same shape | - |
| syslog | udp | yes | n/a (one-way) | - |
| tacacs-plus | tcp | yes | yes | `tacacs_packet`, `tacacs_type` |
| tds | tcp | yes | yes | `tds_encryption`, `tds_federated_auth`, `tds_mars` |
| telnet | tcp | yes | same shape | - |
| tftp | udp | yes | yes | `tftp_packet` |
| tls | tcp | yes | yes | `hostname`, `offered_alpn`, `requested_group`, `selected_alpn`, `selected_cipher`, `selected_group`, `selected_tls_version`, `tls_certificate_chain`, `tls_certificate_key`, `tls_certificate_lifetime_days`, `tls_certificate_self_issued`, `tls_certificate_signature`, `tls_certificate_version`, `tls_ech`, `tls_handshake`, `tls_offered_max_version` |
| tns | tcp | yes | yes | `tns_connect_data`, `tns_response`, `tns_version` |
| websocket | tcp | yes | yes | `websocket_masked`, `websocket_opcode` |
| wireguard | udp | yes | yes | `message_type` |

70 families in the catalog, 70 with fixtures, 58 proven on both sides (or symmetric), 4 one-way; server side still unproven: ftp, kafka, mqtt, netbios-ss, quic, resp, rsync, smtp.
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
