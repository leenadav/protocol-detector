
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
| dhcp | udp | yes | - | - |
| dnp3 | tcp | yes | same shape | - |
| dns | tcp/udp | yes | yes | `dns_message`, `dns_rcode` |
| dtls | udp | yes | yes | `handshake`, `offered_dtls_version`, `selected_cipher`, `selected_dtls_version` |
| ethernet-ip | tcp/udp | yes | same shape | `enip_command` |
| fastcgi | tcp | yes | - | `fastcgi_role` |
| ftp | tcp | yes | - | - |
| giop | tcp | yes | yes | `giop_message`, `giop_status` |
| git | tcp | yes | - | `offered_version` |
| http | tcp | yes | yes | `hostname`, `http_status`, `http_upgrade` |
| http2 | tcp | yes | yes | - |
| iec-104 | tcp | yes | same shape | - |
| ikev2 | udp | yes | yes | `exchange`, `offered_dh_group`, `selected_dh_group` |
| imap | tcp | yes | yes | - |
| ipfix | udp | yes | n/a (one-way) | - |
| iso-tsap | tcp | yes | yes | - |
| kafka | tcp | yes | - | `kafka_api_key` |
| kerberos | tcp/udp | yes | yes | `kerberos_error`, `kerberos_message` |
| l2tp | udp | yes | - | - |
| ldap | tcp | yes | yes | `ldap_result` |
| memcached | tcp | yes | - | - |
| modbus | tcp | yes | yes | `modbus_exception`, `modbus_pdu` |
| mongodb | tcp | yes | - | - |
| mqtt | tcp | yes | - | - |
| mysql | tcp | yes | yes | `mysql_auth_plugin`, `mysql_client_ssl`, `mysql_tls_supported` |
| nats | tcp | yes | yes | - |
| netbios-ss | tcp | yes | - | - |
| netflow | udp | yes | n/a (one-way) | - |
| ntp | udp | yes | - | - |
| opcua | tcp | yes | yes | `opcua_message`, `opcua_protocol_version` |
| openvpn | tcp/udp | yes | yes | `openvpn_control`, `tls_auth` |
| pop3 | tcp | yes | yes | - |
| postgresql | tcp | yes | yes | `postgresql_auth`, `postgresql_error_class`, `postgresql_message` |
| pptp | tcp | yes | - | - |
| quic | udp | yes | - | `crypto_assembly`, `hostname`, `initial_protection`, `offered_alpn`, `packet_type`, `quic_version` |
| radius | udp | yes | yes | `radius_code` |
| rdp | tcp | yes | yes | `rdp_security_flags`, `rdp_selected_protocol` |
| resp | tcp | yes | - | - |
| rfb | tcp | yes | - | - |
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
| tftp | udp | yes | - | - |
| tls | tcp | yes | yes | `hostname`, `offered_alpn`, `requested_group`, `selected_alpn`, `selected_cipher`, `selected_group`, `selected_tls_version`, `tls_certificate_chain`, `tls_certificate_key`, `tls_certificate_lifetime_days`, `tls_certificate_self_issued`, `tls_certificate_signature`, `tls_certificate_version`, `tls_ech`, `tls_handshake`, `tls_offered_max_version` |
| tns | tcp | yes | yes | `tns_connect_data`, `tns_response`, `tns_version` |
| websocket | tcp | yes | yes | `websocket_masked`, `websocket_opcode` |
| wireguard | udp | yes | - | `message_type` |

70 families in the catalog, 70 with fixtures, 47 proven on both sides (or symmetric), 4 one-way; server side still unproven: dhcp, fastcgi, ftp, git, kafka, l2tp, memcached, mongodb, mqtt, netbios-ss, ntp, pptp, quic, resp, rfb, rsync, smtp, tftp, wireguard.
<!-- coverage-matrix:end -->
