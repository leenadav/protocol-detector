"""Public capability inventory. Metadata is never scanned in the packet path."""
from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class ProtocolSupport:
    family: str
    transports: Tuple[str, ...]
    scope: str
    profile: str
    requires_hint: bool = False  # True when no profile in this family auto-selects.


_SUPPORTED = (
    ProtocolSupport("websocket", ("tcp",), "frame_header", "One frame header after an HTTP Upgrade boundary (reached by the websocket-upgrade shift or an explicit candidate); payload not decoded", requires_hint=True),
    ProtocolSupport("ftp", ("tcp",), "initial_message", "Client command line (FTP-only verbs); shared USER/PASS/QUIT verbs are ambiguous with POP3 and resolved by session correlation with a 220 greeting"),
    ProtocolSupport("pop3", ("tcp",), "protocol_header/initial_message", "Server +OK/-ERR status line or POP3-only client command; shared verbs resolved by correlation"),
    ProtocolSupport("telnet", ("tcp",), "negotiation_request", "Two complete IAC option negotiation commands; terminal data not inspected"),
    ProtocolSupport("smb1", ("tcp",), "negotiation_request", "NetBIOS session header plus SMB_COM_NEGOTIATE request with dialect strings; maps to the smb application"),
    ProtocolSupport("netbios-ss", ("tcp",), "negotiation_request", "NetBIOS session request with two first-level encoded names; names not emitted"),
    ProtocolSupport("kerberos", ("tcp", "udp"), "initial_message/datagram", "KDC AS-REQ/TGS-REQ ASN.1 framing (pvno 5, msg-type, req-body); principals and pre-authentication unverified"),
    ProtocolSupport("tacacs-plus", ("tcp",), "protocol_header", "TACACS+ header for the first packet of a session; START body lengths when unencrypted"),
    ProtocolSupport("wireguard", ("udp",), "datagram", "Handshake initiation/response/cookie message sizes and reserved bytes; no key or tunnel claim"),
    ProtocolSupport("openvpn", ("tcp", "udp"), "initial_message/datagram", "Client hard-reset control packet (plain or tls-auth layout); no key exchange claim"),
    ProtocolSupport("pptp", ("tcp",), "negotiation_request", "Start-Control-Connection-Request (156 bytes); names not emitted"),
    ProtocolSupport("l2tp", ("udp",), "datagram", "L2TPv2 SCCRQ control message with Message Type AVP first"),
    ProtocolSupport("ssdp", ("udp",), "datagram", "M-SEARCH/NOTIFY/response HTTPU header block with SSDP headers"),
    ProtocolSupport("netflow", ("udp",), "datagram", "NetFlow v5 record framing and NetFlow v9 flowsets (reported as netflow/5, netflow/9)"),
    ProtocolSupport("ipfix", ("udp",), "datagram", "IPFIX (RFC 7011) message header and set framing, validated by the shared flow-export validator"),
    ProtocolSupport("sflow", ("udp",), "datagram", "sFlow v5 datagram with IPv4 agent and bounded sample headers"),
    ProtocolSupport("modbus", ("tcp",), "request_header", "MBAP header and public function request PDU shapes; transaction ids above 0x01ff need a hint"),
    ProtocolSupport("dnp3", ("tcp",), "protocol_header", "Data link frame with header and block CRCs verified"),
    ProtocolSupport("bacnet", ("udp",), "datagram", "BVLC function/length and NPDU version/control framing"),
    ProtocolSupport("iso-tsap", ("tcp",), "negotiation_request", "TPKT/X.224 connection request with TSAP parameters (RFC 1006); shares the TPKT route with RDP"),
    ProtocolSupport("s7comm", ("tcp",), "protocol_header", "One S7 PDU in a COTP data TPDU after the ISO-TSAP connection (reached by the cotp-connect shift or an explicit candidate): header, ROSCTR, public function codes, setup communication fields; addresses and values not decoded", requires_hint=True),
    ProtocolSupport("ethernet-ip", ("tcp", "udp"), "protocol_header/datagram", "Encapsulation header with RegisterSession/list/data commands; CIP not decoded"),
    ProtocolSupport("iec-104", ("tcp",), "protocol_header", "APCI U-format start frames automatically; I/S formats with a hint"),
    ProtocolSupport("kafka", ("tcp",), "request_header", "Request header for ApiVersions/Metadata/Produce/Fetch/SaslHandshake and similar first requests"),
    ProtocolSupport("cql", ("tcp",), "protocol_header", "Cassandra native protocol v4 STARTUP/OPTIONS"),
    ProtocolSupport("rtp", ("udp",), "datagram", "Hint required: RTP v2 fixed header, CSRC and extension framing", True),
    ProtocolSupport("quic", ("udp",), "datagram", "QUIC v1/v2 Initial (client protection removed with public Initial keys; ClientHello SNI/ALPN as offers) and Version Negotiation; no handshake completion, server packets or 0-RTT"),
    ProtocolSupport("ikev2", ("udp",), "datagram", "IKE_SA_INIT initiator: bounded SA/KE/nonce, AES-CBC/GCM and MODP14..18 offers, optional non-ESP marker; no authentication or established IPsec claim"),
    ProtocolSupport("dtls", ("udp",), "datagram", "DTLS1.2 complete epoch-zero ClientHello in one record/datagram; bounded extensions, client assertions only; no fragments, negotiation or decryption"),
    ProtocolSupport("dcerpc", ("tcp",), "bind_request", "Connection-oriented v5.0 unfragmented Bind, NDR 2.0/NDR64 1.0 offers; no authentication, replies, stub decoding or product identity"),
    ProtocolSupport("giop", ("tcp",), "request_header/locate_request", "GIOP 1.2 unfragmented KeyAddr Request/LocateRequest; bounded CDR, opaque arguments and service contexts; no replies or object identity"),
    ProtocolSupport("git", ("tcp",), "service_request", "Native Git pkt-line service request; bounded pathname, optional DNS/IPv4 host and extra parameters; no packfile, server or negotiated-version validation"),
    ProtocolSupport("radius", ("udp",), "datagram", "Hint required: Access-Request PAP/CHAP/State with supported attributes; no authenticator verification or EAP", True),
    ProtocolSupport("fastcgi", ("tcp",), "initial_params", "v1 BEGIN_REQUEST plus complete PARAMS stream; one request, zero reserved fields, no response/body semantics"),
    ProtocolSupport("rsync", ("tcp",), "protocol_header", "Daemon greeting, final protocols 27..32; version/digest offers, no authentication or transfer"),
    ProtocolSupport("tds", ("tcp",), "negotiation_request/negotiation_response", "MSSQL TDS 7.x PRELOGIN packet (client) or its response (server): header, option table, VERSION/ENCRYPTION mandatory, fixed option lengths; instance names, thread, trace and nonce bytes not emitted; no LOGIN7 or query stream"),
    ProtocolSupport("tns", ("tcp",), "negotiation_request/negotiation_response", "Oracle Net CONNECT (client) or ACCEPT/REFUSE/RESEND (server) packet: header checksums zero, versions 308..319, connect data offset/length consistency, printable descriptor; descriptor contents not emitted; no DATA packets or authentication"),
    ProtocolSupport("mysql", ("tcp",), "protocol_header", "Hint required: modern HandshakeV10, 21-byte challenge and native/caching_sha2/sha256 plugin", True),
    ProtocolSupport("mongodb", ("tcp",), "initial_message", "Hint required: uncompressed OP_MSG body/sequences, bounded BSON and CRC-32C; no telemetry or command semantics", True),
    ProtocolSupport("stomp", ("tcp",), "protocol_header", "1.1/1.2 CONNECT/STOMP/CONNECTED, complete empty-body NUL-terminated frame"),
    ProtocolSupport("nats", ("tcp",), "protocol_header", "INFO/CONNECT with required typed JSON fields; bounded extensions, no message bodies"),
    ProtocolSupport("imap", ("tcp",), "protocol_header", "Server CAPABILITY or OK/PREAUTH with explicit IMAP4rev1/2 capability; no commands/authentication"),
    ProtocolSupport("rdp", ("tcp",), "negotiation_request", "TPKT/X.224 with RDP negotiation, optional cookie/correlation; no routing token or session"),
    ProtocolSupport("bgp", ("tcp",), "negotiation_request", "BGPv4 OPEN, standard optional lengths and capability framing"),
    ProtocolSupport("smb2", ("tcp",), "negotiation_request", "Direct TCP SMB2/3 NEGOTIATE including 3.1.1 context framing; offers only"),
    ProtocolSupport("snmp", ("udp",), "datagram", "v1/v2c Get/GetNext/GetBulk read requests; v3 messages (USM header, plaintext read/report or encrypted scoped PDU); no responses or traps"),
    ProtocolSupport("tftp", ("udp",), "datagram", "RRQ/WRQ with bounded options; no transfer state"),
    ProtocolSupport("ntp", ("udp",), "datagram", "Hint required: v3/v4 base client/server header, no extensions/authentication", True),
    ProtocolSupport("http", ("tcp",), "initial_message", "HTTP/1.0 and 1.1 start-line/headers"),
    ProtocolSupport("http2", ("tcp",), "initial_message", "Client preface plus initial SETTINGS; no HPACK"),
    ProtocolSupport("tls", ("tcp",), "initial_message/server_hello/hello_retry_request", "ClientHello plus bounded TLS1.2/1.3 server hello/retry profiles; optional leaf-certificate structure after a TLS 1.2 ServerHello (`certificates`); selections unauthenticated, no decryption"),
    ProtocolSupport("ssh", ("tcp",), "initial_message", "Leading SSH-2.0/1.99 identification"),
    ProtocolSupport("socks5", ("tcp",), "initial_message/negotiation_response", "Client no-auth offer plus request, or server method selection plus reply; subnegotiation and tunnel unverified"),
    ProtocolSupport("opcua", ("tcp",), "negotiation_request/negotiation_response", "OPC UA TCP connection messages Hello, Acknowledge, Error and ReverseHello: little-endian size, buffer minimums, bounded printable opc.tcp URLs and reasons (not emitted); no secure channel"),
    ProtocolSupport("smtp", ("tcp",), "initial_message", "EHLO/HELO only; ambiguous 220 banners unknown"),
    ProtocolSupport("mqtt", ("tcp",), "initial_message", "3.1.1/5.0 CONNECT; MQTT5 CONNECT/Will property validation"),
    ProtocolSupport("resp", ("tcp",), "initial_message", "Non-null bulk-string request array; no product inference"),
    ProtocolSupport("amqp", ("tcp",), "protocol_header", "Plain 0-9-1/1.0 version header only"),
    ProtocolSupport("dns", ("tcp", "udp"), "initial_message/datagram", "QUERY opcode, one question; TCP length prefixes >=512 require dns hint"),
    ProtocolSupport("stun", ("tcp", "udp"), "initial_message/datagram", "Binding method; attributes and optional fingerprint, no HMAC validation"),
    ProtocolSupport("dhcp", ("udp",), "datagram", "DHCPv4 types 1..8, no overloaded options"),
    ProtocolSupport("coap", ("udp",), "datagram", "CoAP v1 framing, token <=8; tiny messages require coap hint"),
    ProtocolSupport("syslog", ("udp",), "datagram", "RFC5424 version 1 header/structured data; no RFC3164"),
    ProtocolSupport("postgresql", ("tcp",), "initial_message/negotiation_request", "v3.0..3.2 startup or SSL/GSS request; no authentication"),
    ProtocolSupport("rfb", ("tcp",), "protocol_header", "RFB 3.3/3.7/3.8 banner; no VNC security exchange"),
    ProtocolSupport("bittorrent", ("tcp",), "initial_message", "68-byte peer handshake; encrypted transport unsupported"),
    ProtocolSupport("memcached", ("tcp",), "initial_message", "Selected binary request commands 0x00..0x10; no SASL/text/meta"),
    ProtocolSupport("ldap", ("tcp",), "initial_message", "LDAPv3 BindRequest, simple/SASL; no controls or searches"),
    ProtocolSupport("sip", ("tcp", "udp"), "initial_headers/datagram", "SIP/2.0 required header framing; no dialogue/body semantics"),
    ProtocolSupport("rtsp", ("tcp",), "initial_headers", "RTSP/1.0 and 2.0 header framing; no RTP/media decoding"),
)


def supported_protocols():
    return _SUPPORTED
