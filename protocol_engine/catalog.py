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
    ProtocolSupport("smb1", ("tcp",), "negotiation_request", "NetBIOS session header plus SMB_COM_NEGOTIATE request (dialect strings) or response (NT LM 0.12, LAN Manager or core layout; challenge and domain not emitted); maps to the smb application"),
    ProtocolSupport("netbios-ss", ("tcp",), "negotiation_request", "NetBIOS session request with two first-level encoded names; names not emitted"),
    ProtocolSupport("kerberos", ("tcp", "udp"), "initial_message/datagram", "KDC AS/TGS-REQ, AS/TGS-REP and KRB-ERROR ASN.1 framing (pvno 5, msg-type per tag, ordered fields, error code reported); principals, tickets and pre-authentication unverified and never emitted"),
    ProtocolSupport("tacacs-plus", ("tcp",), "protocol_header", "TACACS+ header for the first two packets of a session (START seq 1, REPLY seq 2); body lengths and status codes checked when unencrypted, never emitted"),
    ProtocolSupport("wireguard", ("udp",), "datagram", "Handshake initiation/response/cookie message sizes and reserved bytes; no key or tunnel claim; message type reported for both directions"),
    ProtocolSupport("openvpn", ("tcp", "udp"), "initial_message/datagram", "Client or server hard-reset control packet (plain or tls-auth layout, server acknowledgement array and remote session id); no key exchange claim"),
    ProtocolSupport("pptp", ("tcp",), "negotiation_request", "Start-Control-Connection-Request (156 bytes); names not emitted; Start-Control-Connection-Reply with result code reported"),
    ProtocolSupport("l2tp", ("udp",), "datagram", "L2TPv2 SCCRQ control message with Message Type AVP first; SCCRP with the peer's tunnel id, message kind reported"),
    ProtocolSupport("ssdp", ("udp",), "datagram", "M-SEARCH/NOTIFY/response HTTPU header block with SSDP headers"),
    ProtocolSupport("netflow", ("udp",), "datagram", "NetFlow v5 record framing and NetFlow v9 flowsets (reported as netflow/5, netflow/9)"),
    ProtocolSupport("ipfix", ("udp",), "datagram", "IPFIX (RFC 7011) message header and set framing, validated by the shared flow-export validator"),
    ProtocolSupport("sflow", ("udp",), "datagram", "sFlow v5 datagram with IPv4 agent and bounded sample headers"),
    ProtocolSupport("modbus", ("tcp",), "request_header", "MBAP header with public function request PDU shapes, normal response shapes (byte count and data) and exception responses (code reported); transaction ids above 0x01ff need a hint"),
    ProtocolSupport("dnp3", ("tcp",), "protocol_header", "Data link frame with header and block CRCs verified"),
    ProtocolSupport("bacnet", ("udp",), "datagram", "BVLC function/length and NPDU version/control framing"),
    ProtocolSupport("iso-tsap", ("tcp",), "negotiation_request", "TPKT/X.224 connection request with TSAP parameters (RFC 1006); shares the TPKT route with RDP"),
    ProtocolSupport("s7comm", ("tcp",), "protocol_header", "One S7 PDU in a COTP data TPDU after the ISO-TSAP connection (reached by the cotp-connect shift or an explicit candidate): header, ROSCTR, public function codes, setup communication fields; addresses and values not decoded", requires_hint=True),
    ProtocolSupport("ethernet-ip", ("tcp", "udp"), "protocol_header/datagram", "Encapsulation header with RegisterSession/list/data commands; CIP not decoded"),
    ProtocolSupport("iec-104", ("tcp",), "protocol_header", "APCI U-format start frames automatically; I/S formats with a hint"),
    ProtocolSupport("kafka", ("tcp",), "request_header", "Request header for ApiVersions/Metadata/Produce/Fetch/SaslHandshake and similar first requests"),
    ProtocolSupport("cql", ("tcp",), "protocol_header", "Cassandra native protocol v4 STARTUP/OPTIONS requests and ERROR/READY/AUTHENTICATE/SUPPORTED responses"),
    ProtocolSupport("rtp", ("udp",), "datagram", "Hint required: RTP v2 fixed header, CSRC and extension framing", True),
    ProtocolSupport("quic", ("udp",), "datagram", "QUIC v1/v2 Initial (client protection removed with public Initial keys; ClientHello SNI/ALPN as offers) and Version Negotiation; no handshake completion, server packets or 0-RTT"),
    ProtocolSupport("ikev2", ("udp",), "datagram", "IKE_SA_INIT initiator or responder: bounded SA/KE/nonce, AES-CBC/GCM and MODP14..18 offers or the single selected proposal, optional CERTREQ and non-ESP marker; no authentication or established IPsec claim"),
    ProtocolSupport("dtls", ("udp",), "datagram", "DTLS1.2 complete epoch-zero ClientHello, HelloVerifyRequest or ServerHello in one record/datagram; bounded extensions, assertions only; no fragments, encrypted epochs or decryption"),
    ProtocolSupport("dcerpc", ("tcp",), "bind_request", "Connection-oriented v5.0 unfragmented Bind, Bind_ack (result list, accepted NDR 2.0/NDR64 1.0) and Bind_nak; no authentication, stub decoding or product identity"),
    ProtocolSupport("giop", ("tcp",), "request_header/locate_request", "GIOP 1.2 unfragmented KeyAddr Request/LocateRequest and Reply/LocateReply (status reported); bounded CDR, opaque arguments, bodies and service contexts; no object identity"),
    ProtocolSupport("git", ("tcp",), "service_request", "Native Git pkt-line service request; bounded pathname, optional DNS/IPv4 host and extra parameters; no packfile, server or negotiated-version validation; server ref advertisement (object id, refname, capabilities framed) or protocol v2 banner, message kind reported"),
    ProtocolSupport("radius", ("udp",), "datagram", "Hint required: Access-Request PAP/CHAP/State, Access-Accept/Reject/Challenge with the attributes each code allows; code reported, no authenticator verification or EAP decoding", True),
    ProtocolSupport("fastcgi", ("tcp",), "initial_params", "v1 BEGIN_REQUEST plus complete PARAMS stream; one request, zero reserved fields, no response/body semantics; application-server STDOUT/STDERR/END_REQUEST records, record kind reported"),
    ProtocolSupport("rsync", ("tcp",), "protocol_header", "Daemon greeting, final protocols 27..32; version/digest offers, no authentication or transfer"),
    ProtocolSupport("tds", ("tcp",), "negotiation_request/negotiation_response", "MSSQL TDS 7.x PRELOGIN packet (client) or its response (server): header, option table, VERSION/ENCRYPTION mandatory, fixed option lengths; instance names, thread, trace and nonce bytes not emitted; no LOGIN7 or query stream"),
    ProtocolSupport("tns", ("tcp",), "negotiation_request/negotiation_response", "Oracle Net CONNECT (client) or ACCEPT/REFUSE/RESEND (server) packet: header checksums zero, versions 308..319, connect data offset/length consistency, printable descriptor; descriptor contents not emitted; no DATA packets or authentication"),
    ProtocolSupport("mysql", ("tcp",), "protocol_header", "Hint required: server HandshakeV10 (21-byte challenge, native/caching_sha2/sha256 plugin), client SSLRequest or HandshakeResponse41 (capabilities, bounded user/database/plugin/attributes, plugin reported, names not emitted)", True),
    ProtocolSupport("mongodb", ("tcp",), "initial_message", "Hint required: uncompressed OP_MSG body/sequences, bounded BSON and CRC-32C; no telemetry or command semantics; request/reply direction reported from responseTo", True),
    ProtocolSupport("stomp", ("tcp",), "protocol_header", "1.1/1.2 CONNECT/STOMP/CONNECTED, complete empty-body NUL-terminated frame"),
    ProtocolSupport("nats", ("tcp",), "protocol_header", "INFO/CONNECT with required typed JSON fields; bounded extensions, no message bodies"),
    ProtocolSupport("imap", ("tcp",), "protocol_header", "Server CAPABILITY or OK/PREAUTH with explicit IMAP4rev1/2 capability; no commands/authentication"),
    ProtocolSupport("rdp", ("tcp",), "negotiation_request", "TPKT/X.224 with RDP negotiation, optional cookie/correlation; no routing token or session"),
    ProtocolSupport("bgp", ("tcp",), "negotiation_request", "BGPv4 OPEN, standard optional lengths and capability framing"),
    ProtocolSupport("smb2", ("tcp",), "negotiation_request", "Direct TCP SMB2/3 NEGOTIATE request (offers) or response (selected dialect, signing mode, 3.1.1 contexts); security token not emitted"),
    ProtocolSupport("snmp", ("udp",), "datagram", "v1/v2c and v3 messages with every standard PDU kind (Get, GetNext, GetBulk, Set, Response, Trap, Inform, Report; v3 USM header and plaintext or encrypted scoped PDU); PDU kind reported, values never emitted"),
    ProtocolSupport("tftp", ("udp",), "datagram", "RRQ/WRQ with bounded options; no transfer state; server OACK with the standard numeric options, ERROR with the tftp hint only (DATA/ACK too weak to identify), packet kind reported"),
    ProtocolSupport("ntp", ("udp",), "datagram", "Hint required: v3/v4 base client/server header, no extensions/authentication; mode (client/server) reported", True),
    ProtocolSupport("http", ("tcp",), "initial_message", "HTTP/1.0 and 1.1 start-line/headers; method, content-type class and a dns-message accept reported"),
    ProtocolSupport("onc-rpc", ("tcp", "udp"), "initial_message/response_header/datagram", "ONC RPC v2 CALL (program label, version, credential flavor; AUTH_NONE/AUTH_SYS structure) and REPLY (accept or reject status) over TCP last-fragment records or UDP; arguments and results not decoded"),
    ProtocolSupport("diameter", ("tcp",), "negotiation_request/negotiation_response", "Capabilities-Exchange-Request/Answer on the base application: header flags, every AVP header, mandatory AVPs, Result-Code class; identities and product name not emitted"),
    ProtocolSupport("zmtp", ("tcp",), "initial_message", "ZMTP 3.0/3.1 64-byte greeting (signature, version, mechanism, as-server flag, zero filler); mechanism and role reported"),
    ProtocolSupport("bolt", ("tcp",), "initial_message/negotiation_response", "Neo4j Bolt handshake (magic, four version ranges) automatically; the four-byte server version response with the bolt hint"),
    ProtocolSupport("http2", ("tcp",), "initial_message", "Client preface plus initial SETTINGS, then the first HEADERS block (HPACK decoded: method, scheme, authority host, content-type class; server :status)"),
    ProtocolSupport("tls", ("tcp",), "initial_message/server_hello/hello_retry_request", "ClientHello plus bounded TLS1.2/1.3 server hello/retry profiles; optional leaf-certificate structure after a TLS 1.2 ServerHello (`certificates`); encrypted_client_hello extension structure reported as `tls_ech`; selections unauthenticated, no decryption"),
    ProtocolSupport("ssh", ("tcp",), "initial_message", "Leading SSH-2.0/1.99 identification"),
    ProtocolSupport("socks5", ("tcp",), "initial_message/negotiation_response", "Client no-auth offer plus request, or server method selection plus reply; subnegotiation and tunnel unverified"),
    ProtocolSupport("opcua", ("tcp",), "negotiation_request/negotiation_response", "OPC UA TCP connection messages Hello, Acknowledge, Error and ReverseHello: little-endian size, buffer minimums, bounded printable opc.tcp URLs and reasons (not emitted); no secure channel"),
    ProtocolSupport("smtp", ("tcp",), "initial_message", "EHLO/HELO only; ambiguous 220 banners unknown"),
    ProtocolSupport("mqtt", ("tcp",), "initial_message", "3.1.1/5.0 CONNECT; MQTT5 CONNECT/Will property validation"),
    ProtocolSupport("resp", ("tcp",), "initial_message", "Non-null bulk-string request array; no product inference"),
    ProtocolSupport("amqp", ("tcp",), "protocol_header", "Plain 0-9-1/1.0 version header only; broker Connection.Start frame (properties, mechanisms and locales framed, not emitted)"),
    ProtocolSupport("dns", ("tcp", "udp"), "initial_message/datagram", "Query or response with QUERY opcode and one question, bounded record walk; message kind and rcode reported; TCP length prefixes >=512 require dns hint"),
    ProtocolSupport("stun", ("tcp", "udp"), "initial_message/datagram", "Binding method; attributes and optional fingerprint, no HMAC validation"),
    ProtocolSupport("dhcp", ("udp",), "datagram", "DHCPv4 types 1..8, no overloaded options; operation and message type reported"),
    ProtocolSupport("coap", ("udp",), "datagram", "CoAP v1 framing, token <=8; tiny messages require coap hint"),
    ProtocolSupport("syslog", ("udp", "tcp"), "datagram/initial_message", "RFC5424 version 1 header/structured data; no RFC3164; over TCP one RFC 6587 octet-counting or non-transparent frame"),
    ProtocolSupport("xmpp", ("tcp",), "initial_message/negotiation_response", "RFC 6120 stream header in either direction (optional XML declaration, client/server/component namespace, version, to/from domain as hostname); features, STARTTLS and stanzas not inspected"),
    ProtocolSupport("postgresql", ("tcp",), "initial_message/negotiation_request", "v3.0..3.2 startup or SSL/GSS request (client); Authentication*, ErrorResponse and NegotiateProtocolVersion (server) with method, SQLSTATE class reported; salts, SASL data and messages not emitted"),
    ProtocolSupport("rfb", ("tcp",), "protocol_header", "RFB 3.3/3.7/3.8 banner; no VNC security exchange"),
    ProtocolSupport("bittorrent", ("tcp",), "initial_message", "68-byte peer handshake; encrypted transport unsupported"),
    ProtocolSupport("memcached", ("tcp",), "initial_message", "Selected binary request commands 0x00..0x10; no SASL/text/meta; binary responses (status and sizes consistent with the command, status reported)"),
    ProtocolSupport("ldap", ("tcp",), "initial_message", "LDAPv3 BindRequest, simple/SASL, and BindResponse (result code reported; DN, diagnostic and SASL credentials not emitted); no controls or searches"),
    ProtocolSupport("sip", ("tcp", "udp"), "initial_headers/datagram", "SIP/2.0 required header framing; no dialogue/body semantics"),
    ProtocolSupport("rtsp", ("tcp",), "initial_headers", "RTSP/1.0 and 2.0 header framing; no RTP/media decoding"),
)


def supported_protocols():
    return _SUPPORTED
