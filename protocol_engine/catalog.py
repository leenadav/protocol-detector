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
    ProtocolSupport("radius", ("udp",), "datagram", "Hint required: Access-Request PAP/CHAP/State with supported attributes; no authenticator verification or EAP", True),
    ProtocolSupport("fastcgi", ("tcp",), "initial_params", "v1 BEGIN_REQUEST plus complete PARAMS stream; one request, zero reserved fields, no response/body semantics"),
    ProtocolSupport("rsync", ("tcp",), "protocol_header", "Daemon greeting, final protocols 27..32; version/digest offers, no authentication or transfer"),
    ProtocolSupport("mysql", ("tcp",), "protocol_header", "Hint required: modern HandshakeV10, 21-byte challenge and native/caching_sha2/sha256 plugin", True),
    ProtocolSupport("mongodb", ("tcp",), "initial_message", "Hint required: uncompressed OP_MSG body/sequences, bounded BSON and CRC-32C; no telemetry or command semantics", True),
    ProtocolSupport("stomp", ("tcp",), "protocol_header", "1.1/1.2 CONNECT/STOMP/CONNECTED, complete empty-body NUL-terminated frame"),
    ProtocolSupport("nats", ("tcp",), "protocol_header", "INFO/CONNECT with required typed JSON fields; bounded extensions, no message bodies"),
    ProtocolSupport("imap", ("tcp",), "protocol_header", "Server CAPABILITY or OK/PREAUTH with explicit IMAP4rev1/2 capability; no commands/authentication"),
    ProtocolSupport("rdp", ("tcp",), "negotiation_request", "TPKT/X.224 with RDP negotiation, optional cookie/correlation; no routing token or session"),
    ProtocolSupport("bgp", ("tcp",), "negotiation_request", "BGPv4 OPEN, standard optional lengths and capability framing"),
    ProtocolSupport("smb2", ("tcp",), "negotiation_request", "Direct TCP SMB2/3 NEGOTIATE including 3.1.1 context framing; offers only"),
    ProtocolSupport("snmp", ("udp",), "datagram", "v1/v2c Get/GetNext/GetBulk read requests; no v3, responses or traps"),
    ProtocolSupport("tftp", ("udp",), "datagram", "RRQ/WRQ with bounded options; no transfer state"),
    ProtocolSupport("ntp", ("udp",), "datagram", "Hint required: v3/v4 base client/server header, no extensions/authentication", True),
    ProtocolSupport("http", ("tcp",), "initial_message", "HTTP/1.0 and 1.1 start-line/headers"),
    ProtocolSupport("http2", ("tcp",), "initial_message", "Client preface plus initial SETTINGS; no HPACK"),
    ProtocolSupport("tls", ("tcp",), "initial_message", "ClientHello only; no decryption or handshake authentication"),
    ProtocolSupport("ssh", ("tcp",), "initial_message", "Leading SSH-2.0/1.99 identification"),
    ProtocolSupport("socks5", ("tcp",), "initial_message", "No-auth offer plus client request; server unverified"),
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
