"""Application catalog: App-ID style attributes for every recognized family.

The catalog is administrative metadata looked up by name once a structural
identification exists. It is never scanned in the packet path, carries no
detection logic and does not turn an observation into a product claim.
Categories, technologies, risk scores and characteristics follow the vocabulary
used by application-aware firewalls so that policies written in that vocabulary
can be evaluated against this engine's output.
"""
from dataclasses import dataclass
from types import MappingProxyType
from typing import Optional, Tuple

CATEGORIES = MappingProxyType({
    "business-systems": ("auth-service", "database", "general-business", "ics-protocol", "management",
                         "software-development", "storage-backup"),
    "collaboration": ("email", "instant-messaging", "voip-video", "web-posting"),
    "general-internet": ("file-sharing", "internet-utility"),
    "media": ("audio-streaming", "gaming", "photo-video"),
    "networking": ("encrypted-tunnel", "infrastructure", "ip-protocol", "proxy", "remote-access", "routing"),
    "custom": ("configured-mapping", "custom-signature"),
    "unknown": ("unknown", "session-outcome"),
})
TECHNOLOGIES = ("network-protocol", "client-server", "browser-based", "peer-to-peer", "unknown")
CHARACTERISTICS = ("evasive", "excessive-bandwidth", "prone-to-misuse", "transfers-files",
                   "tunnels-other-applications", "used-by-malware", "has-known-vulnerabilities",
                   "widely-used", "pervasive", "cleartext-credentials")
# Session outcomes are reported with the application vocabulary but are not applications.
OUTCOMES = ("unknown-tcp", "unknown-udp", "incomplete", "insufficient-data", "not-applicable")


@dataclass(frozen=True)
class Application:
    name: str
    category: str
    subcategory: str
    technology: str
    risk: int
    description: str
    characteristics: Tuple[str, ...] = ()
    standard_ports: Tuple[str, ...] = ()
    secure_ports: Tuple[str, ...] = ()
    implicitly_uses: Tuple[str, ...] = ()
    depends_on: Tuple[str, ...] = ()
    container: Optional[str] = None
    aliases: Tuple[str, ...] = ()

    @property
    def has_ports(self):
        return bool(self.standard_ports or self.secure_ports)

    def uses_port(self, transport, port):
        """True when transport/port is a documented standard or secure port."""
        table = _PORT_TABLES.get(self.name)
        if table is None:
            table = _PORT_TABLES[self.name] = _port_table(self.standard_ports + self.secure_ports)
        exact, ranges, dynamic = table.get(transport, _EMPTY_PORTS)
        return dynamic or port in exact or any(low <= port <= high for low, high in ranges)


_EMPTY_PORTS = (frozenset(), (), False)
_PORT_TABLES = {}


def _port_table(entries):
    """Per-transport exact set, range list and dynamic flag, computed once per application."""
    table = {}
    for entry in entries:
        kind, _, spec = entry.partition("/")
        exact, ranges, dynamic = table.get(kind, (set(), [], False))
        if spec == "dynamic":
            dynamic = True
        else:
            low, _, high = spec.partition("-")
            if high:
                ranges.append((int(low), int(high)))
            else:
                exact.add(int(low))
        table[kind] = (exact, ranges, dynamic)
    return {kind: (frozenset(exact), tuple(ranges), dynamic) for kind, (exact, ranges, dynamic) in table.items()}


def _app(name, category, subcategory, technology, risk, description, characteristics=(), ports=(), secure=(),
         implicitly_uses=(), depends_on=(), container=None, aliases=()):
    return Application(name, category, subcategory, technology, risk, description, tuple(characteristics),
                       tuple(ports), tuple(secure), tuple(implicitly_uses), tuple(depends_on), container, tuple(aliases))


_ENTRIES = (
    # Generic applications and session outcomes.
    _app("web-browsing", "general-internet", "internet-utility", "browser-based", 4,
         "HTTP/1.x or HTTP/2 traffic without a more specific application mapping",
         ("widely-used", "pervasive", "transfers-files", "tunnels-other-applications", "used-by-malware",
          "has-known-vulnerabilities", "prone-to-misuse", "cleartext-credentials"), ("tcp/80", "tcp/8080"), ("tcp/443",),
         aliases=("http",)),
    _app("http-proxy", "networking", "proxy", "browser-based", 4, "HTTP CONNECT tunnel request to a forward proxy",
         ("tunnels-other-applications", "evasive", "widely-used", "prone-to-misuse"), ("tcp/8080", "tcp/3128", "tcp/8000"), ("tcp/443",),
         implicitly_uses=("web-browsing",)),
    _app("websocket", "general-internet", "internet-utility", "browser-based", 3, "WebSocket frames after an HTTP/1.1 Upgrade",
         ("tunnels-other-applications", "widely-used"), ("tcp/80",), ("tcp/443",), implicitly_uses=("web-browsing",)),
    _app("grpc", "business-systems", "general-business", "client-server", 2,
         "gRPC request over a structurally validated HTTP/2 connection: POST with an application/grpc content-type (an asserted header)",
         ("widely-used", "tunnels-other-applications"), ("tcp/80",), ("tcp/443",), implicitly_uses=("web-browsing",)),
    _app("ssl", "networking", "encrypted-tunnel", "browser-based", 4,
         "TLS handshake without decrypted inner application; ALPN and SNI are client offers",
         ("widely-used", "pervasive", "tunnels-other-applications", "used-by-malware", "has-known-vulnerabilities",
          "evasive"), ("tcp/443",), aliases=("tls",)),
    _app("dtls", "networking", "encrypted-tunnel", "client-server", 3,
         "DTLS 1.2 ClientHello over UDP; inner application not inferred",
         ("tunnels-other-applications",), ("udp/443", "udp/4433")),
    _app("quic", "networking", "encrypted-tunnel", "browser-based", 3,
         "QUIC v1/v2 Initial packet; ClientHello recovered from Initial protection when possible; HTTP/3 is an ALPN offer",
         ("tunnels-other-applications", "widely-used", "evasive"), ("udp/443",), aliases=("http3", "quic-base")),
    _app("unknown-tcp", "unknown", "unknown", "unknown", 5,
         "TCP payload outside every supported structural profile", ("evasive",)),
    _app("unknown-udp", "unknown", "unknown", "unknown", 5,
         "UDP payload outside every supported structural profile", ("evasive",)),
    _app("incomplete", "unknown", "session-outcome", "unknown", 1,
         "Handshake not completed, or completed without any application payload"),
    _app("insufficient-data", "unknown", "session-outcome", "unknown", 1,
         "Payload observed but inspection ended before a profile could complete"),
    _app("not-applicable", "unknown", "session-outcome", "unknown", 1,
         "Observation integrity lost or inspection not applicable; no identification is retained"),
    # Supported families.
    _app("ssh", "networking", "encrypted-tunnel", "client-server", 4,
         "SSH 2.0 identification line", ("tunnels-other-applications", "transfers-files", "widely-used", "evasive",
                                          "used-by-malware"), ("tcp/22",)),
    _app("smtp", "collaboration", "email", "client-server", 5, "SMTP client EHLO/HELO",
         ("transfers-files", "widely-used", "used-by-malware", "has-known-vulnerabilities", "prone-to-misuse",
          "cleartext-credentials"), ("tcp/25", "tcp/587"), ("tcp/465",)),
    _app("imap", "collaboration", "email", "client-server", 4, "IMAP4rev1/rev2 server capabilities",
         ("transfers-files", "widely-used", "has-known-vulnerabilities", "cleartext-credentials"), ("tcp/143",), ("tcp/993",)),
    _app("dns", "networking", "infrastructure", "network-protocol", 4, "DNS query/response framing",
         ("widely-used", "pervasive", "tunnels-other-applications", "used-by-malware", "evasive"),
         ("udp/53", "tcp/53"), ("tcp/853",)),
    _app("mqtt", "networking", "infrastructure", "client-server", 2, "MQTT 3.1.1/5.0 CONNECT",
         ("cleartext-credentials",), ("tcp/1883",), ("tcp/8883",)),
    _app("resp", "business-systems", "database", "client-server", 3,
         "RESP command array as used by Redis-compatible servers; no product inference",
         ("prone-to-misuse", "has-known-vulnerabilities", "cleartext-credentials"), ("tcp/6379",), aliases=("redis",)),
    _app("amqp", "networking", "infrastructure", "client-server", 2, "AMQP 0-9-1/1.0 version header",
         (), ("tcp/5672",), ("tcp/5671",)),
    _app("stomp", "networking", "infrastructure", "client-server", 2, "STOMP 1.1/1.2 handshake",
         ("cleartext-credentials",), ("tcp/61613",), ("tcp/61614",)),
    _app("nats", "networking", "infrastructure", "client-server", 2, "NATS INFO/CONNECT", ("cleartext-credentials",), ("tcp/4222",)),
    _app("stun", "networking", "infrastructure", "network-protocol", 2, "STUN Binding", ("evasive",),
         ("udp/3478", "tcp/3478"), ("tcp/5349", "udp/5349")),
    _app("turn", "networking", "infrastructure", "network-protocol", 3, "TURN Allocate, Refresh, CreatePermission, ChannelBind or TCP-relay methods over STUN framing",
         ("evasive", "tunnels-other-applications", "prone-to-misuse"), ("udp/3478", "tcp/3478"), ("tcp/5349", "udp/5349"),
         implicitly_uses=("stun",)),
    _app("netbios-ns", "networking", "infrastructure", "network-protocol", 2, "NetBIOS name service query, registration, release, WACK or refresh in the DNS message layout",
         ("has-known-vulnerabilities", "prone-to-misuse"), ("udp/137",), aliases=("nbns",)),
    _app("mdns", "networking", "infrastructure", "network-protocol", 2, "Multicast DNS query, probe, known-answer query, response or announcement (.local names, QU and cache-flush bits)",
         ("pervasive", "prone-to-misuse"), ("udp/5353",), aliases=("bonjour", "zeroconf")),
    _app("llmnr", "networking", "infrastructure", "network-protocol", 3, "Link-Local Multicast Name Resolution query or response (explicit candidate)",
         ("has-known-vulnerabilities", "prone-to-misuse"), ("udp/5355",)),
    _app("postgresql", "business-systems", "database", "client-server", 3, "PostgreSQL v3 startup or SSL/GSS request",
         ("transfers-files", "cleartext-credentials"), ("tcp/5432",), aliases=("postgres",)),
    _app("mssql-db", "business-systems", "database", "client-server", 3, "MSSQL TDS 7.x PRELOGIN exchange",
         ("transfers-files", "has-known-vulnerabilities", "widely-used"), ("tcp/1433",), aliases=("mssql", "tds", "sql-server", "ms-sql")),
    _app("oracle", "business-systems", "database", "client-server", 3, "Oracle Net (TNS) connect exchange",
         ("transfers-files", "has-known-vulnerabilities", "widely-used"), ("tcp/1521",), aliases=("oracle-db", "tns", "sqlnet", "oracle-net")),
    _app("mysql", "business-systems", "database", "client-server", 3, "MySQL HandshakeV10 (explicit candidate)",
         ("transfers-files", "has-known-vulnerabilities"), ("tcp/3306",)),
    _app("mongodb", "business-systems", "database", "client-server", 3, "MongoDB OP_MSG (explicit candidate)",
         ("transfers-files", "prone-to-misuse"), ("tcp/27017",)),
    _app("memcached", "business-systems", "database", "client-server", 3, "Memcached binary request",
         ("prone-to-misuse", "has-known-vulnerabilities"), ("tcp/11211", "udp/11211")),
    _app("ldap", "business-systems", "auth-service", "client-server", 2, "LDAPv3 BindRequest, BindResponse, ExtendedRequest or ExtendedResponse (StartTLS announces a shift to TLS)",
         ("cleartext-credentials",), ("tcp/389",), ("tcp/636",)),
    _app("irc", "collaboration", "instant-messaging", "client-server", 4, "IRC registration lines (NICK, USER, CAP, PASS) and server opening lines (NOTICE, PING, numeric replies)",
         ("evasive", "used-by-malware", "transfers-files", "cleartext-credentials"), ("tcp/6667", "tcp/6660", "tcp/6661", "tcp/6662", "tcp/6663", "tcp/6664", "tcp/6665", "tcp/6666", "tcp/6668", "tcp/6669"), ("tcp/6697",)),
    _app("ms-rpc-over-http", "business-systems", "general-business", "client-server", 3, "RPC over HTTP (RPC_CONNECT, RPC_IN_DATA, RPC_OUT_DATA methods; Outlook Anywhere) request",
         ("tunnels-other-applications",), ("tcp/80",), ("tcp/443",), implicitly_uses=("web-browsing",)),
    _app("radius", "business-systems", "auth-service", "client-server", 2, "RADIUS Access-Request (explicit candidate)",
         ("has-known-vulnerabilities",), ("udp/1812", "udp/1813", "udp/1645", "udp/1646")),
    _app("vnc", "networking", "remote-access", "client-server", 4, "RFB 3.3/3.7/3.8 version banner",
         ("prone-to-misuse", "has-known-vulnerabilities", "evasive"), ("tcp/5900-5909",), aliases=("rfb",)),
    _app("rdp", "networking", "remote-access", "client-server", 4, "RDP X.224 connection request with negotiation",
         ("prone-to-misuse", "has-known-vulnerabilities", "tunnels-other-applications", "transfers-files", "widely-used"),
         ("tcp/3389", "udp/3389"), aliases=("ms-rdp",)),
    _app("socks", "networking", "proxy", "client-server", 4, "SOCKS5 client greeting and request or server selection and reply",
         ("evasive", "tunnels-other-applications", "used-by-malware", "prone-to-misuse"), ("tcp/1080",), aliases=("socks5",)),
    _app("bittorrent", "general-internet", "file-sharing", "peer-to-peer", 5, "BitTorrent peer handshake",
         ("evasive", "excessive-bandwidth", "transfers-files", "used-by-malware", "widely-used", "prone-to-misuse"),
         ("tcp/dynamic", "udp/dynamic")),
    _app("sip", "collaboration", "voip-video", "client-server", 3, "SIP/2.0 request/response headers",
         ("has-known-vulnerabilities",), ("udp/5060", "tcp/5060"), ("tcp/5061",)),
    _app("rtsp", "media", "photo-video", "client-server", 3, "RTSP 1.0/2.0 headers", ("excessive-bandwidth",), ("tcp/554",)),
    _app("bgp", "networking", "routing", "network-protocol", 2, "BGPv4 OPEN", ("has-known-vulnerabilities",), ("tcp/179",)),
    _app("smb", "networking", "infrastructure", "client-server", 4, "SMB2/3 direct TCP NEGOTIATE",
         ("transfers-files", "widely-used", "used-by-malware", "has-known-vulnerabilities"), ("tcp/445",),
         aliases=("ms-ds-smb", "ms-ds-smbv2", "ms-ds-smbv3", "cifs", "smb2")),
    _app("snmp", "networking", "infrastructure", "network-protocol", 2, "SNMPv1/v2c read requests and SNMPv3 messages",
         ("has-known-vulnerabilities", "cleartext-credentials"), ("udp/161", "udp/162")),
    _app("tftp", "general-internet", "file-sharing", "client-server", 4, "TFTP read/write request",
         ("transfers-files", "has-known-vulnerabilities"), ("udp/69",)),
    _app("ntp", "networking", "infrastructure", "network-protocol", 2, "NTP v3/v4 header (explicit candidate)",
         ("prone-to-misuse",), ("udp/123",)),
    _app("dhcp", "networking", "infrastructure", "network-protocol", 2, "DHCPv4 message", ("widely-used",), ("udp/67", "udp/68")),
    _app("coap", "networking", "infrastructure", "client-server", 2, "CoAP v1 message", (), ("udp/5683",), ("udp/5684",)),
    _app("syslog", "business-systems", "management", "client-server", 2, "RFC 5424 syslog message", (), ("udp/514", "tcp/514"), ("tcp/6514",)),
    _app("fastcgi", "business-systems", "general-business", "client-server", 2, "FastCGI BEGIN_REQUEST and PARAMS", (), ("tcp/9000",)),
    _app("rsync", "business-systems", "storage-backup", "client-server", 3, "rsync daemon greeting", ("transfers-files",), ("tcp/873",)),
    _app("sun-rpc", "networking", "infrastructure", "client-server", 3, "ONC RPC v2 call or reply for a program outside the named ones",
         ("has-known-vulnerabilities", "prone-to-misuse"), ("tcp/dynamic", "udp/dynamic"), aliases=("onc-rpc", "rpc")),
    _app("portmapper", "networking", "infrastructure", "client-server", 3, "ONC RPC portmapper/rpcbind (program 100000)",
         ("has-known-vulnerabilities", "prone-to-misuse"), ("tcp/111", "udp/111"), implicitly_uses=("sun-rpc",), aliases=("rpcbind",)),
    _app("nfs", "business-systems", "storage-backup", "client-server", 3, "NFS, mount, lock manager, status monitor or NFS ACL program over ONC RPC",
         ("transfers-files", "has-known-vulnerabilities", "widely-used"), ("tcp/2049", "udp/2049", "tcp/dynamic", "udp/dynamic"),
         implicitly_uses=("sun-rpc",), depends_on=("portmapper",)),
    _app("diameter", "business-systems", "auth-service", "client-server", 2, "Diameter capabilities exchange (CER/CEA) on the base application",
         (), ("tcp/3868",), ("tcp/5868",)),
    _app("zeromq", "business-systems", "general-business", "peer-to-peer", 2, "ZMTP 3.x greeting; mechanism and bind side reported",
         ("cleartext-credentials",), ("tcp/dynamic",), aliases=("zmtp",)),
    _app("neo4j", "business-systems", "database", "client-server", 2, "Neo4j Bolt handshake", (), ("tcp/7687",), aliases=("bolt",)),
    _app("webdav", "general-internet", "file-sharing", "browser-based", 3, "HTTP request with a WebDAV method (PROPFIND, MKCOL, LOCK, ...)",
         ("transfers-files", "widely-used"), ("tcp/80",), ("tcp/443",), implicitly_uses=("web-browsing",)),
    _app("ipp", "business-systems", "general-business", "client-server", 2, "Internet Printing Protocol request or response carried in HTTP (application/ipp)",
         (), ("tcp/631",), ("tcp/631",), implicitly_uses=("web-browsing",)),
    _app("ocsp", "networking", "infrastructure", "client-server", 1, "OCSP request or response carried in HTTP (application/ocsp-request or -response)",
         ("widely-used",), ("tcp/80",), implicitly_uses=("web-browsing",)),
    _app("soap", "business-systems", "general-business", "browser-based", 2, "SOAP 1.2 envelope carried in HTTP (application/soap+xml); an asserted header class",
         ("widely-used",), ("tcp/80",), ("tcp/443",), implicitly_uses=("web-browsing",)),
    _app("x11", "networking", "remote-access", "client-server", 3, "X11 connection setup", ("has-known-vulnerabilities",), ("tcp/6000-6063",)),
    _app("spice", "networking", "remote-access", "client-server", 3, "SPICE link header (client message or server reply)", (), ("tcp/5900-5999",), ("tcp/5900-5999",)),
    _app("afp", "business-systems", "storage-backup", "client-server", 3, "Apple Filing Protocol session opening over DSI", ("transfers-files",), ("tcp/548",)),
    _app("omron-fins", "business-systems", "ics-protocol", "client-server", 3, "Omron FINS/TCP node address exchange or frame", ("has-known-vulnerabilities",), ("tcp/9600",), aliases=("fins",)),
    _app("rip", "networking", "routing", "peer-to-peer", 2, "RIP v1/v2 request or response", ("cleartext-credentials",), ("udp/520",)),
    _app("rtcp", "collaboration", "voip-video", "client-server", 1, "RTCP compound packet (explicit candidate)", (), ("udp/dynamic",)),
    _app("xmpp", "collaboration", "instant-messaging", "client-server", 3, "XMPP stream header (client, server or component stream)",
         ("widely-used", "transfers-files"), ("tcp/5222", "tcp/5269"), ("tcp/5223",), aliases=("jabber",)),
    _app("dns-over-https", "networking", "infrastructure", "browser-based", 3,
         "DNS message carried in HTTP (application/dns-message content or accept header over HTTP/1.x or HTTP/2); an asserted header class",
         ("evasive", "tunnels-other-applications"), ("tcp/443",), implicitly_uses=("web-browsing",), aliases=("doh",)),
    _app("git", "business-systems", "software-development", "client-server", 3, "Native Git service request",
         ("transfers-files",), ("tcp/9418",), aliases=("git-base",)),
    _app("giop", "business-systems", "general-business", "client-server", 2, "GIOP 1.2 request", (), ("tcp/dynamic",),
         aliases=("corba", "iiop")),
    _app("dce-rpc", "networking", "infrastructure", "client-server", 3, "DCE/RPC 5.0 bind",
         ("has-known-vulnerabilities",), ("tcp/135", "tcp/dynamic"), aliases=("msrpc", "msrpc-base", "dcerpc")),
    _app("ike", "networking", "encrypted-tunnel", "network-protocol", 2, "IKEv2 IKE_SA_INIT request",
         ("tunnels-other-applications",), ("udp/500", "udp/4500"), aliases=("ikev2", "ipsec-ike", "isakmp")),
    # v0.27 families
    _app("ftp", "general-internet", "file-sharing", "client-server", 4, "FTP client command (or 220 greeting correlated with a client command)",
         ("transfers-files", "cleartext-credentials", "widely-used", "has-known-vulnerabilities"), ("tcp/21",), ("tcp/990",)),
    _app("pop3", "collaboration", "email", "client-server", 4, "POP3 server status line or client command",
         ("cleartext-credentials", "transfers-files", "has-known-vulnerabilities"), ("tcp/110",), ("tcp/995",)),
    _app("telnet", "networking", "remote-access", "client-server", 4, "Telnet option negotiation",
         ("cleartext-credentials", "prone-to-misuse", "has-known-vulnerabilities", "used-by-malware"), ("tcp/23",)),
    _app("netbios-ss", "networking", "infrastructure", "client-server", 3, "NetBIOS session service request",
         ("has-known-vulnerabilities",), ("tcp/139",), aliases=("netbios-ssn",)),
    _app("kerberos", "business-systems", "auth-service", "client-server", 2, "Kerberos KDC AS-REQ/TGS-REQ",
         ("widely-used",), ("tcp/88", "udp/88"), aliases=("kerberos-base",)),
    _app("tacacs-plus", "business-systems", "auth-service", "client-server", 2, "TACACS+ first packet header",
         ("has-known-vulnerabilities",), ("tcp/49",), aliases=("tacacs",)),
    _app("wireguard", "networking", "encrypted-tunnel", "client-server", 3, "WireGuard handshake message sizes",
         ("tunnels-other-applications", "evasive"), ("udp/51820",)),
    _app("openvpn", "networking", "encrypted-tunnel", "client-server", 3, "OpenVPN client hard-reset control packet",
         ("tunnels-other-applications", "evasive"), ("udp/1194", "tcp/1194"), ("tcp/443",)),
    _app("pptp", "networking", "encrypted-tunnel", "client-server", 4, "PPTP start-control-connection request",
         ("tunnels-other-applications", "has-known-vulnerabilities"), ("tcp/1723",)),
    _app("l2tp", "networking", "encrypted-tunnel", "network-protocol", 3, "L2TPv2 SCCRQ control message",
         ("tunnels-other-applications",), ("udp/1701",)),
    _app("ssdp", "networking", "infrastructure", "network-protocol", 2, "SSDP M-SEARCH/NOTIFY over HTTPU",
         ("prone-to-misuse",), ("udp/1900",), aliases=("upnp",)),
    _app("netflow", "business-systems", "management", "client-server", 1, "NetFlow v5/v9 export datagram",
         (), ("udp/2055", "udp/9995", "udp/9996")),
    _app("ipfix", "business-systems", "management", "client-server", 1, "IPFIX export message", (), ("udp/4739",)),
    _app("sflow", "business-systems", "management", "client-server", 1, "sFlow v5 datagram", (), ("udp/6343",)),
    _app("modbus", "business-systems", "ics-protocol", "client-server", 3, "Modbus/TCP request",
         ("has-known-vulnerabilities", "prone-to-misuse"), ("tcp/502",)),
    _app("s7comm", "business-systems", "ics-protocol", "client-server", 3, "Siemens S7 PDU after the ISO-TSAP connection",
         ("has-known-vulnerabilities", "cleartext-credentials"), ("tcp/102",), (), implicitly_uses=("iso-tsap",), aliases=("s7", "siemens-s7")),
    _app("opc-ua", "business-systems", "ics-protocol", "client-server", 3, "OPC UA TCP connection messages",
         ("has-known-vulnerabilities", "transfers-files"), ("tcp/4840",), aliases=("opcua", "opc-ua-tcp", "opc")),
    _app("dnp3", "business-systems", "ics-protocol", "client-server", 3, "DNP3 link frame", ("has-known-vulnerabilities",), ("tcp/20000",)),
    _app("bacnet", "business-systems", "ics-protocol", "client-server", 3, "BACnet/IP BVLC/NPDU", ("has-known-vulnerabilities",), ("udp/47808",)),
    _app("iso-tsap", "business-systems", "ics-protocol", "client-server", 3, "ISO transport over TCP connection request (carries S7comm among others)",
         ("has-known-vulnerabilities",), ("tcp/102",), aliases=("cotp",)),
    _app("ethernet-ip", "business-systems", "ics-protocol", "client-server", 3, "EtherNet/IP encapsulation request",
         ("has-known-vulnerabilities",), ("tcp/44818", "udp/44818", "udp/2222"), aliases=("enip", "cip")),
    _app("iec-104", "business-systems", "ics-protocol", "client-server", 3, "IEC 60870-5-104 APCI", ("has-known-vulnerabilities",), ("tcp/2404",),
         aliases=("iec-60870-5-104",)),
    _app("kafka", "business-systems", "general-business", "client-server", 2, "Kafka request header", ("transfers-files",), ("tcp/9092",), ("tcp/9093",)),
    _app("cql", "business-systems", "database", "client-server", 2, "Cassandra native protocol v4 request", ("cleartext-credentials",), ("tcp/9042",),
         aliases=("cassandra",)),
    _app("rtp", "collaboration", "voip-video", "client-server", 2, "RTP header (explicit candidate)", ("excessive-bandwidth",), ("udp/dynamic",)),
)

# Engine protocol/encryption labels to catalog names. Versions after '/' never matter.
_PROTOCOL_NAMES = MappingProxyType({
    "http": "web-browsing", "http2": "web-browsing", "tls": "ssl", "dtls": "dtls", "quic": "quic", "smb1": "smb", "rfb": "vnc", "socks5": "socks", "smb2": "smb",
    "dcerpc": "dce-rpc", "ikev2": "ike", "tds": "mssql-db", "tns": "oracle", "opcua": "opc-ua",
    "onc-rpc": "sun-rpc", "zmtp": "zeromq", "bolt": "neo4j", "fins": "omron-fins",
})


def _validate(entries):
    names = {entry.name for entry in entries}
    if len(names) != len(entries):
        raise ValueError("Duplicate application name")
    aliases = {}
    for entry in entries:
        if entry.category not in CATEGORIES or entry.subcategory not in CATEGORIES[entry.category]:
            raise ValueError("Unknown category for " + entry.name)
        if entry.technology not in TECHNOLOGIES or not 1 <= entry.risk <= 5:
            raise ValueError("Invalid technology or risk for " + entry.name)
        if not set(entry.characteristics) <= set(CHARACTERISTICS):
            raise ValueError("Unknown characteristic for " + entry.name)
        for port in entry.standard_ports + entry.secure_ports:
            kind, _, spec = port.partition("/")
            if kind not in ("tcp", "udp") or not (spec == "dynamic" or all(
                    part.isdigit() and 1 <= int(part) <= 65535 for part in spec.split("-")) and len(spec.split("-")) <= 2):
                raise ValueError("Invalid port specification for " + entry.name)
        for reference in entry.implicitly_uses + entry.depends_on + ((entry.container,) if entry.container else ()):
            if reference not in names:
                raise ValueError("Unresolved application reference in " + entry.name)
        for alias in entry.aliases:
            if alias in names or alias in aliases:
                raise ValueError("Alias collides with an application name")
            aliases[alias] = entry.name
    return MappingProxyType({entry.name: entry for entry in entries}), MappingProxyType(aliases)


APPLICATIONS, ALIASES = _validate(_ENTRIES)


def application_name(protocol_name=None, encryption=None):
    """Catalog name for an engine protocol/encryption label, or None."""
    label = encryption or protocol_name
    if not label:
        return None
    base = label.split("/", 1)[0]
    name = _PROTOCOL_NAMES.get(base, base)
    return name if name in APPLICATIONS else None


def lookup(name):
    """Resolve a catalog name or alias to its Application, or None."""
    if name in APPLICATIONS:
        return APPLICATIONS[name]
    canonical = ALIASES.get(name)
    return APPLICATIONS[canonical] if canonical else None


def custom_application(name, container):
    """Administrative mapping (RuleIndex) presented as an application of its own.

    It inherits the container's technology/risk/characteristics and implicitly
    uses the container, mirroring how specific web applications imply the
    generic web-browsing/ssl applications they are carried in.
    """
    base = APPLICATIONS[container]
    return Application(name, "custom", "configured-mapping", base.technology, base.risk,
                       "Configured mapping carried over " + container, base.characteristics,
                       base.standard_ports, base.secure_ports, (container,), (), container, ())
