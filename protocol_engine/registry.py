"""Immutable parser factories, built once outside the data path."""
from types import MappingProxyType
from .parsers import TLSParser
from .extended import HTTP2Parser, HTTP2ServerParser, Socks5Parser, TextParser
from .messaging import AMQPParser, MQTTParser, RESPParser
from .binary import BitTorrentParser, DNSParser, LDAPParser, MemcachedParser, PostgreSQLParser, RFBParser, STUNParser

from .network import BGPParser, SMB2Parser
from .stomp import STOMPParser
from .remote import RDPParser
from .fastcgi import FastCGIParser
from .rsync import RsyncParser
from .git_transport import GitParser, GitTextParser
from .dcerpc import DCERPCParser
from .giop import GIOPParser
from .database import MySQLParser, MongoDBParser
from .session_text import TelnetParser
from .windows import KerberosParser, NetBIOSSessionParser, SMB1Parser, TACACSParser
from .vpn import OpenVPNParser, PPTPParser
from .ics import COTPParser, DNP3Parser, ENIPParser, IEC104Parser, ModbusParser, TPKTParser
from .datainfra import CQLParser, KafkaParser
from .upgrade import WebSocketParser
from .s7 import S7Parser

PARSERS = MappingProxyType({
    "dcerpc": DCERPCParser, "giop": GIOPParser, "git": GitParser, "fastcgi": FastCGIParser, "rsync": RsyncParser,
    "mysql": MySQLParser, "mongodb": MongoDBParser,
    "stomp": STOMPParser, "rdp": RDPParser,
    "bgp": BGPParser, "smb2": SMB2Parser, "tls": TLSParser, "text": TextParser, "http2": HTTP2Parser, "socks5": Socks5Parser,
    "mqtt": MQTTParser, "resp": RESPParser, "amqp": AMQPParser,
    "postgresql": PostgreSQLParser, "rfb": RFBParser, "bittorrent": BitTorrentParser,
    "memcached": MemcachedParser, "ldap": LDAPParser, "dns": DNSParser, "stun": STUNParser,
    "telnet": TelnetParser, "smb1": SMB1Parser, "netbios-ss": NetBIOSSessionParser, "kerberos": KerberosParser,
    "tacacs-plus": TACACSParser, "openvpn": OpenVPNParser, "pptp": PPTPParser, "modbus": ModbusParser, "dnp3": DNP3Parser,
    "iso-tsap": COTPParser, "ethernet-ip": ENIPParser, "iec-104": IEC104Parser, "kafka": KafkaParser, "cql": CQLParser,
    "websocket": WebSocketParser, "s7comm": S7Parser, "http2-server": HTTP2ServerParser,
})

# Automatic ambiguity routes are not public candidate hints.
FACTORIES = MappingProxyType(dict(PARSERS, git_text=GitTextParser, tpkt=TPKTParser))
