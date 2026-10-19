"""Immutable parser factories, built once outside the data path."""
from types import MappingProxyType
from .parsers import TLSParser
from .extended import HTTP2Parser, Socks5Parser, TextParser
from .messaging import AMQPParser, MQTTParser, RESPParser
from .binary import BitTorrentParser, DNSParser, LDAPParser, MemcachedParser, PostgreSQLParser, RFBParser, STUNParser

from .network import BGPParser, SMB2Parser
from .stomp import STOMPParser
from .remote import RDPParser
from .fastcgi import FastCGIParser
from .rsync import RsyncParser
from .database import MySQLParser, MongoDBParser

PARSERS = MappingProxyType({
    "fastcgi": FastCGIParser, "rsync": RsyncParser,
    "mysql": MySQLParser, "mongodb": MongoDBParser,
    "stomp": STOMPParser, "rdp": RDPParser,
    "bgp": BGPParser, "smb2": SMB2Parser, "tls": TLSParser, "text": TextParser, "http2": HTTP2Parser, "socks5": Socks5Parser,
    "mqtt": MQTTParser, "resp": RESPParser, "amqp": AMQPParser,
    "postgresql": PostgreSQLParser, "rfb": RFBParser, "bittorrent": BitTorrentParser,
    "memcached": MemcachedParser, "ldap": LDAPParser, "dns": DNSParser, "stun": STUNParser,
})
