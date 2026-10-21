"""Bounded prefix dispatch, independent of ports and application-rule count.

This is a small fixed classifier, not a general multi-pattern matching engine.
Ambiguous HTTP method prefixes stay undecided until a distinguishing byte.
"""
from .extended import H2_PREFACE
from .git_transport import HEX as GIT_HEX
from .ics import enip_probe, modbus_probe
from .datainfra import kafka_probe
from .enterprise_db import tns_probe
from .opcua import OPCUA_MAGICS, opcua_probe

LOOKAHEAD = 24
_table = ["unknown"] * 256
for _byte in b"!#$%&'*+.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-":
    _table[_byte] = "text"
for _byte, _family in ((64, "rsync"), (3, "tpkt"), (22, "tls"), (5, "socks5"), (16, "mqtt"), (19, "bittorrent"), (128, "memcached"),
                       (0x81, "netbios-ss"), (0xc0, "tacacs-plus"), (0xc1, "tacacs-plus"), (0x12, "tds")):
    _table[_byte] = _family
for _byte in (0, 1, 48, 82, 80, 65, 42, 67, 83, 255, 4, 0x63, 0x64, 0x65, 0x66, 0x6f, 0x70, 0x68):
    _table[_byte] = "ambiguous"
FIRST_BYTE = tuple(_table)
del _table, _byte, _family
_STOMP_STARTS = (b'CONNECT\n', b'CONNECT\r\n', b'CONNECTED\n', b'CONNECTED\r\n', b'STOMP\n', b'STOMP\r\n')


def select(prefix):
    """Return a family or None; prefix contains 1..LOOKAHEAD bytes."""
    first = prefix[0]
    if first in (72, 65, 69, 82):  # OPC UA HELF/ACKF/ERRF/RHEF before the text and AMQP/RFB routes
        if len(prefix) < 8:
            if any(magic.startswith(prefix[:4]) for magic in OPCUA_MAGICS):
                return None
        elif opcua_probe(prefix):
            return 'opcua'
    if first == 71:  # GIOP is also a legal HTTP extension-method prefix.
        magic = b'GIOP'
        if len(prefix) <= 4 and magic.startswith(prefix):
            return None
        if prefix[:4] == magic and prefix[4] == 1:
            return 'giop'
    if first in GIT_HEX and all(byte in GIT_HEX for byte in prefix[:4]):
        if len(prefix) < 4:
            return None
        discriminator = prefix[4:8]
        if b'git-'.startswith(discriminator):
            return 'git_text' if len(discriminator) == 4 else None
    if first == 5:
        if len(prefix) < 2:
            return None
        if prefix[1] == 0x64:
            return 'dnp3'  # 0x0564 start bytes; SOCKS5 would announce 100 methods, DCE/RPC needs minor 0
        if prefix[1] == 0:
            # RPC minor version zero, or a SOCKS5 server selecting no authentication and replying
            # (05 REP 00 ATYP): a DCE/RPC packet would need type 5 (fault) with flags zero and a
            # big-endian data representation whose second byte is an address type, never first.
            if len(prefix) < 6:
                return None
            return 'socks5' if prefix[2] == 5 and prefix[3] <= 8 and prefix[4] == 0 and prefix[5] in (1, 3, 4) else 'dcerpc'
        return 'socks5'
    family = FIRST_BYTE[first]
    if family != "ambiguous":
        return family
    if first == 255:
        if len(prefix) < 2:
            return None
        if prefix[1] == 255:
            return 'bgp'
        if 0xf1 <= prefix[1] <= 0xfe:
            return 'telnet'
        return 'unknown'
    if first == 4:
        if len(prefix) < 5:
            return None
        if prefix[1] == 0 and prefix[4] == 0:
            return 'ethernet-ip'
        if prefix[1] & 1:
            # A TDS PRELOGIN response (type 4, EOM status, window 0, VERSION token first) versus a
            # compressed CQL request: CQL never compresses STARTUP/OPTIONS, and a body length with
            # both low bytes zero (bytes 7 and 8) would be at least 64 KiB, beyond any budget.
            if len(prefix) < 9:
                return None
            if prefix[7] == 0 and prefix[8] == 0:
                return 'tds'
        return 'cql'
    if first in (0x63, 0x64, 0x65, 0x66, 0x6f, 0x70):
        if len(prefix) < 2:
            return None
        if prefix[1] != 0:
            return 'text'
        if len(prefix) < 8:
            return None
        return 'ethernet-ip' if enip_probe(prefix) else 'unknown'
    if first == 0x68:
        if len(prefix) < 2:
            return None
        if prefix[1] != 4:
            return 'text'
        return 'iec-104' if len(prefix) >= 6 and prefix[2] & 3 == 3 and prefix[3:6] == b'\0\0\0' else ('text' if len(prefix) >= 6 else None)
    if first in (67, 83):
        # Common SSH/SMTP and HTTP C*/S* prefixes can leave immediately; only
        # CO... and ST... need the longer handshake discriminator.
        if len(prefix) > 1 and prefix[1] != (79 if first == 67 else 84):
            return 'text'
        for start in _STOMP_STARTS:
            if prefix.startswith(start):
                return 'stomp'
            if start.startswith(prefix):
                return None
        return 'text'
    if first in (0, 1):
        if len(prefix) < 8:
            return None
        # This conservative BEGIN_REQUEST header cannot be our DNS profile:
        # DNS QDCOUNT would be padding<<8, never one when reserved is zero.
        if first == 1 and prefix[1] == 1 and prefix[2:4] != b"\x00\x00" and prefix[4:6] == b"\x00\x08" and prefix[7] == 0:
            return "fastcgi"
        if first == 0 and prefix[4:8] == b"\xfeSMB":
            return "smb2"
        if first == 0 and prefix[4:8] == b"\xffSMB":
            return "smb1"
        if first == 0 and prefix[4:8] == b"\x1a\x2b\x3c\x4d":
            return "pptp"
        if prefix[4:8] == b"\x21\x12\xa4\x42":
            return "stun"
        if first == 0 and prefix[4] in (0x6a, 0x6c) and _kerberos_length(prefix):
            return "kerberos"
        if prefix[2:4] == b"\x00\x00" and prefix[4] in (1, 2, 4, 11) and prefix[5] == 0 and prefix[6:8] == b"\x00\x00":
            # Oracle Net header: length, checksum 0, type, reserved 0, header checksum 0.
            if prefix[4] != 11 and len(prefix) < 10:
                return None
            if tns_probe(prefix):
                return "tns"
        if modbus_probe(prefix):
            return "modbus"
        code = int.from_bytes(prefix[4:8], "big")
        if first == 0 and (code in (80877103, 80877104) or (code >> 16 == 3 and code & 65535 <= 2)):
            return "postgresql"
        if first == 0 and kafka_probe(prefix):
            return "kafka"
        if int.from_bytes(prefix[:2], "big") < 12:
            return "unknown"
        if len(prefix) < 14:
            return None
        from .wire import dns_probe
        if dns_probe(prefix[2:14]):
            return "dns"
        if prefix[2] in (0x38, 0x50) and 14 <= int.from_bytes(prefix[:2], "big") <= 1500 and prefix[3:11] != bytes(8):
            return "openvpn"
        return "unknown"
    if first == 48:  # BER SEQUENCE versus an HTTP method beginning with '0'.
        if len(prefix) < 2:
            return None
        width = 0 if prefix[1] < 128 else prefix[1] & 127
        if width > 4 or prefix[1] == 128:
            return "text"
        offset = 2 + width
        if len(prefix) <= offset:
            return None
        if prefix[offset] == 2:
            return "ldap"
    if first == 82:
        for version in (b"RFB 003.003\n", b"RFB 003.007\n", b"RFB 003.008\n"):
            if prefix.startswith(version):
                return "rfb"
            if version.startswith(prefix):
                return None
    if first == 80:  # PRI can also be an HTTP/1 extension method.
        if H2_PREFACE.startswith(prefix):
            return "http2" if len(prefix) == len(H2_PREFACE) else None
    elif first == 65:
        magic = b"AMQP\x00"
        if prefix.startswith(magic):
            return "amqp"
        if magic.startswith(prefix):
            return None
    elif first == 42:
        # RESP requests start *<positive decimal>CRLF. '*' is also an HTTP token.
        end = prefix.find(b"\r\n")
        if end >= 0 and prefix[1:end].isdigit():
            return "resp"
        digits = prefix[1:]
        if digits.endswith(b"\r"):
            digits = digits[:-1]
        if (not digits or digits.isdigit()) and len(prefix) < LOOKAHEAD:
            return None
    return "text"


def _kerberos_length(prefix):
    """TCP length prefix must equal the BER-encoded KDC-REQ size (tag + length + content)."""
    size = int.from_bytes(prefix[:4], "big")
    first = prefix[5]
    if first < 128:
        return size == 2 + first
    width = first & 127
    if not 1 <= width <= 3 or 6 + width > len(prefix):
        return False
    return size == 2 + width + int.from_bytes(prefix[6:6 + width], "big")
