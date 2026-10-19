"""Bounded prefix dispatch, independent of ports and application-rule count.

This is a small fixed classifier, not a general multi-pattern matching engine.
Ambiguous HTTP method prefixes stay undecided until a distinguishing byte.
"""
from .extended import H2_PREFACE
from .git_transport import HEX as GIT_HEX

LOOKAHEAD = 24
_table = ["unknown"] * 256
for _byte in b"!#$%&'*+.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-":
    _table[_byte] = "text"
for _byte, _family in ((64, "rsync"), (3, "rdp"), (22, "tls"), (5, "socks5"), (16, "mqtt"), (19, "bittorrent"), (128, "memcached"), (255, "bgp")):
    _table[_byte] = _family
for _byte in (0, 1, 48, 82, 80, 65, 42, 67, 83):
    _table[_byte] = "ambiguous"
FIRST_BYTE = tuple(_table)
del _table, _byte, _family
_STOMP_STARTS = (b'CONNECT\n', b'CONNECT\r\n', b'CONNECTED\n', b'CONNECTED\r\n', b'STOMP\n', b'STOMP\r\n')


def select(prefix):
    """Return a family or None; prefix contains 1..LOOKAHEAD bytes."""
    first = prefix[0]
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
        # RPC minor version zero cannot be a valid SOCKS5 method count.
        return 'dcerpc' if prefix[1] == 0 else 'socks5'
    family = FIRST_BYTE[first]
    if family != "ambiguous":
        return family
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
        if prefix[4:8] == b"\x21\x12\xa4\x42":
            return "stun"
        code = int.from_bytes(prefix[4:8], "big")
        if first == 0 and (code in (80877103, 80877104) or (code >> 16 == 3 and code & 65535 <= 2)):
            return "postgresql"
        if int.from_bytes(prefix[:2], "big") < 12:
            return "unknown"
        if len(prefix) < 14:
            return None
        from .wire import dns_probe
        return "dns" if dns_probe(prefix[2:14]) else "unknown"
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
