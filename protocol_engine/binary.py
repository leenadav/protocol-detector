"""Initial binary stream messages. All advertised sizes are bounded before growth."""
import re
from .framing import FrameParser, ber_field, ber_length
from .parsers import ParseError
from .extended import UnsupportedPrefix
from .wire import stun


class PostgreSQLParser(FrameParser):
    header_size = 8
    protocol_name = "postgresql"

    def frame_size(self, header):
        return int.from_bytes(header[:4], "big")

    def validate(self, data):
        code = int.from_bytes(data[4:8], "big")
        if code in (80877103, 80877104):
            if len(data) != 8:
                raise ParseError("PostgreSQL encryption request length must be eight")
            self.scope = "negotiation_request"
            self.reason = "PostgreSQL SSL/GSS negotiation request validated; encryption not established"
            if code == 80877103:
                self.shift = ("postgresql-sslrequest", "tls")  # after the server's 'S' the client starts TLS
            return
        if code >> 16 != 3 or code & 65535 > 2:
            raise UnsupportedPrefix("Unsupported PostgreSQL startup version")
        if not data.endswith(b"\x00\x00"):
            raise ParseError("PostgreSQL startup parameters require final terminator")
        fields = data[8:-1].split(b"\x00")
        if fields[-1] != b"" or len(fields) % 2 != 1:
            raise ParseError("Invalid PostgreSQL startup name/value pairs")
        seen = set()
        user = False
        if len(fields) > 257:
            from .parsers import BudgetError
            raise BudgetError("PostgreSQL startup parameter count exceeds limit")
        for index in range(0, len(fields) - 1, 2):
            key, value = fields[index:index + 2]
            if not re.fullmatch(rb"[A-Za-z_][A-Za-z0-9_.]*", key) or key in seen:
                raise ParseError("Invalid or duplicate PostgreSQL parameter name")
            seen.add(key)
            if key == b"user":
                user = bool(value)
        if not user:
            raise ParseError("PostgreSQL startup requires a user")
        self.reason = "PostgreSQL v3 startup parameter framing validated; authentication and queries unverified"


class RFBParser(FrameParser):
    header_size = 12
    protocol_name = "rfb"
    scope = "protocol_header"

    def frame_size(self, header):
        return 12

    def validate(self, data):
        if data not in (b"RFB 003.003\n", b"RFB 003.007\n", b"RFB 003.008\n"):
            raise UnsupportedPrefix("Unsupported RFB version banner")
        self.reason = "RFB 3.3/3.7/3.8 version banner validated; VNC security exchange unverified"


class BitTorrentParser(FrameParser):
    header_size = 20
    protocol_name = "bittorrent"

    def frame_size(self, header):
        if header != b"\x13BitTorrent protocol":
            raise ParseError("Invalid BitTorrent protocol identifier")
        return 68

    def validate(self, data):
        self.reason = "BitTorrent peer handshake framing validated; info-hash and peer identity unverified"


class MemcachedParser(FrameParser):
    header_size = 24
    protocol_name = "memcached/binary"

    def frame_size(self, header):
        if header[0] != 0x80 or header[5:8] != b"\x00\x00\x00":
            raise ParseError("Invalid Memcached binary request header")
        body = int.from_bytes(header[8:12], "big")
        key, extras, command = int.from_bytes(header[2:4], "big"), header[4], header[1]
        if key > 250 or body < key + extras:
            raise ParseError("Invalid Memcached key/extras/body sizes")
        value = body - key - extras
        if command in (0, 4, 9, 12, 13):
            valid = key > 0 and extras == 0 and value == 0
        elif command in (1, 2, 3):
            valid = key > 0 and extras == 8
        elif command in (5, 6):
            valid = key > 0 and extras == 20 and value == 0
        elif command in (7, 10, 11):
            valid = body == 0
        elif command == 8:
            valid = key == 0 and extras in (0, 4) and value == 0
        elif command in (14, 15):
            valid = key > 0 and extras == 0
        elif command == 16:
            valid = extras == 0 and value == 0
        else:
            raise UnsupportedPrefix("Unsupported Memcached binary command")
        if not valid:
            raise ParseError("Memcached command contradicts field sizes")
        return 24 + body

    def validate(self, data):
        self.reason = "Memcached binary request framing validated; values and server reply unverified"


class LDAPParser(FrameParser):
    header_size = 6  # sufficient for a definite BER length using up to four bytes
    protocol_name = "ldap/3"

    def frame_size(self, header):
        if header[0] != 0x30:
            raise ParseError("LDAP requires a BER SEQUENCE")
        size, start = ber_length(header, 1, len(header))
        return start + size

    def validate(self, data):
        message, end = ber_field(data, 0, len(data), 0x30)
        if end != len(data):
            raise ParseError("Trailing LDAP data")
        identifier, pos = ber_field(message, 0, len(message), 2)
        if not 1 <= len(identifier) <= 4 or identifier[0] & 128 or int.from_bytes(identifier, "big") == 0:
            raise ParseError("Invalid LDAP request message ID")
        if pos >= len(message) or message[pos] != 0x60:
            raise UnsupportedPrefix("Only initial LDAP BindRequest is supported")
        bind, pos = ber_field(message, pos, len(message), 0x60)
        if pos != len(message):
            raise UnsupportedPrefix("LDAP controls are outside the initial bind profile")
        version, cursor = ber_field(bind, 0, len(bind), 2)
        if version != b"\x03":
            raise UnsupportedPrefix("Only LDAP v3 bind is supported")
        dn, cursor = ber_field(bind, cursor, len(bind), 4)
        try:
            dn.decode("utf-8")
        except UnicodeError:
            raise ParseError("Invalid LDAP DN UTF-8") from None
        if cursor >= len(bind):
            raise ParseError("LDAP bind missing authentication field")
        if bind[cursor] == 0x80:
            _, cursor = ber_field(bind, cursor, len(bind), 0x80)
        elif bind[cursor] == 0xa3:
            sasl, cursor = ber_field(bind, cursor, len(bind), 0xa3)
            mechanism, off = ber_field(sasl, 0, len(sasl), 4)
            if mechanism and not re.fullmatch(rb"[A-Z0-9_-]{1,20}", mechanism):
                raise ParseError("Invalid LDAP SASL mechanism")
            if off < len(sasl):
                _, off = ber_field(sasl, off, len(sasl), 4)
            if off != len(sasl):
                raise ParseError("Trailing LDAP SASL fields")
        else:
            raise UnsupportedPrefix("Unsupported LDAP authentication choice")
        if cursor != len(bind):
            raise ParseError("Trailing LDAP bind fields")
        self.reason = "LDAPv3 BindRequest BER fields validated; credentials, DN semantics and authentication unverified"


class DNSParser(FrameParser):
    header_size = 2
    protocol_name = "dns"

    def frame_size(self, header):
        size = int.from_bytes(header, "big")
        if size < 12:
            raise ParseError("DNS TCP message shorter than DNS header")
        return size + 2

    def validate(self, data):
        from .wire import dns_details, dns_message_evidence
        self.protocol_name, self.reason, qname, qtype = dns_details(data[2:], self.config)
        self.extra_evidence = tuple((e.field, e.value, "message", e.strength) for e in dns_message_evidence(data[2:]))
        if self.config.retain_contexts:
            self.contexts = {"dns-req-query-name": qname, "dns-req-query-type": qtype}


class STUNParser(FrameParser):
    header_size = 20
    protocol_name = "stun"

    def frame_size(self, header):
        if header[0] & 0xc0 or header[4:8] != b"\x21\x12\xa4\x42":
            raise ParseError("Invalid STUN stream header")
        return 20 + int.from_bytes(header[2:4], "big")

    def validate(self, data):
        self.protocol_name, self.reason = stun(data, self.config)
