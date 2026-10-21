"""Explicit-candidate database profiles; arbitrary length bytes are not signatures."""
import re
import struct
from .bson import BSONValidator, i32
from .extended import UnsupportedPrefix
from .framing import FrameParser
from .parsers import BudgetError, ParseError


class MySQLParser(FrameParser):
    header_size = 4
    protocol_name = 'mysql'
    scope = 'protocol_header'

    def frame_size(self, header):
        size = int.from_bytes(header[:3], 'little')
        if header[3] == 1 and size == 32:
            return 36  # client SSLRequest answering the server handshake
        if header[3] != 0:
            raise ParseError('MySQL initial server handshake requires sequence zero')
        if size < 32:
            raise ParseError('MySQL packet shorter than modern handshake profile')
        return size + 4

    def validate(self, data):
        if data[3] == 1:
            return self._ssl_request(data[4:])
        if data[4] != 10:
            raise UnsupportedPrefix('Only MySQL server HandshakeV10 is supported')
        end = data.find(b'\0', 5, min(len(data), 134))
        if end <= 5 or any(byte < 33 or byte > 126 for byte in data[5:end]):
            raise ParseError('Invalid MySQL server version field')
        pos = end + 1
        if pos + 31 > len(data):
            raise ParseError('Truncated MySQL handshake fields')
        # connection id(4), first scramble(8), filler(1), lower flags(2),
        # charset(1), status(2), upper flags(2), auth length(1), reserved(10).
        if data[pos + 12] or not data[pos + 15] or any(data[pos + 21:pos + 31]):
            raise ParseError('Invalid MySQL filler, charset or reserved fields')
        capabilities = int.from_bytes(data[pos + 13:pos + 15], 'little') | (int.from_bytes(data[pos + 18:pos + 20], 'little') << 16)
        if capabilities & 0x88200 != 0x88200:
            raise UnsupportedPrefix('MySQL profile requires protocol-4.1, secure-connection and plugin-auth capabilities')
        if data[pos + 20] != 21:
            raise UnsupportedPrefix('MySQL profile supports 21-byte authentication challenges only')
        pos += 31
        if pos + 13 >= len(data) or data[pos + 12] != 0:
            raise ParseError('Invalid MySQL second challenge length or terminator')
        plugin = data[pos + 13:]
        if not plugin.endswith(b'\0') or b'\0' in plugin[:-1]:
            raise ParseError('Invalid MySQL authentication plugin framing')
        if plugin[:-1] not in (b'mysql_native_password', b'caching_sha2_password', b'sha256_password'):
            raise UnsupportedPrefix('MySQL authentication plugin outside supported handshake profile')
        self.reason = 'MySQL modern server handshake validated; advertised version/capabilities, authentication and commands unverified'
        self.extra_evidence = (('mysql_tls_supported', str(bool(capabilities & 0x800)).lower(), 'server_handshake', 'offered'),)

    def _ssl_request(self, payload):
        """Protocol::SSLRequest: capability flags with CLIENT_SSL, max packet, charset, 23 reserved bytes."""
        capabilities = int.from_bytes(payload[:4], 'little')
        if capabilities & 0xa00 != 0xa00:
            raise ParseError('MySQL SSLRequest requires CLIENT_PROTOCOL_41 and CLIENT_SSL')
        if not payload[8]:
            raise ParseError('MySQL SSLRequest character set must be nonzero')
        if any(payload[9:28]):
            raise ParseError('MySQL SSLRequest reserved bytes must be zero')  # bytes 28..31 may carry MariaDB extended capabilities
        self.scope = 'negotiation_request'
        self.reason = 'MySQL client SSLRequest validated; TLS follows, authentication unverified'
        self.extra_evidence = (('mysql_client_ssl', 'requested', 'ssl_request', 'structural'),)
        self.shift = ('mysql-sslrequest', 'tls')


def _crc_table():
    table = []
    for value in range(256):
        for _ in range(8):
            value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
        table.append(value)
    tables = [tuple(table)]
    for _ in range(7):
        tables.append(tuple((value >> 8) ^ table[value & 255] for value in tables[-1]))
    return tuple(tables)


_CRC32C = _crc_table()


def crc32c(data):
    value = 0xffffffff
    t0, t1, t2, t3, t4, t5, t6, t7 = _CRC32C
    view = memoryview(data)
    end = len(view) & ~7
    # Eight bytes per iteration; explicit little-endian unpacking keeps results
    # independent of host byte order and alignment. Tables are built once.
    for first, second in struct.iter_unpack('<II', view[:end]):
        first ^= value
        value = (t7[first & 255] ^ t6[(first >> 8) & 255] ^ t5[(first >> 16) & 255] ^ t4[first >> 24]
                 ^ t3[second & 255] ^ t2[(second >> 8) & 255] ^ t1[(second >> 16) & 255] ^ t0[second >> 24])
    for byte in view[end:]:
        value = (value >> 8) ^ t0[(value ^ byte) & 255]
    return value ^ 0xffffffff


class MongoDBParser(FrameParser):
    header_size = 20
    protocol_name = 'mongodb'

    def frame_size(self, header):
        size, _, response_to, opcode, flags = struct.unpack('<iiiiI', header)
        if opcode != 2013:
            raise UnsupportedPrefix('Only uncompressed MongoDB OP_MSG is supported')
        if size < 26:
            raise ParseError('MongoDB message shorter than OP_MSG body framing')
        if flags & 0xfffc:
            raise UnsupportedPrefix('Unknown required MongoDB OP_MSG flag')
        if response_to and flags & 0x10000:
            raise ParseError('MongoDB reply cannot set exhaustAllowed')
        if flags & 1 and size - 4 > self.config.max_crc32c_bytes:
            # Stop from the fixed header, before accumulating the body or
            # computing a checksum whose cost is outside the caller's budget.
            raise BudgetError('MongoDB CRC-32C input exceeds checksum budget')
        self.flags, self.response = flags, bool(response_to)
        return size

    def validate(self, data):
        flags, response = self.flags, self.response
        limit = len(data) - (4 if flags & 1 else 0)
        if flags & 1:
            if crc32c(memoryview(data)[:limit]) != int.from_bytes(data[limit:], 'little'):
                raise ParseError('MongoDB CRC-32C mismatch')
        validator = BSONValidator(data, self.config)
        pos, sections, body, sequences = 20, 0, None, set()
        while pos < limit:
            kind, pos = data[pos], pos + 1
            sections += 1
            if sections > min(self.config.max_headers, 128):
                raise BudgetError('MongoDB section count exceeds budget')
            if kind == 0:
                if body is not None:
                    raise ParseError('MongoDB OP_MSG requires exactly one body')
                pos, body = validator.document(pos, limit, collect=True)
            elif kind == 1:
                size = i32(data, pos, limit)
                end = pos + size
                if size < 5 or end > limit:
                    raise ParseError('Invalid MongoDB document-sequence length')
                name, pos = validator.cstring(pos + 4, end)
                if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name):
                    raise UnsupportedPrefix('MongoDB sequence profile supports simple field identifiers only')
                if name in sequences:
                    raise ParseError('Duplicate MongoDB sequence identifier')
                sequences.add(name)
                while pos < end:
                    pos, _ = validator.document(pos, end)
            else:
                raise UnsupportedPrefix('MongoDB profile supports body and document-sequence sections only')
        if body is None:
            raise ParseError('MongoDB OP_MSG has no body section')
        if sequences.intersection(body):
            raise ParseError('MongoDB sequence also exists in body')
        if not response:
            first = next(iter(body), '')
            if not first or first.startswith('$') or '$db' not in body:
                raise ParseError('MongoDB request requires a command first and a database field')
            kind, start, end = body['$db']
            if kind != 2 or end - start <= 5 or b'\0' in data[start + 4:end - 1]:
                raise ParseError('MongoDB database must be a nonempty BSON string without NUL')
        self.reason = 'MongoDB OP_MSG framing and BSON validated; command semantics, authentication and subsequent messages unverified'
