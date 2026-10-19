"""Connection-oriented DCE/RPC 5.0 Bind, without authentication verifier.

Presentation offers only: NDR 2.0 / NDR64 1.0. UUIDs never establish product
identity; no server response, RPC stub decoding or negotiated limits are asserted.
"""
from uuid import UUID
from .framing import FrameParser
from .parsers import BudgetError, ParseError
from .extended import UnsupportedPrefix

# Construct wire constants once, never UUID objects per packet.
_SYNTAXES = {}
for _order in ('big', 'little'):
    _values = {}
    for _identifier, _version, _name in (
            ('8a885d04-1ceb-11c9-9fe8-08002b104860', 2, 'ndr/2.0'),
            ('71710533-beba-4937-8319-b5dbef9ccc36', 1, 'ndr64/1.0')):
        _uuid = UUID(_identifier)
        _wire = _uuid.bytes_le if _order == 'little' else _uuid.bytes
        _values[_wire + _version.to_bytes(4, _order)] = _name
    _SYNTAXES[_order] = _values
del _order, _values, _identifier, _version, _name, _uuid, _wire


class DCERPCParser(FrameParser):
    header_size = 16
    protocol_name = 'dcerpc/5.0'
    scope = 'bind_request'

    def frame_size(self, data):
        if data[:3] != b'\x05\x00\x0b':
            raise UnsupportedPrefix('DCE/RPC profile requires version 5.0 Bind')
        if data[3] & 3 != 3 or data[3] & ~0x17:
            raise UnsupportedPrefix('DCE/RPC profile requires unfragmented bind flags')
        if data[4:8] not in (b'\0\0\0\0', b'\x10\0\0\0'):
            raise UnsupportedPrefix('DCE/RPC profile requires ASCII/IEEE data representation')
        self.byteorder = 'little' if data[4] == 16 else 'big'
        if int.from_bytes(data[10:12], self.byteorder):
            raise UnsupportedPrefix('DCE/RPC authentication verifier outside profile')
        size = int.from_bytes(data[8:10], self.byteorder)
        if size < 72:
            raise ParseError('DCE/RPC bind too short for one presentation context')
        return size

    def validate(self, data):
        count = data[24]
        if not count or any(data[25:28]):
            raise ParseError('Invalid DCE/RPC context list count or reserved fields')
        if count > min(self.config.max_headers, 128):
            raise BudgetError('DCE/RPC presentation context count exceeds budget')
        if count > (len(data)-28)//44:
            raise ParseError('Truncated DCE/RPC context list')
        pos, identifiers, offered = 28, set(), set()
        syntaxes = _SYNTAXES[self.byteorder]
        for _ in range(count):
            if len(data)-pos < 24:
                raise ParseError('Truncated DCE/RPC presentation context')
            context_id = int.from_bytes(data[pos:pos+2], self.byteorder)
            if context_id in identifiers:
                raise ParseError('Duplicate DCE/RPC context identifier')
            identifiers.add(context_id)
            transfers = data[pos+2]
            if data[pos+3] or not transfers:
                raise ParseError('Invalid DCE/RPC transfer list or reserved field')
            if transfers > 2:
                raise UnsupportedPrefix('DCE/RPC profile permits two standard transfer syntaxes per context')
            if not any(data[pos+4:pos+20]):
                raise UnsupportedPrefix('Nil DCE/RPC abstract syntax outside profile')
            pos += 24
            if transfers > (len(data)-pos)//20:
                raise ParseError('Truncated DCE/RPC transfer syntaxes')
            seen = set()
            for _ in range(transfers):
                syntax = data[pos:pos+20]
                name = syntaxes.get(syntax)
                if name is None:
                    raise UnsupportedPrefix('DCE/RPC transfer syntax outside NDR 2.0 / NDR64 1.0 profile')
                if syntax in seen:
                    raise ParseError('Duplicate DCE/RPC transfer syntax')
                seen.add(syntax)
                offered.add(name)
                pos += 20
        if pos != len(data):
            raise ParseError('Unexpected bytes after DCE/RPC bind context list')
        self.extra_evidence = tuple(('offered_transfer_syntax', name, 'bind_request', 'offered')
                                    for name in sorted(offered))
        self.reason = 'DCE/RPC bind presentation offers validated; interface identity, server and negotiation unverified'
