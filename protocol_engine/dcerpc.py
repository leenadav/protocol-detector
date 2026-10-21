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
        if data[:2] != b'\x05\x00' or data[2] not in (0x0b, 0x0c, 0x0d):
            raise UnsupportedPrefix('DCE/RPC profile requires version 5.0 Bind, Bind_ack or Bind_nak')
        self.ptype = data[2]
        if data[3] & 3 != 3 or data[3] & ~0x17:
            raise UnsupportedPrefix('DCE/RPC profile requires unfragmented bind flags')
        if data[4:8] not in (b'\0\0\0\0', b'\x10\0\0\0'):
            raise UnsupportedPrefix('DCE/RPC profile requires ASCII/IEEE data representation')
        self.byteorder = 'little' if data[4] == 16 else 'big'
        if int.from_bytes(data[10:12], self.byteorder):
            raise UnsupportedPrefix('DCE/RPC authentication verifier outside profile')
        size = int.from_bytes(data[8:10], self.byteorder)
        if size < {0x0b: 72, 0x0c: 52, 0x0d: 21}[self.ptype]:
            raise ParseError('DCE/RPC PDU too short for its type')
        return size

    def validate(self, data):
        if self.ptype == 0x0c:
            return self._bind_ack(data)
        if self.ptype == 0x0d:
            return self._bind_nak(data)
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
        self.extra_evidence = (('dcerpc_pdu', 'bind', 'header', 'structural'),) + tuple(
            ('offered_transfer_syntax', name, 'bind_request', 'offered') for name in sorted(offered))
        self.reason = 'DCE/RPC bind presentation offers validated; interface identity, server and negotiation unverified'

    def _bind_ack(self, data):
        """Bind_ack: max sizes, association group, secondary address, result list with one entry per context."""
        order = self.byteorder
        if not int.from_bytes(data[16:18], order) or not int.from_bytes(data[18:20], order):
            raise ParseError('DCE/RPC bind_ack transfer sizes must be nonzero')
        address_length = int.from_bytes(data[24:26], order)
        pos = 26 + address_length
        if address_length > 256 or pos > len(data) or (address_length and (data[pos - 1] != 0 or not all(0x20 <= b < 0x7f for b in data[26:pos - 1]))):
            raise ParseError('DCE/RPC secondary address outside the profile')
        pos = (pos + 3) & ~3
        if pos + 4 > len(data):
            raise ParseError('Truncated DCE/RPC result list header')
        count = data[pos]
        if not count or any(data[pos + 1:pos + 4]):
            raise ParseError('Invalid DCE/RPC result list count or reserved fields')
        if count > min(self.config.max_headers, 128):
            raise BudgetError('DCE/RPC result count exceeds budget')
        pos += 4
        if len(data) - pos != 24 * count:
            raise ParseError('DCE/RPC result list length disagrees with its count')
        syntaxes = _SYNTAXES[order]
        accepted = set()
        for _ in range(count):
            result = int.from_bytes(data[pos:pos + 2], order)
            syntax = data[pos + 4:pos + 24]
            if result > 3:
                raise ParseError('DCE/RPC context result outside the specification')
            if result in (0, 3):
                name = syntaxes.get(syntax)
                if name is None:
                    raise UnsupportedPrefix('DCE/RPC accepted transfer syntax outside NDR 2.0 / NDR64 1.0 profile')
                accepted.add(name)
            elif any(syntax):
                raise ParseError('DCE/RPC rejected context must carry a nil transfer syntax')
            pos += 24
        self.scope = 'bind_response'
        self.extra_evidence = (('dcerpc_pdu', 'bind-ack', 'header', 'structural'),) + tuple(
            ('accepted_transfer_syntax', name, 'bind_ack', 'asserted') for name in sorted(accepted))
        self.reason = 'DCE/RPC bind_ack result list validated; secondary address not emitted, interface identity unverified'

    def _bind_nak(self, data):
        """Bind_nak: reject reason and supported protocol versions; a trailing signature (MS extension) is tolerated."""
        order = self.byteorder
        reason = int.from_bytes(data[16:18], order)
        if reason > 9 and reason != 0xffff:
            raise ParseError('DCE/RPC bind_nak reason outside the specification')
        count = data[18]
        if not count or count > 32:
            raise ParseError('DCE/RPC bind_nak version count outside the profile')
        end = 19 + 2 * count
        if end > len(data) or len(data) - end not in (0, 1, 2, 3, 16, 17, 18, 19):
            raise ParseError('DCE/RPC bind_nak version list disagrees with the PDU length')
        if any(data[at] != 5 for at in range(19, end, 2)):
            raise UnsupportedPrefix('DCE/RPC bind_nak lists versions other than 5')
        self.scope = 'bind_response'
        self.extra_evidence = (('dcerpc_pdu', 'bind-nak', 'header', 'structural'),)
        self.reason = 'DCE/RPC bind_nak validated; reject reason not emitted'
