"""Bounded BSON wire validation without constructing user documents or running code.

All element encodings are framed; binary subtypes remain opaque except legacy
binary length and fixed UUID/MD5 widths. No regex, JavaScript or binary execution.
"""
import struct
from .parsers import BudgetError, ParseError

_FIXED = {1: 8, 6: 0, 7: 12, 9: 8, 10: 0, 16: 4, 17: 8, 18: 8, 19: 16, 127: 0, 255: 0}


def i32(data, pos, limit):
    if pos + 4 > limit:
        raise ParseError('Truncated BSON integer')
    return struct.unpack_from('<i', data, pos)[0]


def utf8(data):
    try:
        return data.decode('utf-8')
    except UnicodeError:
        raise ParseError('Invalid BSON UTF-8') from None


class BSONValidator:
    def __init__(self, data, config):
        self.data = data
        self.field_limit = min(config.max_headers, 128)
        self.name_limit = min(config.max_line, 1024)
        self.fields = 0
        self.documents = 0

    def cstring(self, pos, limit):
        end = self.data.find(b'\0', pos, limit)
        if end < 0:
            raise ParseError('Unterminated BSON cstring')
        if end - pos > self.name_limit:
            raise BudgetError('BSON cstring exceeds name budget')
        return utf8(self.data[pos:end]), end + 1

    def string_end(self, pos, limit):
        size = i32(self.data, pos, limit)
        end = pos + 4 + size
        if size < 1 or end > limit or self.data[end - 1] != 0:
            raise ParseError('Invalid BSON string length or terminator')
        utf8(self.data[pos + 4:end - 1])
        return end

    def document(self, start, limit, depth=1, array=False, collect=False):
        if depth > 16:
            raise BudgetError('BSON nesting exceeds 16 levels')
        self.documents += 1
        if self.documents > 128:
            raise BudgetError('BSON document count exceeds 128')
        size = i32(self.data, start, limit)
        end = start + size
        if size < 5 or end > limit or self.data[end - 1] != 0:
            raise ParseError('Invalid BSON document length or terminator')
        pos, index, names = start + 4, 0, set()
        metadata = {} if collect else None
        while pos < end - 1:
            kind = self.data[pos]
            name, pos = self.cstring(pos + 1, end - 1)
            self.fields += 1
            if self.fields > self.field_limit:
                raise BudgetError('BSON element count exceeds field budget')
            if array:
                if name != str(index):
                    raise ParseError('BSON array keys must be consecutive decimal indices')
            elif name in names:
                raise ParseError('Duplicate BSON field name outside supported profile')
            names.add(name)
            index += 1
            value_start = pos
            if kind in _FIXED:
                pos += _FIXED[kind]
            elif kind == 8:
                if pos >= end - 1 or self.data[pos] not in (0, 1):
                    raise ParseError('Invalid BSON boolean')
                pos += 1
            elif kind in (2, 12, 13, 14):
                pos = self.string_end(pos, end - 1)
                if kind == 12:
                    pos += 12
            elif kind in (3, 4):
                pos, _ = self.document(pos, end - 1, depth + 1, kind == 4)
            elif kind == 5:
                size = i32(self.data, pos, end - 1)
                if size < 0 or pos + 5 + size > end - 1:
                    raise ParseError('Invalid BSON binary length')
                subtype = self.data[pos + 4]
                if 10 <= subtype < 128:
                    raise ParseError('Undefined BSON binary subtype')
                if subtype == 2 and (size < 4 or i32(self.data, pos + 5, end - 1) != size - 4):
                    raise ParseError('Legacy BSON binary lengths disagree')
                if subtype in (3, 4, 5) and size != 16:
                    raise ParseError('Invalid BSON UUID/MD5 width')
                pos += 5 + size
            elif kind == 11:
                _, pos = self.cstring(pos, end - 1)
                options, pos = self.cstring(pos, end - 1)
                if any(char not in 'imsux' for char in options) or options != ''.join(sorted(set(options))):
                    raise ParseError('Invalid BSON regular-expression options')
            elif kind == 15:
                size = i32(self.data, pos, end - 1)
                scope_end = pos + size
                if size < 14 or scope_end > end - 1:
                    raise ParseError('Invalid BSON code-with-scope length')
                code_end = self.string_end(pos + 4, scope_end)
                pos, _ = self.document(code_end, scope_end, depth + 1)
                if pos != scope_end:
                    raise ParseError('BSON scope length mismatch')
            else:
                raise ParseError('Unknown BSON element type')
            if pos > end - 1:
                raise ParseError('BSON value exceeds enclosing document')
            if metadata is not None:
                metadata[name] = (kind, value_start, pos)
        if pos != end - 1:
            raise ParseError('BSON document framing mismatch')
        return end, metadata
