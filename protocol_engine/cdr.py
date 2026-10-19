"""Bounded CDR primitives with offsets relative to the complete GIOP message.

Padding bytes have unspecified values. No recursive type-code decoding or
encapsulation interpretation is performed here.
"""
from .parsers import BudgetError, ParseError


class CDRCursor:
    def __init__(self, data, byteorder, pos=12):
        self.data = data
        self.byteorder = byteorder
        self.pos = pos

    def take(self, size):
        if size < 0 or size > len(self.data) - self.pos:
            raise ParseError('CDR field exceeds enclosing message')
        start = self.pos
        self.pos += size
        return self.data[start:self.pos]

    def align(self, width):
        self.take((-self.pos) % width)

    def uint(self, width):
        self.align(width)
        return int.from_bytes(self.take(width), self.byteorder)

    def sequence(self, limit):
        size = self.uint(4)
        if size > limit:
            raise BudgetError('CDR sequence exceeds field budget')
        return self.take(size)

    def string(self, limit):
        value = self.sequence(limit)
        if not value or value[-1] != 0 or b'\0' in value[:-1]:
            raise ParseError('CDR string requires exactly one terminal NUL')
        return value[:-1]
