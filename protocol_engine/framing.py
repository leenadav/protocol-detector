"""Bounded framing reusable by initial binary-message recognizers."""
from .parsers import BudgetError, ParseError


class FrameParser:
    header_size = 0
    scope = "initial_message"

    def __init__(self, config):
        self.config = config
        self.buffer = bytearray()
        self.needed = self.header_size
        self.header_done = False
        self.done = False
        self.reason = "Waiting for complete framed message"

    def feed(self, data):
        pos = 0
        while not self.done:
            amount = min(self.needed - len(self.buffer), len(data) - pos)
            self.buffer.extend(data[pos:pos + amount])
            pos += amount
            if len(self.buffer) < self.needed:
                break
            if not self.header_done:
                self.needed = self.frame_size(self.buffer)
                if self.needed < self.header_size:
                    raise ParseError("Frame length shorter than its header")
                if self.needed > self.config.max_bytes:
                    raise BudgetError("Advertised frame exceeds byte budget")
                self.header_done = True
                if len(self.buffer) < self.needed:
                    if pos == len(data):
                        break
                    continue
            self.validate(bytes(self.buffer))
            self.done = True
            self.buffer.clear()
        return pos


def ber_length(data, pos, limit):
    if pos >= limit:
        raise ParseError("Truncated BER length")
    first = data[pos]
    pos += 1
    if first < 128:
        return first, pos
    width = first & 127
    if not 1 <= width <= 4 or pos + width > limit:
        raise ParseError("Unsupported indefinite or truncated BER length")
    return int.from_bytes(data[pos:pos + width], "big"), pos + width


def ber_field(data, pos, limit, expected):
    if pos >= limit or data[pos] != expected:
        raise ParseError("Unexpected BER field tag")
    size, start = ber_length(data, pos + 1, limit)
    if start + size > limit:
        raise ParseError("BER field exceeds enclosing length")
    return data[start:start + size], start + size
