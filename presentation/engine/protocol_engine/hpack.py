"""HPACK (RFC 7541) header block decoding, bounded for passive inspection.

One Decoder per connection direction. decode() turns a complete header block
into (name, value) byte pairs; it never emits anything itself. Budgets: the
number of fields, the encoded length of one string, the decoded header list
size (RFC 7540 SETTINGS_MAX_HEADER_LIST_SIZE semantics) and the dynamic table
size, which never grows past the maximum the decoder was created with. Every
structural error is a ParseError; every exceeded bound is a BudgetError.
"""
from collections import deque
from .parsers import BudgetError, ParseError

DEFAULT_TABLE_SIZE = 4096      # SETTINGS_HEADER_TABLE_SIZE initial value (RFC 7540 6.5.2)
ENTRY_OVERHEAD = 32            # RFC 7541 4.1
MAX_INTEGER_BYTES = 4          # continuation bytes; integers stay below 2**28
EOS = 256
STATIC_COUNT = 61

STATIC_TABLE = (
    (b':authority', b''),
    (b':method', b'GET'),
    (b':method', b'POST'),
    (b':path', b'/'),
    (b':path', b'/index.html'),
    (b':scheme', b'http'),
    (b':scheme', b'https'),
    (b':status', b'200'),
    (b':status', b'204'),
    (b':status', b'206'),
    (b':status', b'304'),
    (b':status', b'400'),
    (b':status', b'404'),
    (b':status', b'500'),
    (b'accept-charset', b''),
    (b'accept-encoding', b'gzip, deflate'),
    (b'accept-language', b''),
    (b'accept-ranges', b''),
    (b'accept', b''),
    (b'access-control-allow-origin', b''),
    (b'age', b''),
    (b'allow', b''),
    (b'authorization', b''),
    (b'cache-control', b''),
    (b'content-disposition', b''),
    (b'content-encoding', b''),
    (b'content-language', b''),
    (b'content-length', b''),
    (b'content-location', b''),
    (b'content-range', b''),
    (b'content-type', b''),
    (b'cookie', b''),
    (b'date', b''),
    (b'etag', b''),
    (b'expect', b''),
    (b'expires', b''),
    (b'from', b''),
    (b'host', b''),
    (b'if-match', b''),
    (b'if-modified-since', b''),
    (b'if-none-match', b''),
    (b'if-range', b''),
    (b'if-unmodified-since', b''),
    (b'last-modified', b''),
    (b'link', b''),
    (b'location', b''),
    (b'max-forwards', b''),
    (b'proxy-authenticate', b''),
    (b'proxy-authorization', b''),
    (b'range', b''),
    (b'referer', b''),
    (b'refresh', b''),
    (b'retry-after', b''),
    (b'server', b''),
    (b'set-cookie', b''),
    (b'strict-transport-security', b''),
    (b'transfer-encoding', b''),
    (b'user-agent', b''),
    (b'vary', b''),
    (b'via', b''),
    (b'www-authenticate', b''),
)

# (code, bit length) per symbol 0..255, then EOS (RFC 7541 Appendix B).
HUFFMAN_CODES = (
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28),
    (0xfffffe4, 28), (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28),
    (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
    (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28),
    (0xfffffed, 28), (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28),
    (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28),
    (0xffffff8, 28), (0xffffff9, 28), (0xffffffa, 28), (0xffffffb, 28),
    (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
    (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11),
    (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11),
    (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
    (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6),
    (0x1a, 6), (0x1b, 6), (0x1c, 6), (0x1d, 6),
    (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
    (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10),
    (0x1ffa, 13), (0x21, 6), (0x5d, 7), (0x5e, 7),
    (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
    (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7),
    (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7),
    (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
    (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7),
    (0xfc, 8), (0x73, 7), (0xfd, 8), (0x1ffb, 13),
    (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
    (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5),
    (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6),
    (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
    (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5),
    (0x2b, 6), (0x76, 7), (0x2c, 6), (0x8, 5),
    (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15),
    (0x7fc, 11), (0x3ffd, 14), (0x1ffd, 13), (0xffffffc, 28),
    (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20),
    (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23),
    (0x3fffd6, 22), (0x7fffda, 23), (0x7fffdb, 23), (0x7fffdc, 23),
    (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
    (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23),
    (0xffffee, 24), (0x7fffe1, 23), (0x7fffe2, 23), (0x7fffe3, 23),
    (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),
    (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24),
    (0x3fffda, 22), (0x1fffdd, 21), (0xfffe9, 20), (0x3fffdb, 22),
    (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
    (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24),
    (0x1fffdf, 21), (0x3fffdf, 22), (0x7fffeb, 23), (0x7fffec, 23),
    (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
    (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23),
    (0xfffea, 20), (0x3fffe2, 22), (0x3fffe3, 22), (0x3fffe4, 22),
    (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
    (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19),
    (0x3fffe7, 22), (0x7ffff2, 23), (0x3fffe8, 22), (0x1ffffec, 25),
    (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27),
    (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25),
    (0x7fff2, 19), (0x1fffe3, 21), (0x3ffffe6, 26), (0x7ffffe0, 27),
    (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
    (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26),
    (0xffffffd, 28), (0x7ffffe3, 27), (0x7ffffe4, 27), (0x7ffffe5, 27),
    (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21),
    (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23),
    (0x3fffea, 22), (0x3fffeb, 22), (0x1ffffee, 25), (0x1ffffef, 25),
    (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
    (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26),
    (0x7ffffe7, 27), (0x7ffffe8, 27), (0x7ffffe9, 27), (0x7ffffea, 27),
    (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27),
    (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26),
    (0x3fffffff, 30),
)

def _build_huffman():
    """Nibble-driven decoder table from the canonical code.

    The 257-symbol code is complete (Kraft sum 1), so every bit path ends in a
    leaf within 30 bits and the tree has exactly 256 internal nodes. Each table
    entry is (next state, emitted bytes, hit EOS) for one state and one nibble;
    `ones` maps the states on the all-ones path to their depth, which is what a
    valid padding must leave behind (RFC 7541 5.2: fewer than 8 bits).
    """
    children = [[None, None]]
    for symbol, (code, length) in enumerate(HUFFMAN_CODES):
        node = 0
        for shift in range(length - 1, -1, -1):
            bit = (code >> shift) & 1
            if shift == 0:
                children[node][bit] = (True, symbol)
            else:
                branch = children[node][bit]
                if branch is None:
                    children.append([None, None])
                    branch = (False, len(children) - 1)
                    children[node][bit] = branch
                node = branch[1]
    if len(children) != 256 or any(child is None for pair in children for child in pair):
        raise ValueError("HPACK Huffman code is not complete")
    table = []
    for state in range(256):
        for nibble in range(16):
            node, out, eos = state, bytearray(), False
            for shift in (3, 2, 1, 0):
                leaf, value = children[node][(nibble >> shift) & 1]
                if leaf:
                    if value == EOS:
                        eos = True
                    else:
                        out.append(value)
                    node = 0
                else:
                    node = value
            table.append((node, bytes(out), eos))
    ones, node, depth = {}, 0, 0
    while True:
        leaf, value = children[node][1]
        if leaf:
            break
        depth += 1
        ones[value] = depth
        node = value
    return tuple(table), ones


_HUFFMAN_TABLE, _HUFFMAN_ONES = _build_huffman()


def decode_integer(data, pos, prefix_bits):
    """RFC 7541 5.1 integer starting at data[pos]; returns (value, next position)."""
    mask = (1 << prefix_bits) - 1
    value = data[pos] & mask
    pos += 1
    if value < mask:
        return value, pos
    shift = 0
    while True:
        if pos >= len(data):
            raise ParseError("Truncated HPACK integer")
        if shift >= 7 * MAX_INTEGER_BYTES:
            raise ParseError("HPACK integer exceeds the decoder limit")
        byte = data[pos]
        pos += 1
        value += (byte & 0x7f) << shift
        shift += 7
        if not byte & 0x80:
            return value, pos


def huffman_decode(data):
    """RFC 7541 5.2: canonical Huffman string; strict padding (fewer than 8 one bits), no EOS.

    Two table steps per input byte; the cost is linear in the encoded length.
    """
    table = _HUFFMAN_TABLE
    state = 0
    out = bytearray()
    for byte in data:
        state, emitted, eos = table[(state << 4) | (byte >> 4)]
        if eos:
            raise ParseError("HPACK Huffman string contains EOS")
        if emitted:
            out += emitted
        state, emitted, eos = table[(state << 4) | (byte & 15)]
        if eos:
            raise ParseError("HPACK Huffman string contains EOS")
        if emitted:
            out += emitted
    if state and _HUFFMAN_ONES.get(state, 8) >= 8:
        raise ParseError("Invalid HPACK Huffman padding")
    return bytes(out)


class Decoder:
    """Dynamic table plus budgets for one direction of one connection."""

    def __init__(self, max_table_size=DEFAULT_TABLE_SIZE, max_fields=128, max_string=8192, max_list_size=16384):
        self.max_table_size = max_table_size
        self.table_size = max_table_size
        self.table = deque()        # newest entry first: index 62 is table[0]
        self.used = 0
        self.max_fields = max_fields
        self.max_string = max_string
        self.max_list_size = max_list_size

    def _lookup(self, index):
        if not index:
            raise ParseError("HPACK index zero")
        if index <= STATIC_COUNT:
            return STATIC_TABLE[index - 1]
        index -= STATIC_COUNT + 1
        if index >= len(self.table):
            raise ParseError("HPACK index beyond the dynamic table")
        return self.table[index]

    def _string(self, data, pos):
        if pos >= len(data):
            raise ParseError("Truncated HPACK string")
        huffman = data[pos] & 0x80
        length, pos = decode_integer(data, pos, 7)
        if length > self.max_string:
            raise BudgetError("HPACK string exceeds the length budget")
        end = pos + length
        if end > len(data):
            raise ParseError("Truncated HPACK string")
        value = bytes(data[pos:end])
        return (huffman_decode(value) if huffman else value), end

    def _add(self, name, value):
        size = len(name) + len(value) + ENTRY_OVERHEAD
        if size > self.table_size:
            self.table.clear()
            self.used = 0
            return
        while self.used + size > self.table_size:
            old_name, old_value = self.table.pop()
            self.used -= len(old_name) + len(old_value) + ENTRY_OVERHEAD
        self.table.appendleft((name, value))
        self.used += size

    def _resize(self, size):
        if size > self.max_table_size:
            raise ParseError("HPACK dynamic table size update above the acknowledged maximum")
        self.table_size = size
        while self.used > size:
            old_name, old_value = self.table.pop()
            self.used -= len(old_name) + len(old_value) + ENTRY_OVERHEAD

    def decode(self, block):
        """Decode one complete header block into a list of (name, value) bytes pairs."""
        fields = []
        pos, total, updates = 0, 0, 0
        while pos < len(block):
            byte = block[pos]
            add = False
            if byte & 0x80:
                index, pos = decode_integer(block, pos, 7)
                name, value = self._lookup(index)
            elif byte & 0x40:
                index, pos = decode_integer(block, pos, 6)
                name, value, pos = self._literal(block, pos, index)
                add = True
            elif byte & 0x20:
                if fields or updates >= 2:
                    raise ParseError("HPACK dynamic table size update must begin the header block")
                size, pos = decode_integer(block, pos, 5)
                self._resize(size)
                updates += 1
                continue
            else:
                index, pos = decode_integer(block, pos, 4)
                name, value, pos = self._literal(block, pos, index)
            total += len(name) + len(value) + ENTRY_OVERHEAD
            if total > self.max_list_size:
                raise BudgetError("HPACK header list exceeds the size budget")
            if len(fields) >= self.max_fields:
                raise BudgetError("HPACK header field count exceeds budget")
            fields.append((name, value))
            if add:
                self._add(name, value)
        return fields

    def _literal(self, block, pos, index):
        if index:
            name = self._lookup(index)[0]
        else:
            name, pos = self._string(block, pos)
            if not name:
                raise ParseError("Empty HPACK header name")
        value, pos = self._string(block, pos)
        return name, value, pos
