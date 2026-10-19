"""FastCGI v1 BEGIN_REQUEST followed by a complete bounded PARAMS stream.

Single request, stream start only. Reserved bytes must be zero in this profile;
padding is arbitrary. Management records and multiplexing are outside scope.
Parameter bytes can span record boundaries; names/values are never published.
"""
import struct
from .parsers import BudgetError, ParseError
from .extended import UnsupportedPrefix


class FastCGIParser:
    protocol_name = 'fastcgi/1'
    scope = 'initial_params'

    def __init__(self, config):
        self.config = config
        self.header = bytearray()
        self.begin = bytearray()
        self.params = bytearray()
        self.request_id = None
        self.active = False
        self.remaining = 0
        self.padding = 0
        self.content_size = 0
        self.wire_size = 0
        self.records = 0
        self.done = False
        self.reason = 'Waiting for FastCGI BEGIN_REQUEST and complete PARAMS stream'

    def _header(self):
        version, kind, request_id, size, padding, reserved = struct.unpack('!BBHHBB', self.header)
        self.header.clear()
        if version != 1 or reserved:
            raise UnsupportedPrefix('FastCGI profile requires version 1 and zero reserved header')
        if not request_id:
            raise UnsupportedPrefix('FastCGI management records are outside this profile')
        if self.request_id is None:
            if kind != 1:
                raise UnsupportedPrefix('FastCGI stream must begin with BEGIN_REQUEST')
            if size != 8:
                raise ParseError('FastCGI BEGIN_REQUEST body must contain eight bytes')
        elif kind != 4 or request_id != self.request_id:
            raise UnsupportedPrefix('FastCGI profile requires one uninterrupted PARAMS stream')
        self.records += 1
        # BEGIN and the terminating empty PARAMS count as records too.
        if self.records > min(self.config.max_headers, 128):
            raise BudgetError('FastCGI record count exceeds budget')
        self.wire_size += 8 + size + padding
        if self.wire_size > self.config.max_bytes:
            raise BudgetError('Advertised FastCGI record exceeds remaining byte budget')
        self.current_id = request_id
        self.content_size = self.remaining = size
        self.padding = padding
        self.active = True

    def _complete(self):
        if self.request_id is None:
            role = int.from_bytes(self.begin[:2], 'big')
            if role not in (1, 2, 3) or self.begin[2] & ~1 or any(self.begin[3:]):
                raise UnsupportedPrefix('FastCGI role, flags or reserved body outside supported profile')
            self.request_id = self.current_id
            self.begin.clear()
            self.extra_evidence = (('fastcgi_role', ('responder', 'authorizer', 'filter')[role - 1],
                                    'begin_request', 'offered'),)
        elif self.content_size == 0:
            self._validate_params()
            self.params.clear()
            self.done = True
            self.reason = 'FastCGI BEGIN_REQUEST and PARAMS framing validated; values, response and request completion unverified'
        self.active = False

    def _validate_params(self):
        pos, count, size = 0, 0, len(self.params)
        while pos < size:
            count += 1
            if count > min(self.config.max_headers, 128):
                raise BudgetError('FastCGI parameter count exceeds budget')
            lengths = []
            for _ in range(2):
                if pos == size:
                    raise ParseError('Truncated FastCGI parameter length')
                length = self.params[pos]
                pos += 1
                if length & 128:
                    if size - pos < 3:
                        raise ParseError('Truncated FastCGI four-byte parameter length')
                    length = ((length & 127) << 24) | int.from_bytes(self.params[pos:pos + 3], 'big')
                    pos += 3
                lengths.append(length)
            name_size, value_size = lengths
            if name_size + value_size > self.config.max_bytes:
                raise BudgetError('FastCGI parameter lengths exceed byte budget')
            if name_size + value_size > size - pos:
                raise ParseError('FastCGI parameter exceeds completed PARAMS stream')
            # Binary strings are framed, not interpreted as HTTP headers or CGI
            # variables. Empty names and duplicate names have no identity meaning.
            pos += name_size + value_size

    def feed(self, data):
        pos = 0
        while pos < len(data) and not self.done:
            if not self.active:
                amount = min(8 - len(self.header), len(data) - pos)
                self.header.extend(data[pos:pos + amount])
                pos += amount
                if len(self.header) < 8:
                    break
                self._header()
            if self.remaining:
                amount = min(self.remaining, len(data) - pos)
                target = self.begin if self.request_id is None else self.params
                target.extend(data[pos:pos + amount])
                self.remaining -= amount
                pos += amount
            if not self.remaining and self.padding:
                amount = min(self.padding, len(data) - pos)
                self.padding -= amount
                pos += amount
            if not self.remaining and not self.padding:
                self._complete()
        return pos
