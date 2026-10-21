"""Incremental STOMP 1.1/1.2 handshake framing; no messages or authentication."""
from .parsers import BudgetError, ParseError


def _unescape(value):
    if b'\\' not in value:
        return value
    output = bytearray()
    index = 0
    replacements = {114: 13, 110: 10, 99: 58, 92: 92}
    while index < len(value):
        byte = value[index]
        if byte == 92:
            index += 1
            if index == len(value) or value[index] not in replacements:
                raise ParseError("Undefined STOMP escape")
            byte = replacements[value[index]]
        output.append(byte)
        index += 1
    return bytes(output)


class STOMPParser:
    protocol_name = 'stomp'
    scope = 'protocol_header'

    def __init__(self, config):
        self.config = config
        self.line = bytearray()
        self.command = None
        self.headers = {}
        self.header_count = 0
        self.await_null = False
        self.done = False
        self.reason = 'Waiting for complete STOMP handshake frame'

    def feed(self, data):
        pos = 0
        while pos < len(data) and not self.done:
            if self.await_null:
                if data[pos] != 0:
                    raise ParseError("STOMP handshake must have an empty body and NUL terminator")
                self.done = True
                self.headers.clear()
                self.reason = 'STOMP handshake frame validated; version offers, authentication and later messages unverified'
                return pos + 1
            newline = data.find(b'\n', pos)
            end = len(data) if newline < 0 else newline + 1
            if len(self.line) + end - pos > self.config.max_line:
                raise BudgetError("STOMP line length exceeds budget")
            self.line.extend(data[pos:end])
            pos = end
            if newline < 0:
                break
            line = bytes(self.line[:-1])
            self.line.clear()
            if line.endswith(b'\r'):
                line = line[:-1]
            if b'\r' in line or b'\x00' in line:
                raise ParseError("Invalid STOMP line framing")
            self.consume_line(line)
        return pos

    def consume_line(self, line):
        if self.command is None:
            if line not in (b'CONNECT', b'STOMP', b'CONNECTED'):
                raise ParseError("Unsupported STOMP initial command")
            self.command = line
            return
        if not line:
            if self.command == b'CONNECTED':
                if self.headers.get(b'version') not in (b'1.1', b'1.2'):
                    raise ParseError("Unsupported STOMP server version")
            else:
                versions = self.headers.get(b'accept-version', b'').split(b',')
                if (not self.headers.get(b'host') or not any(v in (b'1.1', b'1.2') for v in versions)
                        or any(v not in (b'1.0', b'1.1', b'1.2') for v in versions)):
                    raise ParseError("STOMP handshake needs host and supported accept-version list")
            length = self.headers.get(b'content-length', b'0')
            if not length or any(byte != 48 for byte in length):
                raise ParseError("STOMP handshake content-length must be zero")
            heartbeat = self.headers.get(b'heart-beat')
            if heartbeat is not None:
                parts = heartbeat.split(b',')
                if len(parts) != 2 or any(not part.isdigit() or len(part) > 20 for part in parts):
                    raise ParseError("Invalid STOMP heart-beat pair")
            self.await_null = True
            return
        self.header_count += 1
        if self.header_count > self.config.max_headers:
            raise BudgetError("STOMP header count exceeds budget")
        name, separator, value = line.partition(b':')
        if not separator or not name:
            raise ParseError("Invalid STOMP header")
        if self.command == b'STOMP':
            if b':' in value:
                raise ParseError("Unescaped colon in STOMP header")
            name, value = _unescape(name), _unescape(value)
        try:
            name.decode('utf-8')
            value.decode('utf-8')
        except UnicodeError:
            raise ParseError("Invalid STOMP UTF-8 header") from None
        # First occurrence wins, including duplicate content-length. Count every
        # line for resource bounds, but never retain credential/extension values.
        if name in (b'host', b'version', b'accept-version', b'content-length', b'heart-beat'):
            self.headers.setdefault(name, value)
