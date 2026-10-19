"""Bounded incremental parsers. Each feed receives only newly available bytes."""
import re
from .model import normalize_hostname

TOKEN = rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+"


class ParseError(ValueError):
    pass


class BudgetError(ParseError):
    pass


class LineParser:
    def __init__(self, config, protocol):
        self.config = config
        # Unbound callback avoids a self -> bound-method -> self reference cycle.
        self._line_handler = type(self).consume_line
        self.protocol = protocol
        self.line = bytearray()
        self.first = True
        self.headers = 0
        self.host = None
        self.host_count = 0
        self.http11_request = False
        self.content_length = None
        self.transfer_encoding = False
        self.done = False
        self.protocol_name = None
        self.reason = "Waiting for complete line"

    def feed(self, data):
        pos = 0
        while pos < len(data) and not self.done:
            newline = data.find(b"\n", pos)
            end = len(data) if newline < 0 else newline + 1
            piece = data[pos:end]
            # Check limits before growing memory, including unterminated lines.
            limit = min(self.config.max_line, 255) if self.protocol == "ssh" else self.config.max_line
            if len(self.line) + len(piece) > limit:
                if self.protocol == "ssh" and limit == 255:
                    raise ParseError("SSH identification exceeds 255 bytes")
                raise BudgetError("Line length budget exceeded")
            self.line.extend(piece)
            pos = end
            if newline < 0:
                break
            if not self.line.endswith(b"\r\n"):
                raise ParseError("Expected CRLF line ending")
            line = bytes(self.line[:-2])
            self.line.clear()
            self._line_handler(self, line)
        return pos

    def consume_line(self, line):
        if self.protocol == "ssh":
            if not re.fullmatch(rb"SSH-(?:2\.0|1\.99)-[\x21-\x2c\x2e-\x7e]+(?: [\x20-\x7e]*)?", line):
                raise ParseError("Invalid or unsupported SSH identification")
            self.protocol_name = "ssh"
            self.done = True
            self.reason = "SSH identification validated; key exchange not inspected"
            return
        if self.first:
            self.first = False
            request = re.fullmatch(TOKEN + rb" [\x21-\x7e]+ HTTP/1\.[01]", line)
            response = re.fullmatch(rb"HTTP/1\.[01] [1-5][0-9]{2} [\x09\x20-\x7e\x80-\xff]*", line)
            if not (request or response):
                raise ParseError("Unsupported HTTP/1.x start-line")
            self.http11_request = bool(request and line.endswith(b"HTTP/1.1"))
            version = line.rsplit(b" ", 1)[-1] if request else line.split(b" ", 1)[0]
            self.protocol_name = "http/1.1" if version == b"HTTP/1.1" else "http/1.0"
            self.reason = "Start-line validated; waiting for headers"
            return
        if not line:
            if self.http11_request and self.host_count != 1:
                raise ParseError("HTTP/1.1 request requires one Host")
            if self.transfer_encoding and self.content_length is not None:
                raise ParseError("Ambiguous Transfer-Encoding and Content-Length")
            self.done = True
            self.reason = "HTTP start-line and headers validated; body and later requests not inspected"
            return
        self.headers += 1
        if self.headers > self.config.max_headers:
            raise BudgetError("Header count budget exceeded")
        name, colon, value = line.partition(b":")
        if not colon or not re.fullmatch(TOKEN, name):
            raise ParseError("Invalid header name")
        if any(c < 32 and c != 9 or c == 127 for c in value):
            raise ParseError("Control byte in header")
        name, value = name.lower(), value.strip(b" \t")
        if name == b"host":
            self.host_count += 1
            if self.host_count > 1 or not value:
                raise ParseError("Duplicate or empty Host")
            try:
                text = value.decode("ascii")
                # Literal IPv6 is valid HTTP authority but not a DNS rule key.
                if text.startswith("["):
                    import ipaddress
                    closing = text.index("]")
                    ipaddress.IPv6Address(text[1:closing])
                    suffix = text[closing + 1:]
                    if suffix and (not suffix.startswith(":") or len(suffix) > 6 or not suffix[1:].isdigit()
                                   or not 0 < int(suffix[1:]) <= 65535):
                        raise ValueError
                else:
                    host, separator, port = text.partition(":")
                    if separator and (len(port) > 5 or not port.isdigit() or not 0 < int(port) <= 65535):
                        raise ValueError
                    import ipaddress
                    try:
                        ipaddress.IPv4Address(host)
                    except ValueError:
                        self.host = normalize_hostname(host)
            except (ValueError, UnicodeError):
                raise ParseError("Invalid Host authority") from None
        elif name == b"content-length":
            # Conservative policy: duplicate CL is not accepted, even if identical.
            if self.content_length is not None or not re.fullmatch(rb"[0-9]{1,20}", value):
                raise ParseError("Invalid or duplicate Content-Length")
            self.content_length = int(value)
        elif name == b"transfer-encoding":
            if self.transfer_encoding or value.lower() != b"chunked":
                raise ParseError("Unsupported or duplicate Transfer-Encoding")
            self.transfer_encoding = True


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, size):
        if size < 0 or self.pos + size > len(self.data):
            raise ParseError("TLS field exceeds enclosing length")
        value = self.data[self.pos:self.pos + size]
        self.pos += size
        return value

    def vector(self, width):
        return self.take(int.from_bytes(self.take(width), "big"))

    def end(self):
        if self.pos != len(self.data):
            raise ParseError("Trailing bytes in TLS structure")


def parse_hello(body):
    reader = Reader(body)
    if reader.take(2) not in (b"\x03\x01", b"\x03\x02", b"\x03\x03"):
        raise ParseError("Unsupported ClientHello version")
    reader.take(32)
    if len(reader.vector(1)) > 32:
        raise ParseError("Session ID exceeds maximum")
    ciphers = reader.vector(2)
    compression = reader.vector(1)
    if len(ciphers) < 2 or len(ciphers) % 2 or not compression or 0 not in compression:
        raise ParseError("Invalid cipher or compression vector")
    hostname, alpn = None, ()
    if reader.pos == len(body):
        return hostname, alpn
    extensions = Reader(reader.vector(2))
    reader.end()
    seen = set()
    while extensions.pos < len(extensions.data):
        kind = int.from_bytes(extensions.take(2), "big")
        value = extensions.vector(2)
        if kind in seen:
            raise ParseError("Duplicate TLS extension")
        seen.add(kind)
        if kind == 0:  # server_name
            envelope = Reader(value)
            names = Reader(envelope.vector(2))
            envelope.end()
            if not names.data:
                raise ParseError("Empty SNI list")
            name_types = set()
            while names.pos < len(names.data):
                name_type = names.take(1)[0]
                name = names.vector(2)
                if name_type in name_types or not name:
                    raise ParseError("Duplicate or empty SNI name")
                name_types.add(name_type)
                if name_type != 0:
                    raise ParseError("Unsupported SNI name type")
                try:
                    hostname = normalize_hostname(name.decode("ascii"))
                except (ValueError, UnicodeError):
                    raise ParseError("Invalid SNI DNS hostname") from None
        elif kind == 16:  # ALPN is an offer, not the negotiated application protocol.
            envelope = Reader(value)
            offers = Reader(envelope.vector(2))
            envelope.end()
            if not offers.data:
                raise ParseError("Empty ALPN list")
            protocols = []
            while offers.pos < len(offers.data):
                protocol = offers.vector(1)
                if not protocol or len(protocols) >= 64:
                    raise ParseError("Invalid ALPN offer or offer-count limit")
                protocols.append(protocol.decode("ascii") if all(32 <= c < 127 for c in protocol)
                                 else "hex:" + protocol.hex())
            alpn = tuple(protocols)
    return hostname, alpn


class TLSParser:
    def __init__(self, config):
        self.config = config
        self.record_header = bytearray()
        self.record_remaining = 0
        self.record_versions = 0
        self.handshake = bytearray()
        self.hello_size = None
        self.done = False
        self.host = None
        self.alpn = ()
        self.reason = "Waiting for complete TLS hello"

    def feed(self, data):
        pos = 0
        while pos < len(data) and not self.done:
            if self.record_remaining == 0:
                amount = min(5 - len(self.record_header), len(data) - pos)
                self.record_header.extend(data[pos:pos + amount])
                pos += amount
                if len(self.record_header) < 5:
                    break
                header = self.record_header
                if header[0] != 22 or header[1] != 3 or header[2] not in (1, 2, 3):
                    raise ParseError("Expected plaintext TLS handshake record")
                self.record_versions |= 1 << header[2]
                self.record_remaining = int.from_bytes(header[3:5], "big")
                self.record_header.clear()
                if not 1 <= self.record_remaining <= 16384:
                    raise ParseError("Invalid TLS record length")
            needed = 4 - len(self.handshake) if self.hello_size is None else 4 + self.hello_size - len(self.handshake)
            amount = min(needed, self.record_remaining, len(data) - pos)
            self.handshake.extend(data[pos:pos + amount])
            pos += amount
            self.record_remaining -= amount
            if self.hello_size is None and len(self.handshake) == 4:
                if self.handshake[0] not in (1, 2):
                    raise ParseError("Initial handshake is not ClientHello or ServerHello")
                self.hello_size = int.from_bytes(self.handshake[1:4], "big")
                if self.hello_size < (41 if self.handshake[0] == 1 else 38):
                    raise ParseError("TLS hello length invalid")
                if self.hello_size > self.config.max_bytes - 9:
                    raise BudgetError("TLS hello exceeds configured byte budget")
            if self.hello_size is not None and len(self.handshake) == self.hello_size + 4:
                if self.handshake[0] == 1:
                    self.host, self.alpn = parse_hello(bytes(self.handshake[4:]))
                    self.reason = "ClientHello structure validated; SNI/ALPN are client assertions, not decrypted content"
                else:
                    from .tls_server import parse_server_hello
                    self.extra_evidence, self.scope, self.reason = parse_server_hello(
                        bytes(self.handshake[4:]), self.config, self.record_versions, self.record_remaining)
                self.handshake.clear()
                self.done = True
        return pos
