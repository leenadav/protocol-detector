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
        # Bounded signature contexts, only when configured; never emitted as evidence.
        self.contexts = {} if config.retain_contexts else None
        self.continues = False
        self.kexinit = None
        self.fingerprints = ()
        self.extra_evidence = ()
        self.shift = None          # (boundary, expected family) once the message announces a protocol change
        self.method = None
        self.target = None
        self.status = None
        self.upgrade = None
        self.connection_upgrade = False
        self.websocket_key = False
        self.websocket_version = False
        self.websocket_accept = False
        self.h2_settings = False

    def feed(self, data):
        if self.continues and self.kexinit is not None:
            consumed = self.kexinit.feed(data)
            if self.kexinit.done:
                from .fingerprints import hassh
                kex, enc, mac, comp = self.kexinit.lists[0], self.kexinit.lists[2], self.kexinit.lists[4], self.kexinit.lists[6]
                self.fingerprints = (("hassh", hassh(kex, enc, mac, comp), "kexinit"),)
                self.kexinit = None
                self.continues = False
            return consumed
        # A continuation (STARTTLS watch) consumes lines only on later calls: the call that
        # completes the identification returns at the boundary so the Inspector publishes
        # first and routes later lines through the error-tolerant continuation path.
        continuing = self.done and self.continues
        pos = 0
        while pos < len(data) and (not self.done or (continuing and self.continues)):
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
            self.extra_evidence = (("ssh_version", line.split(b"-", 2)[1].decode("ascii"), "banner", "structural"),)
            if self.config.fingerprints:
                # Keep reading one KEXINIT packet for the HASSH fingerprint; identification stands either way.
                self.kexinit = KexInit(self.config)
                self.continues = True
            return
        if self.first:
            self.first = False
            request = re.fullmatch(TOKEN + rb" [\x21-\x7e]+ HTTP/1\.[01]", line)
            response = re.fullmatch(rb"HTTP/1\.[01] [1-5][0-9]{2} [\x09\x20-\x7e\x80-\xff]*", line)
            if not (request or response):
                raise ParseError("Unsupported HTTP/1.x start-line")
            self.http11_request = bool(request and line.endswith(b"HTTP/1.1"))
            version = line.rsplit(b" ", 1)[-1] if request else line.split(b" ", 1)[0]
            if request:
                self.method, self.target = line.split(b" ", 2)[:2]
                self.method = self.method.upper()
            else:
                self.status = int(line.split(b" ", 2)[1])
                self.extra_evidence += (("http_status", str(self.status), "status_line", "structural"),)
            self.protocol_name = "http/1.1" if version == b"HTTP/1.1" else "http/1.0"
            self.reason = "Start-line validated; waiting for headers"
            if self.contexts is not None:
                parts = line.split(b" ", 2)
                self.contexts["http-req-version"] = version
                if request:
                    self.contexts["http-req-method"] = parts[0]
                    target = parts[1]
                    self.contexts["http-req-uri-path"] = target.split(b"?", 1)[0]
                else:
                    self.contexts["http-rsp-status"] = int(parts[1])
                    self.contexts["http-rsp-reason"] = parts[2] if len(parts) > 2 else b""
                self.contexts["http-req-headers"] = bytearray()
            return
        if not line:
            if self.http11_request and self.host_count != 1:
                raise ParseError("HTTP/1.1 request requires one Host")
            if self.transfer_encoding and self.content_length is not None:
                raise ParseError("Ambiguous Transfer-Encoding and Content-Length")
            self.done = True
            self.reason = "HTTP start-line and headers validated; body and later requests not inspected"
            self._shift_boundary()
            if self.contexts is not None:
                self.contexts["http-req-headers"] = bytes(self.contexts["http-req-headers"])
                if self.host is not None:
                    self.contexts["http-req-host-header"] = self.host.encode("ascii")
                if self.content_length is not None:
                    self.contexts["http-req-content-length"] = self.content_length
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
        if self.contexts is not None:
            block = self.contexts["http-req-headers"]
            if len(block) < 4096:  # bounded header block for raw-context signatures
                block.extend((name + b": " + value + b"\r\n")[:4096 - len(block)])
            if name == b"user-agent" and "http-req-user-agent-header" not in self.contexts:
                self.contexts["http-req-user-agent-header"] = value[:1024]
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
        elif name == b"upgrade":
            if self.upgrade is not None or not re.fullmatch(rb"[\x21-\x7e]{1,64}(?:, *[\x21-\x7e]{1,64}){0,7}", value):
                raise ParseError("Invalid or duplicate Upgrade header")
            self.upgrade = value.split(b",", 1)[0].strip().lower()
        elif name == b"connection":
            if b"upgrade" in [token.strip().lower() for token in value.split(b",")]:
                self.connection_upgrade = True
        elif name == b"sec-websocket-key":
            if self.websocket_key or not re.fullmatch(rb"[A-Za-z0-9+/]{22}==", value):
                raise ParseError("Invalid or duplicate Sec-WebSocket-Key")
            self.websocket_key = True
        elif name == b"sec-websocket-version":
            if self.websocket_version or value != b"13":
                raise ParseError("Unsupported or duplicate Sec-WebSocket-Version")
            self.websocket_version = True
        elif name == b"sec-websocket-accept":
            if self.websocket_accept or not re.fullmatch(rb"[A-Za-z0-9+/]{27}=", value):
                raise ParseError("Invalid or duplicate Sec-WebSocket-Accept")
            self.websocket_accept = True
        elif name == b"http2-settings":
            if self.h2_settings or not re.fullmatch(rb"[A-Za-z0-9_\-]{0,1024}", value):
                raise ParseError("Invalid or duplicate HTTP2-Settings")
            self.h2_settings = True

    def _shift_boundary(self):
        """Decide whether the bytes after this header block belong to another protocol.

        CONNECT: the tunnel payload follows (any protocol; TLS in practice). Upgrade
        to websocket/h2c on a request, or a 101 response naming websocket or h2c:
        the frames follow (server HTTP/2 frames carry no preface). A 200 to CONNECT cannot be told from a body-less response
        on the server side alone, so no server-side CONNECT shift exists; the
        session verdict combines the client shift with the server response.
        """
        if self.method == b"CONNECT":
            if not re.fullmatch(rb"(?:[A-Za-z0-9.\-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\]):[0-9]{1,5}", self.target or b""):
                return  # not authority-form: still HTTP syntax, but no proxy would open a tunnel for it
            self.scope = "tunnel_request"
            self.extra_evidence += (("http_method", "CONNECT", "request_line", "structural"),)
            self.shift = ("http-connect", None)
            return
        if self.upgrade is None:
            return
        token = self.upgrade if self.upgrade in (b"websocket", b"h2c") else b"other"
        self.extra_evidence += (("http_upgrade", token.decode("ascii"), "headers", "structural"),)
        if self.method is not None:
            if not self.connection_upgrade:
                raise ParseError("Upgrade requires a Connection: Upgrade header")
            if self.content_length or self.transfer_encoding:
                return  # a request body precedes any switch; later bytes are not framed by the new protocol yet
            if token == b"websocket":
                if self.method != b"GET" or not (self.websocket_key and self.websocket_version):
                    raise ParseError("WebSocket upgrade requires GET with Sec-WebSocket-Key and -Version 13")
                self.shift = ("websocket-upgrade", "websocket")
            elif token == b"h2c" and self.h2_settings:
                self.shift = ("h2c-upgrade", "http2")
        elif self.status == 101:
            if token == b"websocket":
                if not self.websocket_accept:
                    raise ParseError("101 websocket upgrade requires Sec-WebSocket-Accept")
                self.shift = ("websocket-upgrade", "websocket")
            elif token == b"h2c":
                if not self.connection_upgrade:
                    raise ParseError("101 h2c upgrade requires a Connection: Upgrade header")
                self.shift = ("h2c-upgrade", "http2-server")  # server frames follow without a preface


class KexInit:
    """One SSH_MSG_KEXINIT binary packet after the identification line (RFC 4253 7.1).

    Bounded by the 35000-byte packet limit and max_bytes. Name-lists are
    validated as comma-separated printable ASCII; only their HASSH digest and the
    lists needed for it are kept, never cookie bytes.
    """
    MAX_PACKET = 35000

    def __init__(self, config):
        self.config = config
        self.buffer = bytearray()
        self.needed = 4
        self.length = None
        self.done = False
        self.lists = None

    def feed(self, data):
        pos = 0
        while pos < len(data) and not self.done:
            amount = min(self.needed - len(self.buffer), len(data) - pos)
            self.buffer.extend(data[pos:pos + amount])
            pos += amount
            if len(self.buffer) < self.needed:
                break
            if self.length is None:
                self.length = int.from_bytes(self.buffer[:4], "big")
                if not 17 <= self.length <= min(self.MAX_PACKET, self.config.max_bytes - 4):
                    raise ParseError("SSH packet length outside KEXINIT profile")
                self.needed = 4 + self.length
                continue
            self._validate(bytes(self.buffer[4:]))
            self.done = True
            self.buffer.clear()
        return pos

    def _validate(self, packet):
        padding = packet[0]
        if packet[1] != 20:
            raise ParseError("First SSH packet is not KEXINIT")
        if padding < 4 or 1 + padding + 1 + 16 > len(packet):
            raise ParseError("Invalid SSH KEXINIT padding or cookie framing")
        pos, lists = 18, []
        payload_end = len(packet) - padding
        for _ in range(10):
            if pos + 4 > payload_end:
                raise ParseError("Truncated SSH KEXINIT name-list")
            size = int.from_bytes(packet[pos:pos + 4], "big")
            pos += 4
            if pos + size > payload_end or size > 4096:
                raise ParseError("SSH KEXINIT name-list exceeds packet or profile")
            value = packet[pos:pos + size]
            if any(byte < 0x21 or byte > 0x7e for byte in value):
                raise ParseError("SSH KEXINIT name-list must be printable ASCII")
            lists.append(value)
            pos += size
        if pos + 5 > payload_end or packet[pos] > 1 or packet[pos + 1:pos + 5] != bytes(4):
            raise ParseError("Invalid SSH KEXINIT trailer")
        if pos + 5 != payload_end:
            raise ParseError("Unexpected bytes after SSH KEXINIT")
        self.lists = tuple(lists)


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


class ClientHelloInfo:
    """Structural ClientHello fields kept for signatures and fingerprints; no key material."""
    __slots__ = ("version", "ciphers", "extensions", "hostname", "alpn", "groups", "signature_algorithms",
                 "point_formats", "supported_versions", "body")

    def __init__(self):
        self.version = 0
        self.ciphers = ()
        self.extensions = ()
        self.hostname = None
        self.alpn = ()
        self.groups = ()
        self.signature_algorithms = ()
        self.point_formats = ()
        self.supported_versions = ()
        self.body = None


_TLS_VERSION_NAMES = {0x0300: "SSL 3.0", 0x0301: "1.0", 0x0302: "1.1", 0x0303: "1.2", 0x0304: "1.3"}


def offered_max_version(legacy, supported):
    """Highest TLS version a ClientHello offers.

    With a supported_versions extension the legacy field is ignored (RFC 8446
    4.2.1); GREASE and unknown values are skipped. Otherwise the legacy field.
    """
    best = 0
    for value in supported:
        if value > best and value in _TLS_VERSION_NAMES:
            best = value
    return _TLS_VERSION_NAMES.get(best or legacy, "unknown")


def _u16_list(data, width=2):
    if len(data) % width:
        raise ParseError("TLS list length is not a multiple of its element width")
    return tuple(int.from_bytes(data[i:i + width], "big") for i in range(0, len(data), width))


def parse_hello(body, info=None, offered=None):
    """Validate a ClientHello body; return (hostname, alpn) and fill info when supplied.

    `offered`, when a list, receives [legacy_version, supported_versions tuple]
    without the cost of the full ClientHelloInfo collection. The fixed fields and
    the extension walk are index arithmetic over the body (this is the hottest
    parser in the engine); every bound raises the same ParseError the Reader
    helper raises, so truncated or inconsistent lengths fail identically.
    """
    size = len(body)
    if size < 2:
        raise ParseError("TLS field exceeds enclosing length")
    version = body[0:2]
    if offered is not None:
        offered.append(int.from_bytes(version, "big"))
        offered.append(())
    if version not in (b"\x03\x01", b"\x03\x02", b"\x03\x03"):
        raise ParseError("Unsupported ClientHello version")
    pos = 34  # version + random
    if pos + 1 > size:
        raise ParseError("TLS field exceeds enclosing length")
    session_length = body[pos]
    pos += 1
    if pos + session_length > size:
        raise ParseError("TLS field exceeds enclosing length")
    if session_length > 32:
        raise ParseError("Session ID exceeds maximum")
    pos += session_length
    if pos + 2 > size:
        raise ParseError("TLS field exceeds enclosing length")
    cipher_length = (body[pos] << 8) | body[pos + 1]
    pos += 2
    if pos + cipher_length > size:
        raise ParseError("TLS field exceeds enclosing length")
    ciphers = body[pos:pos + cipher_length]
    pos += cipher_length
    if pos + 1 > size:
        raise ParseError("TLS field exceeds enclosing length")
    compression_length = body[pos]
    pos += 1
    if pos + compression_length > size:
        raise ParseError("TLS field exceeds enclosing length")
    compression = body[pos:pos + compression_length]
    pos += compression_length
    if cipher_length < 2 or cipher_length % 2 or not compression or 0 not in compression:
        raise ParseError("Invalid cipher or compression vector")
    if info is not None:
        info.version = int.from_bytes(version, "big")
        info.ciphers = _u16_list(ciphers)
    hostname, alpn = None, ()
    if pos == size:
        return hostname, alpn
    if pos + 2 > size:
        raise ParseError("TLS field exceeds enclosing length")
    extensions_length = (body[pos] << 8) | body[pos + 1]
    pos += 2
    if pos + extensions_length > size:
        raise ParseError("TLS field exceeds enclosing length")
    if pos + extensions_length != size:
        raise ParseError("Trailing bytes in TLS structure")
    data, end = body, size
    seen = set()
    order = []
    while pos < end:
        if pos + 2 > end:
            raise ParseError("TLS field exceeds enclosing length")
        kind = (data[pos] << 8) | data[pos + 1]
        pos += 2
        if pos + 2 > end:
            raise ParseError("TLS field exceeds enclosing length")
        length = (data[pos] << 8) | data[pos + 1]
        pos += 2
        if pos + length > end:
            raise ParseError("TLS field exceeds enclosing length")
        value = data[pos:pos + length]
        pos += length
        if kind in seen:
            raise ParseError("Duplicate TLS extension")
        seen.add(kind)
        if info is not None:
            order.append(kind)
            if len(order) > 128:
                raise BudgetError("ClientHello extension count exceeds inspection limit")
        if kind == 43 and offered is not None:
            # supported_versions: one length byte then 16-bit values.
            if not value or value[0] != len(value) - 1 or value[0] % 2:
                raise ParseError("Invalid supported_versions extension")
            offered[1] = tuple(int.from_bytes(value[i:i + 2], "big") for i in range(1, len(value), 2))
        if info is not None and kind in (10, 11, 13, 43):
            lists = Reader(value)
            if kind == 10:
                info.groups = _u16_list(lists.vector(2))
            elif kind == 11:
                info.point_formats = tuple(lists.vector(1))
            elif kind == 13:
                info.signature_algorithms = _u16_list(lists.vector(2))
            else:
                info.supported_versions = _u16_list(lists.vector(1))
            lists.end()
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
    if info is not None:
        info.extensions = tuple(order)
        info.hostname, info.alpn = hostname, alpn
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
        self.contexts = None
        self.hello = None
        self.fingerprints = ()
        self.extra_evidence = ()
        self.continues = False
        self.watch = None          # CertificateWatch after a TLS 1.2 ServerHello when configured
        self.consumed = 0          # bytes accepted so far; the watch inherits the remaining byte budget
        self.reason = "Waiting for complete TLS hello"

    def feed(self, data):
        if self.watch is not None:
            # Post-identification continuation: the leaf certificate adds asserted evidence
            # or the watch ends quietly; the ServerHello identification stands either way.
            consumed = self.watch.feed(data)
            if self.watch.done:
                self.extra_evidence += self.watch.evidence
                self.watch = None
                self.continues = False
            return consumed
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
                    body = bytes(self.handshake[4:])
                    info = ClientHelloInfo() if (self.config.retain_contexts or self.config.fingerprints) else None
                    offered = []
                    self.host, self.alpn = parse_hello(body, info, offered)
                    self.extra_evidence = (("tls_offered_max_version", offered_max_version(offered[0], offered[1]), "client_hello", "offered"),)
                    if info is not None and self.config.fingerprints:
                        from .fingerprints import ja3, ja4
                        self.fingerprints = (("ja4", ja4(info), "client_hello"), ("ja3", ja3(info), "client_hello"))
                    if info is not None and self.config.retain_contexts:
                        info.body = body
                        self.contexts = {"ssl-req-client-hello": body, "ssl-req-version": info.version,
                                         "ssl-req-cipher-suite": frozenset(info.ciphers),
                                         "ssl-req-client-hello-ext-type": frozenset(info.extensions)}
                        if self.host:
                            self.contexts["ssl-req-chello-sni"] = self.host.encode("ascii")
                        if self.alpn:
                            self.contexts["ssl-req-alpn"] = ",".join(self.alpn).encode("latin-1", "replace")
                        self.hello = info
                    self.reason = "ClientHello structure validated; SNI/ALPN are client assertions, not decrypted content"
                else:
                    from .tls_server import parse_server_hello, CertificateWatch
                    self.extra_evidence, self.scope, self.reason = parse_server_hello(
                        bytes(self.handshake[4:]), self.config, self.record_versions, self.record_remaining)
                    if self.config.certificates and self.scope == "server_hello" and \
                            ("selected_tls_version", "1.2", "server_hello", "asserted") in self.extra_evidence:
                        # TLS 1.3 encrypts its Certificate message; only a 1.2 flight can be read.
                        self.watch = CertificateWatch(self.config, self.record_remaining, self.config.max_bytes - self.consumed - pos)
                        self.continues = True
                self.handshake.clear()
                self.done = True
        self.consumed += pos
        return pos
