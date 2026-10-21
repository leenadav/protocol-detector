"""Additional bounded initial-message recognizers; no port-based inference."""
import ipaddress
import re
from .model import normalize_hostname
from .media import METHODS, accept_class, content_type_class
from .control import ControlHeaders, START
from .parsers import BudgetError, LineParser, ParseError, TOKEN
from .service_text import nats, imap_capability
from .session_text import command_line, imap_command, pop3_greeting

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
_NATS_START = re.compile(rb'(INFO|CONNECT)[ \t]+(.+)', re.I)


class UnsupportedPrefix(ParseError):
    """An ambiguous or unsupported structure, not proof of a malformed protocol."""


class AmbiguousPrefix(UnsupportedPrefix):
    """Valid for several families at once; carries the candidate set for session correlation."""

    def __init__(self, message, candidates):
        super().__init__(message)
        self.candidates = tuple(candidates)


class TextParser(LineParser):
    """Share first-line framing for HTTP, SSH and SMTP instead of rescanning.

    In particular, EHLO can be a syntactically valid HTTP extension method;
    its first word alone must not select SMTP.
    """
    SMTP_COMMANDS = frozenset((b"EHLO", b"HELO", b"MAIL", b"RCPT", b"DATA", b"RSET", b"NOOP", b"QUIT", b"VRFY", b"EXPN",
                               b"HELP", b"AUTH", b"BDAT", b"STARTTLS"))

    def __init__(self, config):
        super().__init__(config, "http")
        self.family = "text"
        self.extra_evidence = ()
        self.control = None
        self.watched = 0

    def feed(self, data):
        if self.continues:
            return LineParser.feed(self, data)
        return super().feed(data)

    def _consume_smtp(self, line):
        """After EHLO: watch a bounded number of client commands for STARTTLS (RFC 3207)."""
        self.watched += 1
        if len(line) + 2 > 512:
            raise ParseError("SMTP command exceeds 512 bytes")
        verb = line.split(b" ", 1)[0].upper()
        if verb not in self.SMTP_COMMANDS:
            raise ParseError("Unexpected SMTP command")
        if verb == b"STARTTLS":
            if line.upper() != b"STARTTLS":
                raise ParseError("STARTTLS takes no parameters")
            self.shift = ("starttls", "tls")
            self.continues = False
            return
        if verb != b"NOOP" or self.watched >= min(self.config.max_headers, 8):
            self.continues = False  # MAIL/AUTH/... begin the plaintext session; stop watching

    def consume_line(self, line):
        if self.first and not line.endswith((b"HTTP/1.0", b"HTTP/1.1")) and START.fullmatch(line):
            self.control = ControlHeaders(line, self.config)
            self.family, self.protocol_name = self.control.family, self.control.protocol_name
            self.scope = "initial_headers"
            self.first = False
            self._line_handler = TextParser._consume_control
            return
        if not self.first:
            return super().consume_line(line)
        command, separator, identity = line.partition(b" ")
        potentially_special = line.startswith(b"SSH-") or command.upper() in (b"EHLO", b"HELO")
        potentially_special = potentially_special or line[:1] in (b'I', b'i', b'C', b'c', b'*')
        if potentially_special and re.fullmatch(TOKEN + rb" [\x21-\x7e]+ HTTP/1\.[01]", line):
            self.family = "http"
            self._line_handler = LineParser.consume_line
            return self._line_handler(self, line)
        if line.startswith(b"SSH-"):
            self.family = self.protocol = "ssh"
            if len(line) + 2 > 255:
                raise ParseError("SSH identification exceeds 255 bytes")
            if self.contexts is not None:
                self.contexts["ssh-req-banner"] = line
            return super().consume_line(line)
        if command.upper() in (b"EHLO", b"HELO"):
            self.family = "smtp"
            if len(line) + 2 > 512:
                raise ParseError("SMTP command exceeds 512 bytes")
            if not separator or not identity:
                raise ParseError("SMTP greeting needs a domain or address literal")
            try:
                text = identity.decode("ascii")
                if text.startswith("[") and text.endswith("]"):
                    address = text[1:-1]
                    if address.lower().startswith("ipv6:"):
                        ipaddress.IPv6Address(address[5:])
                    else:
                        ipaddress.IPv4Address(address)
                else:
                    normalize_hostname(text)
            except (ValueError, UnicodeError):
                raise ParseError("Invalid SMTP greeting identity") from None
            self.protocol_name = "smtp"
            self.done = True
            self.reason = "SMTP client EHLO/HELO syntax validated; server exchange and message body not inspected"
            self.extra_evidence = (("smtp_client_identity", text, "smtp_greeting", "asserted"),)
            if self.contexts is not None:
                self.contexts["smtp-req-argument"] = identity
            # Keep reading commands for STARTTLS; the identification stands either way.
            self.continues = True
            self._line_handler = TextParser._consume_smtp
            return
        if line[:1] in (b'I', b'i', b'C', b'c'):
            match = _NATS_START.fullmatch(line)
            if match:
                nats(match.group(1).upper(), match.group(2), self.config)
                self.family = self.protocol_name = 'nats'
                self.scope = 'protocol_header'
                self.done = True
                self.reason = 'NATS INFO/CONNECT JSON structure validated; authentication and later messages unverified'
                return
        if line.startswith(b'* '):
            if not imap_capability(line, self.config):
                raise AmbiguousPrefix('Untagged text without explicit IMAP revision capabilities is ambiguous', ('imap',))
            self.family = self.protocol_name = 'imap'
            self.scope = 'protocol_header'
            self.done = True
            self.reason = 'IMAP server capability syntax validated; revision capabilities, authentication and later messages unverified'
            return
        if re.match(rb"220(?:[ -]|$)", line):
            raise AmbiguousPrefix("A 220 server greeting alone is ambiguous between SMTP and FTP; a client command is required", ("smtp", "ftp"))
        is_http = re.fullmatch(TOKEN + rb" [\x21-\x7e]+ HTTP/1\.[01]", line) or re.fullmatch(rb"HTTP/1\.[01] [1-5][0-9]{2} .*", line)
        if not is_http:
            if line[:1] in (b'+', b'-') and pop3_greeting(line):
                self.family = self.protocol_name = 'pop3'
                self.scope = 'protocol_header'
                self.done = True
                self.reason = 'POP3 server status line validated; mailbox and authentication unverified'
                return
            if imap_command(line, self.config):
                self.family = self.protocol_name = 'imap'
                self.scope = 'initial_message'
                self.done = True
                self.reason = 'IMAP tagged client command validated; arguments and credentials are not inspected or emitted'
                if line.split(b" ")[1].upper() == b"STARTTLS":
                    self.shift = ("starttls", "tls")
                return
            classified = command_line(line)
            if classified is not None:
                family, candidates, shift = classified
                if family is None:
                    raise AmbiguousPrefix("Command shared by FTP and POP3; the server greeting decides", candidates)
                self.family = self.protocol_name = family
                self.scope = 'initial_message'
                self.done = True
                self.shift = shift
                self.reason = ('FTP client command syntax validated; arguments are not emitted, transfers unverified' if family == 'ftp'
                               else 'POP3 client command syntax validated; credentials are not emitted, mailbox unverified')
                return
        self.family = "http"
        # First-line framing has resolved the family. Later HTTP headers need
        # no shared-text dispatch, regardless of how many protocols are added.
        self._line_handler = LineParser.consume_line
        return self._line_handler(self, line)

    def _consume_control(self, line):
        self.control.consume_line(line)
        self.done, self.reason = self.control.done, self.control.reason


# HTTP/2 frame types inspected after the initial SETTINGS (RFC 9113 section 6).
_H2_DATA, _H2_HEADERS, _H2_PRIORITY, _H2_SETTINGS, _H2_PING, _H2_WINDOW_UPDATE, _H2_CONTINUATION = 0, 1, 2, 4, 6, 8, 9
_H2_END_STREAM, _H2_END_HEADERS, _H2_PADDED, _H2_PRIORITY_FLAG = 0x1, 0x4, 0x8, 0x20
MAX_H2_HEADER_BLOCK = 16384     # decoded header list and encoded block budget (SETTINGS_MAX_HEADER_LIST_SIZE class)
MAX_H2_PREAMBLE_FRAMES = 8      # WINDOW_UPDATE/PRIORITY/PING/SETTINGS frames tolerated before HEADERS
MAX_H2_BLOCK_FRAMES = 8         # HEADERS plus CONTINUATION frames of one header block
_H2_TOKEN = frozenset(b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz")
_H2_METHOD = frozenset(b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_H2_PSEUDO_REQUEST = frozenset((b":method", b":scheme", b":authority", b":path", b":protocol"))
_H2_CONNECTION_SPECIFIC = frozenset((b"connection", b"keep-alive", b"proxy-connection", b"transfer-encoding", b"upgrade"))
_H2_PSEUDO_LETTERS = {b":method": "m", b":authority": "a", b":scheme": "s", b":path": "p", b":protocol": "r", b":status": "t"}


def _valid_port(port):
    return port.isdigit() and len(port) <= 5 and 0 < int(port) <= 65535


def _authority_host(value):
    """DNS host of an :authority value, or None for IP literals; userinfo and bad ports are errors."""
    if b"@" in value or not value:
        raise ParseError("HTTP/2 :authority must be host[:port] without userinfo")
    if value[:1] == b"[":
        end = value.find(b"]")
        if end < 0:
            raise ParseError("Invalid HTTP/2 :authority IP literal")
        try:
            ipaddress.IPv6Address(value[1:end].decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            raise ParseError("Invalid HTTP/2 :authority IP literal") from None
        rest = value[end + 1:]
        if rest:
            if rest[:1] != b":" or not _valid_port(rest[1:]):
                raise ParseError("Invalid HTTP/2 :authority port")
        return None
    host, sep, port = value.rpartition(b":")
    if sep:
        if not _valid_port(port):
            raise ParseError("Invalid HTTP/2 :authority port")
    else:
        host = value
    try:
        return normalize_hostname(host.decode("ascii"))
    except UnicodeDecodeError:
        raise ParseError("HTTP/2 :authority must be ASCII") from None
    except ValueError:
        if all(c in b"0123456789." for c in host):
            return None     # IPv4 literal: structurally fine, never an application identity
        raise ParseError("Invalid HTTP/2 :authority host") from None


class HTTP2Parser:
    """Client preface AND complete initial SETTINGS, then the first request HEADERS block.

    Identification is published once SETTINGS is complete. The parser then keeps
    reading frames (bounded count) until the first HEADERS block ends, decodes it
    with HPACK and emits only bounded, enumerated evidence: method, scheme,
    content-type class, the :authority host, the :protocol of an extended CONNECT.
    Any frame outside the profile ends the continuation quietly; the
    identification stands. DATA payloads are never read.
    """
    protocol_name = "http/2"
    request = True
    preface = H2_PREFACE

    def __init__(self, config):
        self.config = config
        self.prefix_position = 0
        self.header = bytearray()
        self.payload = bytearray()
        self.length = None
        self.done = False
        self.continues = False
        self.consumed = 0
        self.fingerprints = ()
        self.extra_evidence = ()
        self.refined = False       # True once a HEADERS block added evidence; lets the engine skip a rebuild
        self.host = None
        self.contexts = {} if config.retain_contexts else None
        self.frame = bytearray()
        self.body = bytearray()
        self.block = bytearray()
        self.block_stream = None
        self.preamble_frames = 0
        self.block_frames = 0
        self.reason = "Waiting for complete HTTP/2 client preface and initial SETTINGS"

    def feed(self, data):
        if self.done:
            return self._frames(data)
        pos = 0
        if self.prefix_position < len(H2_PREFACE):
            amount = min(len(H2_PREFACE) - self.prefix_position, len(data))
            if data[:amount] != H2_PREFACE[self.prefix_position:self.prefix_position + amount]:
                raise ParseError("Invalid HTTP/2 client preface")
            self.prefix_position += amount
            pos += amount
            if self.prefix_position < len(H2_PREFACE):
                self.consumed += pos
                return pos
        if len(self.header) < 9:
            amount = min(9 - len(self.header), len(data) - pos)
            self.header.extend(data[pos:pos + amount])
            pos += amount
            if len(self.header) < 9:
                self.consumed += pos
                return pos
            self.length = int.from_bytes(self.header[:3], "big")
            stream = int.from_bytes(self.header[5:9], "big") & 0x7fffffff
            if self.header[3] != 4 or self.header[4] & 1 or stream:
                raise ParseError("Initial HTTP/2 frame must be non-ACK SETTINGS on stream zero")
            if self.length > 16384 or self.length % 6:
                raise ParseError("Invalid initial SETTINGS payload length")
            if len(self.preface) + 9 + self.length > self.config.max_bytes:
                raise BudgetError("Initial HTTP/2 SETTINGS exceeds byte budget")
        amount = min(self.length - len(self.payload), len(data) - pos)
        self.payload.extend(data[pos:pos + amount])
        pos += amount
        self.consumed += pos
        if len(self.payload) == self.length:
            settings = self._settings(self.payload)
            if self.config.fingerprints and self.request:
                from .fingerprints import h2_settings_fingerprint
                self.fingerprints = (("h2_settings", h2_settings_fingerprint(settings), "settings_frame"),)
            self.done = True
            self.continues = True
            self.reason = ("HTTP/2 client preface and initial SETTINGS validated; no HEADERS frame decoded yet" if self.request
                           else "HTTP/2 server SETTINGS after the h2c upgrade validated; no HEADERS frame decoded yet")
        return pos

    @staticmethod
    def _settings(payload):
        settings = []
        for offset in range(0, len(payload), 6):
            setting = int.from_bytes(payload[offset:offset + 2], "big")
            value = int.from_bytes(payload[offset + 2:offset + 6], "big")
            settings.append((setting, value))
            if setting == 2 and value not in (0, 1):
                raise ParseError("Invalid SETTINGS_ENABLE_PUSH")
            if setting == 4 and value > 0x7fffffff:
                raise ParseError("Invalid SETTINGS_INITIAL_WINDOW_SIZE")
            if setting == 5 and not 16384 <= value <= 0xffffff:
                raise ParseError("Invalid SETTINGS_MAX_FRAME_SIZE")
            # Unknown setting identifiers and repeated settings are allowed.
        return settings

    # -- frames after the initial SETTINGS --

    def _frames(self, data):
        pos = 0
        while pos < len(data) and self.continues:
            if len(self.frame) < 9:
                amount = min(9 - len(self.frame), len(data) - pos)
                self.frame.extend(data[pos:pos + amount])
                pos += amount
                self.consumed += amount
                if len(self.frame) < 9:
                    break
                self.length = int.from_bytes(self.frame[:3], "big")
                if self.consumed + self.length > self.config.max_bytes:
                    raise BudgetError("HTTP/2 frame exceeds the byte budget")
                if not self._frame_header(self.frame[3], self.frame[4], int.from_bytes(self.frame[5:9], "big") & 0x7fffffff):
                    self.continues = False     # outside the profile: keep the identification, stop reading
                    break
            amount = min(self.length - len(self.body), len(data) - pos)
            self.body.extend(data[pos:pos + amount])
            pos += amount
            self.consumed += amount
            if len(self.body) == self.length:
                self._frame_complete(self.frame[3], self.frame[4], int.from_bytes(self.frame[5:9], "big") & 0x7fffffff, self.body)
                self.frame = bytearray()
                self.body = bytearray()
        return pos

    def _frame_header(self, kind, flags, stream):
        """Validate a frame header; False for a frame type outside the profile."""
        if self.block_stream is not None:
            if kind != _H2_CONTINUATION or stream != self.block_stream or flags & ~_H2_END_HEADERS:
                raise ParseError("HTTP/2 header block interrupted by another frame")
            self.block_frames += 1
            if self.block_frames >= MAX_H2_BLOCK_FRAMES:
                raise BudgetError("HTTP/2 CONTINUATION frame count exceeds budget")
            if len(self.block) + self.length > MAX_H2_HEADER_BLOCK:
                raise BudgetError("HTTP/2 header block exceeds the size budget")
            return True
        if kind == _H2_HEADERS:
            if not stream & 1 or flags & ~(_H2_END_STREAM | _H2_END_HEADERS | _H2_PADDED | _H2_PRIORITY_FLAG):
                raise ParseError("HTTP/2 HEADERS must open a client-initiated stream with known flags")
            if self.length > MAX_H2_HEADER_BLOCK:
                raise BudgetError("HTTP/2 HEADERS frame exceeds the size budget")
            self.block_stream = stream
            return True
        if kind not in (_H2_SETTINGS, _H2_WINDOW_UPDATE, _H2_PRIORITY, _H2_PING):
            return False
        self.preamble_frames += 1
        if self.preamble_frames > MAX_H2_PREAMBLE_FRAMES:
            raise BudgetError("HTTP/2 frame count before HEADERS exceeds budget")
        if kind == _H2_SETTINGS:
            if stream or flags & ~1 or (flags & 1 and self.length) or (not flags & 1 and (self.length % 6 or self.length > 16384)):
                raise ParseError("Invalid HTTP/2 SETTINGS frame")
        elif kind == _H2_WINDOW_UPDATE:
            if self.length != 4 or flags:
                raise ParseError("Invalid HTTP/2 WINDOW_UPDATE frame")
        elif kind == _H2_PRIORITY:
            if self.length != 5 or flags or not stream:
                raise ParseError("Invalid HTTP/2 PRIORITY frame")
        elif self.length != 8 or stream or flags & ~1:
            raise ParseError("Invalid HTTP/2 PING frame")
        return True

    def _frame_complete(self, kind, flags, stream, body):
        if kind == _H2_SETTINGS and not flags & 1:
            self._settings(body)
        elif kind == _H2_WINDOW_UPDATE:
            if not int.from_bytes(body, "big") & 0x7fffffff:
                raise ParseError("HTTP/2 WINDOW_UPDATE increment must be positive")
        elif kind == _H2_PRIORITY:
            if int.from_bytes(body[:4], "big") & 0x7fffffff == stream:
                raise ParseError("HTTP/2 PRIORITY frame depends on its own stream")
        elif kind in (_H2_HEADERS, _H2_CONTINUATION):
            fragment = body
            if kind == _H2_HEADERS:
                if flags & _H2_PADDED:
                    if not fragment:
                        raise ParseError("Padded HTTP/2 HEADERS frame without a pad length")
                    pad = fragment[0]
                    fragment = fragment[1:]
                    if pad > len(fragment) - (5 if flags & _H2_PRIORITY_FLAG else 0):
                        raise ParseError("HTTP/2 HEADERS padding exceeds the frame")
                    fragment = fragment[:len(fragment) - pad]
                if flags & _H2_PRIORITY_FLAG:
                    if len(fragment) < 5 or int.from_bytes(fragment[:4], "big") & 0x7fffffff == stream:
                        raise ParseError("Invalid HTTP/2 HEADERS priority fields")
                    fragment = fragment[5:]
            self.block.extend(fragment)
            if flags & _H2_END_HEADERS:
                self._headers(bytes(self.block))
                self.continues = False

    # -- the decoded header block --

    def _headers(self, block):
        from .hpack import Decoder
        decoder = Decoder(max_fields=min(self.config.max_headers, 128), max_string=min(self.config.max_line, 8192),
                          max_list_size=MAX_H2_HEADER_BLOCK)
        fields = decoder.decode(block)
        pseudo, regular, order = {}, [], []
        for name, value in fields:
            bare = name[1:] if name[:1] == b":" else name
            if not bare or any(b not in _H2_TOKEN for b in bare):
                raise ParseError("HTTP/2 field name must be a lowercase token")
            if any(b in (0, 10, 13) for b in value) or value[:1] in (b" ", b"\t") or value[-1:] in (b" ", b"\t"):
                raise ParseError("HTTP/2 field value contains forbidden bytes or edge whitespace")
            if name[:1] == b":":
                if regular:
                    raise ParseError("HTTP/2 pseudo-header after a regular field")
                if name in pseudo:
                    raise ParseError("Duplicate HTTP/2 pseudo-header")
                if name not in (_H2_PSEUDO_REQUEST if self.request else (b":status",)):
                    raise ParseError("HTTP/2 pseudo-header outside this message direction")
                pseudo[name] = value
                order.append(_H2_PSEUDO_LETTERS[name])
                continue
            if name in _H2_CONNECTION_SPECIFIC or (name == b"te" and value.lower() != b"trailers"):
                raise ParseError("HTTP/2 connection-specific field")
            regular.append((name, value))
        evidence = self._request(pseudo, regular) if self.request else self._response(pseudo, regular)
        content_type = next((value for name, value in regular if name == b"content-type"), None)
        if content_type is not None:
            evidence.append(("http2_content_type", content_type_class(content_type), "headers_frame", "asserted"))
        accept = next((value for name, value in regular if name == b"accept"), None)
        if accept is not None and accept_class(accept) == "dns":
            evidence.append(("http2_accept", "dns", "headers_frame", "asserted"))
        if self.config.fingerprints and self.request:
            self.fingerprints += (("h2_pseudo_order", ",".join(order), "headers_frame"),)
        if self.contexts is not None:
            self._contexts(pseudo, regular)
        self.extra_evidence += tuple(evidence)
        self.scope = "request_headers" if self.request else "response_headers"
        self.refined = True

    def _request(self, pseudo, regular):
        if b":method" not in pseudo:
            raise ParseError("HTTP/2 request without :method")
        method = pseudo[b":method"]
        if not method or len(method) > 32 or any(b not in _H2_METHOD for b in method):
            raise ParseError("Invalid HTTP/2 :method")
        evidence = [("http2_message", "request", "headers_frame", "structural"),
                    ("http2_method", method.decode("ascii") if method in METHODS else "extension", "headers_frame", "structural")]
        if method == b"CONNECT" and b":protocol" not in pseudo:
            if b":scheme" in pseudo or b":path" in pseudo or b":authority" not in pseudo:
                raise ParseError("HTTP/2 CONNECT requires :authority alone")
        else:
            if b":scheme" not in pseudo or not pseudo.get(b":path"):
                raise ParseError("HTTP/2 request requires :scheme and a non-empty :path")
            scheme = pseudo[b":scheme"].lower()
            evidence.append(("http2_scheme", scheme.decode("ascii") if scheme in (b"http", b"https") else "other", "headers_frame", "structural"))
            if b":protocol" in pseudo:
                if method != b"CONNECT" or b":authority" not in pseudo:
                    raise ParseError("HTTP/2 :protocol requires an extended CONNECT with :authority")
                protocol = pseudo[b":protocol"].lower()
                evidence.append(("http2_protocol", "websocket" if protocol == b"websocket" else "other", "headers_frame", "asserted"))
        if b":authority" in pseudo:
            self.host = _authority_host(pseudo[b":authority"])
        self.reason = ("HTTP/2 client preface, SETTINGS and first request HEADERS validated (HPACK decoded); "
                       "only method, scheme, authority host, extended-CONNECT protocol and content-type class are emitted")
        return evidence

    def _response(self, pseudo, regular):
        status = pseudo.get(b":status")
        if status is None or len(status) != 3 or not status.isdigit() or not 100 <= int(status) <= 599:
            raise ParseError("HTTP/2 response requires a three-digit :status")
        self.reason = ("HTTP/2 server SETTINGS and first response HEADERS validated (HPACK decoded); "
                       "only the status code and content-type class are emitted")
        return [("http2_message", "response", "headers_frame", "structural"),
                ("http2_status", status.decode("ascii"), "headers_frame", "structural")]

    def _contexts(self, pseudo, regular):
        if self.request:
            self.contexts["http2-req-method"] = pseudo[b":method"]
            if b":path" in pseudo:
                self.contexts["http2-req-uri-path"] = pseudo[b":path"].split(b"?", 1)[0]
            if b":authority" in pseudo:
                self.contexts["http2-req-host-header"] = pseudo[b":authority"]
            agent = next((value for name, value in regular if name == b"user-agent"), None)
            if agent is not None:
                self.contexts["http2-req-user-agent-header"] = agent[:1024]
            self.contexts["http2-req-headers"] = b"".join(name + b": " + value + b"\r\n" for name, value in regular)
        else:
            self.contexts["http2-rsp-status"] = int(pseudo[b":status"])


class HTTP2ServerParser(HTTP2Parser):
    """Server side of an h2c upgrade: the first frame is SETTINGS without any preface (RFC 7540 3.2).

    Reached only through the h2c-upgrade shift of a 101 response or an explicit
    candidate; the SETTINGS fingerprint is a client characteristic and is not
    derived for a server. The first response HEADERS block is decoded like the
    client's request (status code and content-type class only).
    """
    request = False
    preface = b""

    def __init__(self, config):
        super().__init__(config)
        self.prefix_position = len(H2_PREFACE)
        self.reason = "Waiting for the server's initial HTTP/2 SETTINGS after the h2c upgrade"


class Socks5Parser:
    """SOCKS5 initial exchange of one direction.

    Client: greeting offering no-auth followed by the complete request (CONNECT,
    BIND or UDP ASSOCIATE with an IPv4, IPv6 or domain destination). Server
    (v0.41): method selection (no-auth or username/password) followed by the
    complete reply. Neither direction claims that authentication or the tunnel
    succeeded; subnegotiation bytes are outside the profile.
    """
    protocol_name = "socks5"
    MAX_BYTES = 2 + 255 + 4 + 1 + 255 + 2      # longest client exchange
    _REPLIES = ("succeeded", "general-failure", "not-allowed", "network-unreachable", "host-unreachable",
                "connection-refused", "ttl-expired", "command-not-supported", "address-type-not-supported")

    def __init__(self, config):
        self.config = config
        self.buffer = bytearray()
        self.scope = "initial_message"
        self.extra_evidence = ()
        self.contexts = None
        self.done = False
        self.reason = "Waiting for SOCKS5 greeting and request"

    def feed(self, data):
        if self.done:
            return 0
        before = len(self.buffer)
        self.buffer.extend(data[:self.MAX_BYTES - before])
        end = self._parse(self.buffer)
        if end is None:
            if len(self.buffer) >= self.MAX_BYTES:
                raise ParseError("SOCKS5 exchange exceeds its maximum size")
            return len(self.buffer) - before
        self.done = True
        self.buffer = bytearray()
        return end - before

    def _parse(self, buf):
        """Return the exchange length once complete, None while bytes are missing."""
        if len(buf) < 2:
            return None
        if buf[0] != 5:
            raise ParseError("Invalid SOCKS5 version")
        second = buf[1]
        if second == 0 or (second == 2 and len(buf) >= 5 and buf[2] == 5 and buf[4] == 0):
            return self._server(buf)
        if second == 2 and len(buf) < 5:
            return None          # a client offering two methods or a server selecting username/password
        return self._client(buf)

    def _address(self, buf, pos, what):
        """Return (atyp, address text or None, position after the port) or None when incomplete."""
        if pos + 1 > len(buf):
            return None
        atyp = buf[pos - 1]
        if atyp == 3:
            length = buf[pos]
            if length == 0:
                raise ParseError("Empty SOCKS5 " + what)
            pos += 1
        else:
            length = 4 if atyp == 1 else 16
        if pos + length + 2 > len(buf):
            return None
        field = bytes(buf[pos:pos + length])
        try:
            address = normalize_hostname(field.decode("ascii")) if atyp == 3 else str(ipaddress.ip_address(field))
        except (ValueError, UnicodeError):
            raise ParseError("Invalid or unsupported SOCKS5 " + what) from None
        return atyp, address, pos + length + 2

    def _client(self, buf):
        count = buf[1]
        if len(buf) < 2 + count:
            return None
        methods = buf[2:2 + count]
        if 255 in methods:
            raise ParseError("No-acceptable-methods is a server response, not a client method")
        if 0 not in methods:
            raise UnsupportedPrefix("SOCKS5 authentication subnegotiation is not supported")
        request = 2 + count
        if len(buf) < request + 4:
            return None
        if buf[request] != 5 or buf[request + 1] not in (1, 2, 3) or buf[request + 2] != 0 or buf[request + 3] not in (1, 3, 4):
            raise ParseError("Invalid SOCKS5 request header")
        parsed = self._address(buf, request + 4, "destination")
        if parsed is None:
            return None
        _, address, end = parsed
        port = int.from_bytes(buf[end - 2:end], "big")
        self.reason = "SOCKS5 client greeting and request validated; method selection, server reply and tunneled protocol unverified"
        self.extra_evidence = (
            ("socks_command", {1: "CONNECT", 2: "BIND", 3: "UDP_ASSOCIATE"}[buf[request + 1]], "socks_request", "asserted"),
            ("socks_target", address, "socks_request", "asserted"),
            ("socks_port", str(port), "socks_request", "asserted"),
        )
        if self.config.retain_contexts:
            self.contexts = {"socks-req-target": address.encode("ascii"), "socks-req-port": port}
        return end

    def _server(self, buf):
        if len(buf) < 6:
            return None
        if buf[2] != 5 or buf[3] > 8 or buf[4] != 0 or buf[5] not in (1, 3, 4):
            raise ParseError("Invalid SOCKS5 server reply header")
        parsed = self._address(buf, 6, "bound address")
        if parsed is None:
            return None
        _, _, end = parsed
        self.scope = "negotiation_response"
        self.reason = "SOCKS5 server method selection and reply validated; bound address not emitted, tunneled protocol unverified"
        self.extra_evidence = (("socks_method", "no-authentication" if buf[1] == 0 else "username-password", "socks_reply", "structural"),
                               ("socks_reply", self._REPLIES[buf[3]], "socks_reply", "asserted"))
        return end
